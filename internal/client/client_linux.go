//go:build linux && amd64

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/protocol"
	"github.com/Lfardell1/Soteria/internal/transfer"
)

type launcher func(peer, stderr *os.File) (*exec.Cmd, error)

// Test seams are limited to process creation and signal delivery. Production
// always creates its socketpair as the caller, before sudo changes identity.
type engineClient struct {
	launch       launcher
	signals      func() (<-chan os.Signal, func())
	setupTimeout time.Duration
	drainTimeout time.Duration
	stopTimeout  time.Duration
}

func defaultClient() engineClient {
	return engineClient{
		launch: launchStarter, signals: sessionSignals,
		setupTimeout: protocol.SetupTimeout, drainTimeout: 2 * time.Second, stopTimeout: time.Second,
	}
}

func nonroot() error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("run the frontend as a non-root caller, not with sudo; UID 0 workloads are forbidden")
	}
	return nil
}

func Run(ctx context.Context, request Request, streams Streams) (int, error) {
	if err := nonroot(); err != nil {
		return InfrastructureExit, err
	}
	return defaultClient().run(ctx, request, streams)
}

func Cleanup(ctx context.Context, id string, streams Streams) (int, error) {
	if err := nonroot(); err != nil {
		return InfrastructureExit, err
	}
	return defaultClient().cleanup(ctx, id, streams)
}

func starterCommand(peer, stderr *os.File) *exec.Cmd {
	cmd := exec.Command("/usr/bin/sudo", "--", protocol.StarterPath)
	cmd.Stdin = peer
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	return cmd
}

func launchStarter(peer, stderr *os.File) (*exec.Cmd, error) {
	cmd := starterCommand(peer, stderr)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start fixed authorized starter: %w", err)
	}
	return cmd, nil
}

func sessionSignals() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGWINCH)
	return ch, func() { signal.Stop(ch) }
}

type received struct {
	message protocol.Message
	err     error
}

type connection struct {
	control *protocol.Conn
	events  <-chan received
	process *exec.Cmd
	wait    <-chan error
	stop    context.CancelFunc
}

func (c engineClient) connect(ctx context.Context, streams Streams, first protocol.Message) (_ *connection, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if streams.In == nil || streams.Out == nil || streams.Err == nil {
		return nil, errors.New("stdin, stdout and stderr descriptors are required")
	}
	control, peer, err := protocol.Pair()
	if err != nil {
		return nil, fmt.Errorf("create control socketpair: %w", err)
	}
	defer peer.Close()
	cmd, err := c.launch(peer, streams.Err)
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	readCtx, cancel := context.WithCancel(ctx)
	closeOnCancel := context.AfterFunc(readCtx, func() { _ = control.Close() })
	s := &connection{control: control, process: cmd, wait: wait, stop: func() {
		cancel()
		closeOnCancel()
		_ = control.Close()
	}}
	// No descriptors, command argv, or host file paths are sent with start.
	if err := control.Send(first); err != nil {
		s.stop()
		_ = c.reap(s)
		return nil, fmt.Errorf("send initial request: %w", err)
	}
	events := make(chan received, 1)
	s.events = events
	go func() {
		defer close(events)
		for {
			message, files, err := control.Receive()
			if len(files) != 0 {
				protocol.CloseFiles(files)
				err = errors.New("unexpected descriptors from supervisor")
			}
			select {
			case events <- received{message, err}:
			case <-readCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return s, nil
}

func (c engineClient) reap(s *connection) error {
	if s.wait == nil {
		return nil
	}
	select {
	case err := <-s.wait:
		s.wait = nil
		return err
	case <-time.After(c.stopTimeout):
	}
	_ = s.process.Process.Kill()
	select {
	case <-s.wait:
		s.wait = nil
		return errors.New("authorized starter did not exit within shutdown deadline")
	case <-time.After(c.stopTimeout):
		return errors.New("authorized starter could not be reaped within shutdown deadline")
	}
}

func (c engineClient) run(ctx context.Context, request Request, streams Streams) (code int, resultErr error) {
	code = InfrastructureExit
	if err := request.Config.Validate(); err != nil {
		return code, err
	}
	for _, size := range []*string{&request.Config.Resources.MemoryMax, &request.Config.Resources.WorkspaceSize, &request.Config.Transfers.MaxBytes} {
		value, _ := config.ParseSize(*size)
		*size = config.FormatSize(value)
	}
	if err := protocol.ValidateArgv(request.Argv); err != nil {
		return code, err
	}
	for _, arg := range request.Argv {
		if !utf8.ValidString(arg) {
			return code, errors.New("command arguments must be valid UTF-8; JSON must not silently change argv bytes")
		}
	}
	tty := isTerminal(streams.In) && isTerminal(streams.Out)
	if request.RequireTTY && !tty {
		return code, errors.New("shell requires terminal stdin and stdout; use run -- /bin/bash --noprofile --norc for noninteractive Bash")
	}
	startedAt := time.Now()
	s, err := c.connect(ctx, streams, protocol.Message{Type: "start", Config: &request.Config})
	if err != nil {
		return code, err
	}
	defer func() {
		s.stop()
		if err := c.reap(s); err != nil && resultErr == nil {
			resultErr = fmt.Errorf("starter: %w", err)
		}
		if resultErr != nil {
			code = InfrastructureExit
		}
	}()
	signals, stopSignals := c.signals()
	defer stopSignals()
	timer := time.NewTimer(max(time.Nanosecond, c.setupTimeout-time.Since(startedAt)))
	defer timer.Stop()
	readyDeadline := timer.C
	transferCtx, cancelTransfers := context.WithCancel(ctx)
	defer cancelTransfers()
	var command *commandIO
	var workers *relayWorkers
	var relayFailures <-chan error
	var importRead, importWrite, exportRead, exportWrite *os.File
	var importDone <-chan error
	var exportDone <-chan error
	var importFinished, exportStarted, exportFinished, interrupted bool
	var exportErr error
	forwardSignal := func(sig os.Signal) error {
		if sig == syscall.SIGWINCH {
			if command != nil && tty {
				rows, cols, err := command.resize()
				if err != nil {
					return fmt.Errorf("resize terminal: %w", err)
				}
				return s.control.Send(protocol.Message{Type: "resize", Rows: rows, Cols: cols})
			}
			return nil
		}
		n, ok := sig.(syscall.Signal)
		if !ok || !allowedSignal(n) {
			return nil
		}
		interrupted = true
		cancelTransfers()
		return s.control.Send(protocol.Message{Type: "signal", Signal: int(n)})
	}
	drainSignals := func() error {
		for {
			select {
			case sig, ok := <-signals:
				if !ok {
					signals = nil
					return nil
				}
				if err := forwardSignal(sig); err != nil {
					return err
				}
				if interrupted {
					return nil
				}
			default:
				return nil
			}
		}
	}
	defer func() {
		// On a local relay/transfer failure, terminate through the lifeline
		// before waiting for blocked I/O. Normal results have already drained.
		s.stop()
		cancelTransfers()
		protocol.CloseFiles([]*os.File{importRead, importWrite, exportRead, exportWrite})
		for _, done := range []<-chan error{importDone, exportDone} {
			if done != nil {
				select {
				case <-done:
				case <-time.After(c.stopTimeout):
					resultErr = errors.Join(resultErr, errors.New("transfer did not stop within shutdown deadline"))
				}
			}
		}
		if workers != nil {
			_ = workers.finish(0, c.stopTimeout)
		}
		if command != nil {
			if err := command.close(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("restore caller terminal: %w", err))
			}
		}
	}()
	maxBytes, _ := config.ParseSize(request.Config.Transfers.MaxBytes)
	limits := transfer.Limits{MaxBytes: maxBytes, MaxFiles: request.Config.Transfers.MaxFiles}
	for {
		select {
		case <-ctx.Done():
			return code, ctx.Err()
		case <-readyDeadline:
			return code, errors.New("supervisor was not ready within startup deadline (maximum 45 seconds)")
		case err := <-s.wait:
			s.wait = nil
			if err != nil {
				return code, fmt.Errorf("authorized starter exited: %w", err)
			}
		case err := <-relayFailures:
			return code, err
		case err := <-importDone:
			importDone = nil
			importFinished = true
			if err != nil {
				return code, fmt.Errorf("import: %w", err)
			}
		case err := <-exportDone:
			exportDone = nil
			exportFinished, exportErr = true, err
			ack := protocol.Message{Type: "export-result"}
			if err != nil {
				localDiagnostic(streams.Err, "export: "+err.Error())
				// Host paths and filenames can be sensitive. Never send the
				// transfer library's detailed error back to the root service.
				ack.Error = "export failed after partial publication"
			}
			if err := s.control.Send(ack); err != nil {
				return code, fmt.Errorf("acknowledge export: %w", err)
			}
		case sig, ok := <-signals:
			if !ok {
				signals = nil
				continue
			}
			if err := forwardSignal(sig); err != nil {
				return code, fmt.Errorf("forward signal: %w", err)
			}
		case event, ok := <-s.events:
			if !ok || event.err != nil {
				if event.err != nil && !errors.Is(event.err, io.EOF) {
					return code, fmt.Errorf("supervisor control failed before result: %w", event.err)
				}
				return code, errors.New("supervisor disconnected before result; no export authorized")
			}
			message := event.message
			switch message.Type {
			case "ready":
				if time.Since(startedAt) > c.setupTimeout {
					return code, errors.New("supervisor ready message exceeded startup deadline")
				}
				if command != nil || message.Facts == nil || protocol.ValidateSessionID(message.SessionID) != nil {
					return code, errors.New("invalid or repeated supervisor ready message")
				}
				readyDeadline = nil
				timer.Stop()
				localDiagnostic(streams.Err, "session "+message.SessionID)
				showFacts(streams.Err, *message.Facts)
				if err := drainSignals(); err != nil {
					return code, err
				}
				if interrupted {
					return code, errors.New("session interrupted before workload handoff; no export performed")
				}
				// All host transfer inspection and command I/O start only after
				// the supervisor has established its resource boundary.
				sources, err := transfer.Imports(request.Imports)
				if err != nil {
					return code, fmt.Errorf("import: %w", err)
				}
				command, err = prepareIO(streams, tty)
				if err != nil {
					return code, fmt.Errorf("prepare command I/O: %w", err)
				}
				importRead, importWrite, err = os.Pipe()
				if err != nil {
					return code, err
				}
				exportRead, exportWrite, err = os.Pipe()
				if err != nil {
					return code, err
				}
				stopPipeCancellation := context.AfterFunc(transferCtx, func() {
					_ = importWrite.Close()
					_ = exportRead.Close()
				})
				defer stopPipeCancellation()
				files := append(append([]*os.File(nil), command.files...), importRead, exportWrite)
				err = s.control.Send(protocol.Message{Type: "run", Argv: request.Argv, TTY: tty, Export: request.ExportDirectory != ""}, files...)
				command.closeFiles()
				_ = importRead.Close()
				_ = exportWrite.Close()
				if err != nil {
					return code, fmt.Errorf("send workload request: %w", err)
				}
				workers = command.start(ctx)
				relayFailures = workers.failures
				done := make(chan error, 1)
				importDone = done
				go func() {
					err := transfer.Send(transferCtx, importWrite, sources, limits)
					done <- errors.Join(err, importWrite.Close()) // EOF is required even for an empty import.
				}()
				if tty {
					rows, cols, err := command.resize()
					if err != nil {
						return code, err
					}
					if err := s.control.Send(protocol.Message{Type: "resize", Rows: rows, Cols: cols}); err != nil {
						return code, err
					}
				}
			case "phase", "warning", "facts", "exporting":
				if message.Type == "exporting" || message.Type == "phase" && message.Phase == "exporting" {
					// An already queued signal takes priority over publication,
					// even if select chose the exporting event first.
					if err := drainSignals(); err != nil {
						return code, err
					}
					if command == nil || request.ExportDirectory == "" || interrupted {
						return code, errors.New("unauthorized export phase; no export performed")
					}
					if !exportStarted {
						exportStarted = true
						done := make(chan error, 1)
						exportDone = done
						go func() {
							err := transfer.Receive(transferCtx, exportRead, request.ExportDirectory, limits)
							done <- errors.Join(err, exportRead.Close())
						}()
					}
				}
				if err := showEvent(streams.Err, message); err != nil {
					return code, err
				}
			case "result":
				if message.Result == nil {
					return code, errors.New("result message has no result")
				}
				r := *message.Result
				showResult(streams.Err, r)
				if command == nil {
					if r.ChildStarted || r.ExitCode() != InfrastructureExit {
						return code, errors.New("workload result arrived before run")
					}
					return r.ExitCode(), nil
				}
				if r.ChildStarted && r.ChildExit == 0 && r.Error == "" && !importFinished {
					select {
					case err := <-importDone:
						importDone = nil
						if err != nil {
							return code, fmt.Errorf("import: %w", err)
						}
					case <-time.After(c.stopTimeout):
						return code, errors.New("successful result arrived before import completed")
					}
				}
				if exportStarted && !exportFinished {
					return code, errors.New("result arrived before export acknowledgement")
				}
				if r.ExitCode() == 0 && request.ExportDirectory != "" && !exportFinished {
					return code, errors.New("successful result arrived without authorized export")
				}
				drainErr := workers.finish(c.drainTimeout, c.stopTimeout)
				workers = nil
				if exportErr != nil {
					drainErr = errors.Join(drainErr, errors.New("export failed; partial output is not rolled back"))
				}
				return r.ExitCode(), drainErr
			default:
				return code, errors.New("unexpected supervisor message type")
			}
		}
	}
}

func allowedSignal(sig syscall.Signal) bool {
	return sig == syscall.SIGINT || sig == syscall.SIGTERM || sig == syscall.SIGHUP || sig == syscall.SIGQUIT
}

func (c engineClient) cleanup(ctx context.Context, id string, streams Streams) (code int, resultErr error) {
	code = InfrastructureExit
	if err := protocol.ValidateSessionID(id); err != nil {
		return code, err
	}
	startedAt := time.Now()
	s, err := c.connect(ctx, streams, protocol.Message{Type: "cleanup", SessionID: id})
	if err != nil {
		return code, err
	}
	defer func() {
		s.stop()
		if err := c.reap(s); err != nil && resultErr == nil {
			resultErr = err
		}
		if resultErr != nil {
			code = InfrastructureExit
		}
	}()
	signals, stopSignals := c.signals()
	defer stopSignals()
	timer := time.NewTimer(max(time.Nanosecond, c.setupTimeout-time.Since(startedAt)))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return code, ctx.Err()
		case <-timer.C:
			return code, errors.New("cleanup response deadline exceeded")
		case sig, ok := <-signals:
			if !ok {
				signals = nil
				continue
			}
			if n, ok := sig.(syscall.Signal); ok && allowedSignal(n) {
				return code, errors.New("cleanup interrupted")
			}
		case err := <-s.wait:
			s.wait = nil
			if err != nil {
				return code, fmt.Errorf("authorized starter exited: %w", err)
			}
		case event, ok := <-s.events:
			if !ok || event.err != nil {
				return code, errors.New("supervisor disconnected before cleanup result")
			}
			if event.message.Type == "result" {
				if event.message.Result == nil {
					return code, errors.New("cleanup message has no result")
				}
				r := *event.message.Result
				showResult(streams.Err, r)
				if r.Error != "" || r.CleanupError != "" {
					return code, nil
				}
				return 0, nil
			}
			if err := showEvent(streams.Err, event.message); err != nil {
				return code, err
			}
		}
	}
}

func localDiagnostic(w io.Writer, text string) {
	message := "soteria: " + safeText(text, 1024) + "\n"
	if file, ok := w.(*os.File); ok {
		fd, err := hostRelay(file, true)
		if err != nil {
			return
		}
		defer fd.close()
		// A full caller stderr pipe must not strand a session or raw terminal.
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		_ = writeRelay(ctx, fd, []byte(message))
		return
	}
	_, _ = io.WriteString(w, message)
}

func safeText(text string, limit int) string {
	var b strings.Builder
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = ' '
		}
		if b.Len()+len(string(r)) > limit-3 {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func showEvent(w io.Writer, message protocol.Message) error {
	switch message.Type {
	case "phase":
		localDiagnostic(w, "phase: "+message.Phase)
	case "warning":
		localDiagnostic(w, "warning: "+message.Warning)
	case "facts":
		if message.Facts == nil {
			return errors.New("facts message has no facts")
		}
		showFacts(w, *message.Facts)
	case "exporting":
		localDiagnostic(w, "phase: exporting")
	default:
		return errors.New("unexpected supervisor event")
	}
	return nil
}

func showFacts(w io.Writer, facts protocol.Facts) {
	fact := func(value string) string {
		if value == "" {
			return "unverified"
		}
		return safeText(value, 128)
	}
	localDiagnostic(w, fmt.Sprintf("facts: filesystem=%s anonymous-memory-swap=%s tmpfs-swap=%s dump-policy=%s network=%s cleanup=%s runtime-digest=%s",
		fact(facts.Filesystem), fact(facts.AnonymousSwap), fact(facts.TmpfsSwap),
		fact(facts.DumpPolicy), fact(facts.Network), fact(facts.Cleanup), fact(facts.RuntimeDigest)))
}

func showResult(w io.Writer, result protocol.Result) {
	if result.Error != "" {
		localDiagnostic(w, "session: "+result.Error)
	}
	if result.CleanupError != "" {
		localDiagnostic(w, fmt.Sprintf("child started=%t exit=%d; cleanup failed: %s", result.ChildStarted, result.ChildExit, result.CleanupError))
	}
	showFacts(w, result.Facts)
}
