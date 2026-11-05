//go:build linux && amd64

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/transfer"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Run uses the experimental Linux engine and fails closed if any required
// prerequisite or isolation boundary is unavailable. No privilege-free fallback
// or host-command execution path is provided.
func Run(ctx context.Context, request Request, streams Streams) (code int, resultErr error) {
	if err := request.Validate(); err != nil {
		return InfrastructureFailure, err
	}
	if err := frontendIdentity(ctx); err != nil {
		return InfrastructureFailure, err
	}
	if err := runtimePrerequisites(true); err != nil {
		return InfrastructureFailure, err
	}
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, err
	}
	sources, err := transfer.Imports(request.Imports)
	if err != nil {
		return InfrastructureFailure, fmt.Errorf("validate imports as caller: %w", err)
	}
	if request.ExportDirectory != "" {
		request.ExportDirectory, err = filepath.Abs(request.ExportDirectory)
		if err != nil {
			return InfrastructureFailure, err
		}
	}
	streams = normalizeStreams(streams)
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, err
	}
	bridge, err := newFrontendIO(request.Interactive, streams)
	if err != nil {
		return InfrastructureFailure, err
	}
	defer func() {
		err := bridge.restore()
		bridge.close()
		if err != nil {
			code, resultErr = InfrastructureFailure, errors.Join(resultErr, fmt.Errorf("restore caller terminal: %w", err))
		}
	}()
	message := controlMessage{Version: protocolVersion, Kind: "run", Request: &wireRequest{
		Config: request.Config, Command: append([]string(nil), request.Command...), Interactive: request.Interactive,
		Import: len(sources) > 0, Export: request.ExportDirectory != "", Terminal: safeTerminal(os.Getenv("TERM")),
	}}
	return invokeStarter(ctx, message, request, sources, bridge, streams)
}

// Cleanup never kills an active session or infers ownership from its name. The
// authorized worker verifies a root-owned caller record and an empty cgroup.
func Cleanup(ctx context.Context, id string, streams Streams) error {
	if !validSessionID(id) {
		return errors.New("session ID must be exactly 32 lowercase hexadecimal characters")
	}
	if err := frontendIdentity(ctx); err != nil {
		return err
	}
	if err := runtimePrerequisites(false); err != nil {
		return err
	}
	_, err := invokeStarter(ctx, controlMessage{Version: protocolVersion, Kind: "cleanup", Target: id}, Request{}, nil, nil, normalizeStreams(streams))
	return err
}

func frontendIdentity(ctx context.Context) error {
	if ctx == nil {
		return errors.New("session context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getgid() == 0 || os.Getegid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return errors.New("run Soteria as a non-root caller, not with sudo; only the fixed one-shot starter requests authorization")
	}
	return nil
}

type lockedWriter struct {
	mu     *sync.Mutex
	writer io.Writer
}

func (w lockedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(data)
}

func normalizeStreams(streams Streams) Streams {
	if streams.In == nil {
		streams.In = strings.NewReader("")
	}
	if streams.Out == nil {
		streams.Out = io.Discard
	}
	if streams.Err == nil {
		streams.Err = io.Discard
	}
	// Arbitrary io.Writers (including bytes.Buffer in embedders/tests) need not
	// support concurrent command output, diagnostics, and sudo prompts.
	mu := new(sync.Mutex)
	streams.Out = lockedWriter{mu, streams.Out}
	streams.Err = lockedWriter{mu, streams.Err}
	return streams
}

type frontendIO struct {
	service []*os.File
	local   []*os.File
	master  *os.File
	input   *os.File
	output  *os.File
	state   *term.State
	started bool
	done    chan error
	failure chan error
	outputs int
}

func newFrontendIO(interactive bool, streams Streams) (_ *frontendIO, err error) {
	bridge := &frontendIO{done: make(chan error, 2), failure: make(chan error, 1)}
	defer func() {
		if err != nil {
			bridge.close()
		}
	}()
	if interactive {
		input, ok := streams.In.(*os.File)
		if !ok || !term.IsTerminal(int(input.Fd())) {
			return nil, errors.New("interactive mode requires a real caller terminal on stdin")
		}
		// normalizeStreams wraps output writers, so unwrap only our own wrapper.
		outputWriter := streams.Out
		if wrapped, ok := outputWriter.(lockedWriter); ok {
			outputWriter = wrapped.writer
		}
		output, ok := outputWriter.(*os.File)
		if !ok || !term.IsTerminal(int(output.Fd())) {
			return nil, errors.New("interactive mode requires a real caller terminal on stdout")
		}
		master, slave, err := pty.Open()
		if err != nil {
			return nil, fmt.Errorf("allocate dedicated workload PTY: %w", err)
		}
		bridge.master, bridge.input, bridge.output = master, input, output
		bridge.local = []*os.File{master}
		bridge.service = []*os.File{slave, slave, slave}
		if err := pty.InheritSize(input, master); err != nil {
			return nil, fmt.Errorf("set workload PTY size: %w", err)
		}
		return bridge, nil
	}
	for i := 0; i < 3; i++ {
		read, write, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		if i == 0 {
			bridge.service = append(bridge.service, read)
			bridge.local = append(bridge.local, write)
		} else {
			bridge.service = append(bridge.service, write)
			bridge.local = append(bridge.local, read)
		}
	}
	return bridge, nil
}

func (b *frontendIO) releaseServiceFiles() {
	// PTY stdio deliberately uses the same slave three times.
	seen := make(map[*os.File]bool)
	for _, file := range b.service {
		if !seen[file] {
			_ = file.Close()
			seen[file] = true
		}
	}
	b.service = nil
}

func (b *frontendIO) start(streams Streams) error {
	if b.started {
		return errors.New("duplicate stdio activation")
	}
	b.started = true
	output := func(source *os.File, destination io.Writer, isPTY bool) {
		b.outputs++
		go func() {
			_, err := io.Copy(destination, source)
			if isPTY && errors.Is(err, unix.EIO) {
				err = nil // Linux PTY masters report EIO when their final slave closes.
			}
			if err != nil && !errors.Is(err, os.ErrClosed) {
				select {
				case b.failure <- fmt.Errorf("command output relay: %w", err):
				default:
				}
			}
			b.done <- err
		}()
	}
	if b.master != nil {
		state, err := term.MakeRaw(int(b.input.Fd()))
		if err != nil {
			return fmt.Errorf("enter terminal relay mode: %w", err)
		}
		b.state = state
		output(b.master, streams.Out, true)
		go func() { _, _ = io.Copy(b.master, streams.In) }()
		return nil
	}
	output(b.local[1], streams.Out, false)
	output(b.local[2], streams.Err, false)
	go func() {
		_, _ = io.Copy(b.local[0], streams.In)
		_ = b.local[0].Close() // Workload stdin EOF is not a lifeline event.
	}()
	return nil
}

func (b *frontendIO) drain() error {
	if b == nil || !b.started {
		return nil
	}
	timer := time.NewTimer(controlTimeout)
	defer timer.Stop()
	var result error
	for i := 0; i < b.outputs; i++ {
		select {
		case err := <-b.done:
			if err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, unix.EIO) {
				result = errors.Join(result, err)
			}
		case <-timer.C:
			return errors.Join(result, errors.New("command output did not drain before the bounded relay deadline"))
		}
	}
	return result
}

func (b *frontendIO) close() {
	if b == nil {
		return
	}
	_ = b.restore()
	b.releaseServiceFiles()
	_ = closeFiles(b.local)
}

func (b *frontendIO) restore() error {
	if b == nil || b.state == nil {
		return nil
	}
	err := term.Restore(int(b.input.Fd()), b.state)
	b.state = nil
	return err
}

type incomingControl struct {
	message controlMessage
	err     error
}

func readControl(connection *net.UnixConn) <-chan incomingControl {
	channel := make(chan incomingControl, 8)
	go func() {
		defer close(channel)
		for {
			var message controlMessage
			_, err := receivePacket(connection, &message, 0)
			channel <- incomingControl{message, err}
			if err != nil {
				return
			}
		}
	}()
	return channel
}

func invokeStarter(ctx context.Context, message controlMessage, request Request, sources []transfer.Source, bridge *frontendIO, streams Streams) (code int, resultErr error) {
	if err := verifyRootExecutable(sudoExecutable, true); err != nil {
		return InfrastructureFailure, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, err
	}
	connection, peer, err := socketPair()
	if err != nil {
		return InfrastructureFailure, err
	}
	defer connection.Close()
	defer peer.Close()
	writer := &packetWriter{connection: connection}
	var files []*os.File
	var importRead, importWrite, exportRead, exportWrite *os.File
	if bridge != nil {
		files = append(files, bridge.service...)
	}
	if message.Request != nil && message.Request.Import {
		importRead, importWrite, err = os.Pipe()
		if err != nil {
			return InfrastructureFailure, err
		}
		defer importWrite.Close()
		defer importRead.Close()
		files = append(files, importRead)
	}
	if message.Request != nil && message.Request.Export {
		exportRead, exportWrite, err = os.Pipe()
		if err != nil {
			return InfrastructureFailure, err
		}
		defer exportRead.Close()
		defer exportWrite.Close()
		files = append(files, exportWrite)
	}
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, err
	}
	// The user-selected command and every host filename stay off sudo/systemd
	// argv and environment. sudo authenticates on its normal /dev/tty, not -S.
	starter := exec.Command(sudoExecutable, "--", installedExecutable, "__start")
	starter.Stdin, starter.Stdout, starter.Stderr = peer, io.Discard, streams.Err
	starter.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "TERM=" + safeTerminal(os.Getenv("TERM"))}
	starter.WaitDelay = controlTimeout
	if err := starter.Start(); err != nil {
		return InfrastructureFailure, fmt.Errorf("authorize fixed session starter: %w", err)
	}
	_ = peer.Close()
	waited := make(chan error, 1)
	starterExited := make(chan struct{})
	go func() { waited <- starter.Wait(); close(starterExited) }()
	// Request graceful cancellation while retaining final cleanup evidence. If
	// the worker is stuck, closing the independent lifeline forces the starter
	// to stop the complete service cgroup. CLI death closes it immediately in
	// the kernel and does not depend on this callback.
	shutdownContext, stopShutdown := context.WithCancel(context.Background())
	defer stopShutdown()
	stopClose := context.AfterFunc(ctx, func() {
		_ = connection.SetWriteDeadline(time.Now().Add(controlTimeout))
		_ = writer.send(controlMessage{Version: protocolVersion, Kind: "cancel"})
		if importWrite != nil {
			_ = importWrite.Close()
		}
		if exportRead != nil {
			_ = exportRead.Close()
		}
		timer := time.NewTimer(stopTimeout + controlTimeout)
		defer timer.Stop()
		select {
		case <-shutdownContext.Done():
		case <-timer.C:
			_ = connection.Close()
		}
	})
	defer stopClose()
	if err := writer.send(message, files...); err != nil {
		cancel(err)
		return InfrastructureFailure, errors.Join(err, waitStarter(waited, starter))
	}
	if bridge != nil {
		bridge.releaseServiceFiles()
	}
	if importRead != nil {
		_ = importRead.Close()
	}
	if exportWrite != nil {
		_ = exportWrite.Close()
	}
	incoming := readControl(connection)
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGWINCH, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	limits := transfer.Limits{}
	if message.Request != nil {
		limits.MaxBytes, _ = config.ParseSize(request.Config.Transfers.MaxBytes)
		limits.MaxFiles = request.Config.Transfers.MaxFiles
	}
	importResult := make(chan error, 1)
	exportResult := make(chan error, 1)
	var accepted, imported, exporting, haveResult, haveFinal bool
	var cancellation error
	ctxDone := ctx.Done()
	var shutdownTimer *time.Timer
	var shutdownDeadline <-chan time.Time
	var starterExitTimer *time.Timer
	var starterExitDeadline <-chan time.Time
	defer func() {
		if shutdownTimer != nil {
			shutdownTimer.Stop()
		}
		if starterExitTimer != nil {
			starterExitTimer.Stop()
		}
	}()
	var relayFailure <-chan error
	if bridge != nil {
		relayFailure = bridge.failure
	}
	code = InfrastructureFailure
	for !haveFinal {
		select {
		case <-starterExited:
			starterExited = nil
			// The final packet is sent before starter exit, but its reader may
			// lose this select race. Allow it to drain before declaring loss.
			starterExitTimer = time.NewTimer(time.Second)
			starterExitDeadline = starterExitTimer.C
		case <-starterExitDeadline:
			starterExitDeadline = nil
			cancel(errors.New("authorized starter exited without final systemd cleanup evidence"))
		case <-ctxDone:
			ctxDone = nil
			cancellation = context.Cause(ctx)
			shutdownTimer = time.NewTimer(2*stopTimeout + 2*controlTimeout)
			shutdownDeadline = shutdownTimer.C
		case <-shutdownDeadline:
			_ = connection.Close()
			_ = starter.Process.Kill()
			return InfrastructureFailure, errors.Join(resultErr, cancellation, errors.New("canceled session did not confirm final cgroup/ExecStopPost shutdown"), reapBounded(waited, starter, time.Second))
		case failure := <-relayFailure:
			cancel(failure)
		case received, open := <-incoming:
			if !open || received.err != nil {
				err := errors.Join(errors.New("session control closed before final systemd cleanup confirmation"), received.err)
				cancel(err)
				_ = connection.Close()
				return InfrastructureFailure, errors.Join(resultErr, err, cancellation, waitStarter(waited, starter))
			}
			event := received.message
			if event.Version != protocolVersion || event.Request != nil || event.Target != "" || event.Signal != 0 || event.Cancelled && event.Kind != "result" {
				cancel(errors.New("invalid service control response"))
				continue
			}
			switch event.Kind {
			case "started":
				if !validSessionID(event.ID) {
					cancel(errors.New("invalid generated session identity"))
				} else {
					_, _ = fmt.Fprintf(streams.Err, "soteria: experimental session %s; stdout and explicit exports leave the workspace; interruption/failure skips export unless already started, and host output is not rolled back\n", event.ID)
				}
			case "accepted":
				if accepted {
					cancel(errors.New("duplicate service request acceptance"))
					continue
				}
				accepted = true
				if bridge != nil {
					if err := bridge.start(streams); err != nil {
						cancel(err)
					}
				}
				if importWrite != nil {
					go func() {
						err := transfer.Send(ctx, importWrite, sources, limits)
						err = errors.Join(err, importWrite.Close())
						importResult <- err
						if err != nil {
							cancel(fmt.Errorf("caller import stream: %w", err))
						}
					}()
				}
			case "phase":
				if !validPhase(event.Phase) {
					cancel(errors.New("invalid lifecycle phase"))
					continue
				}
				_, _ = fmt.Fprintf(streams.Err, "soteria: %s\n", event.Phase)
				if event.Phase == "Exporting" {
					if exporting || exportRead == nil {
						cancel(errors.New("unexpected export boundary"))
						continue
					}
					exporting = true
					go func() {
						err := transfer.Receive(ctx, exportRead, request.ExportDirectory, limits)
						err = errors.Join(err, exportRead.Close())
						exportResult <- err
						ack := controlMessage{Version: protocolVersion, Kind: "export-result"}
						if err != nil {
							ack.Code, ack.Text = InfrastructureFailure, "caller export receiver failed; partial output is not rolled back"
						}
						if sendErr := writer.send(ack); sendErr != nil {
							cancel(sendErr)
						}
					}()
				}
			case "warning":
				_, _ = fmt.Fprintf(streams.Err, "soteria: warning: %s\n", boundedDiagnostic(errors.New(event.Text)))
			case "fact":
				_, _ = fmt.Fprintf(streams.Err, "soteria: %s\n", boundedDiagnostic(errors.New(event.Text)))
			case "cleanup-result":
				if event.Code != 0 {
					resultErr = errors.Join(resultErr, errors.New(event.Text))
				}
			case "result":
				if haveResult || event.Code < 0 || event.Code > 255 {
					cancel(errors.New("invalid or duplicate command result"))
					continue
				}
				haveResult, code = true, event.Code
				if event.Cancelled {
					if ctx.Err() == nil || event.Text != "" {
						resultErr = errors.Join(resultErr, errors.New("service canceled unexpectedly or reported ambiguous cancellation"))
					} else {
						cancellation = context.Cause(ctx)
					}
				} else if event.Text != "" {
					resultErr = errors.Join(resultErr, errors.New(event.Text))
				}
			case "service":
				haveFinal = true
				if event.Code != 0 || event.Text != "" {
					resultErr = errors.Join(resultErr, fmt.Errorf("service/cleanup: %s", event.Text))
				}
			default:
				cancel(errors.New("unexpected service control message"))
			}
		case signal := <-signals:
			switch signal {
			case syscall.SIGWINCH:
				if bridge != nil && bridge.master != nil {
					if err := pty.InheritSize(bridge.input, bridge.master); err != nil {
						cancel(err)
					}
				}
			case syscall.SIGINT, syscall.SIGQUIT:
				if bridge != nil && bridge.master != nil && bridge.started {
					character := byte(3)
					if signal == syscall.SIGQUIT {
						character = 28
					}
					_, _ = bridge.master.Write([]byte{character})
				} else {
					_ = writer.send(controlMessage{Version: protocolVersion, Kind: "signal", Signal: int(signal.(syscall.Signal))})
				}
			default:
				cancel(fmt.Errorf("caller received %s", signal))
			}
		}
	}
	_ = connection.Close()
	resultErr = errors.Join(resultErr, waitStarter(waited, starter))
	if !haveResult {
		resultErr = errors.Join(resultErr, errors.New("worker did not report a command result"))
	}
	if importWrite != nil && accepted {
		select {
		case err := <-importResult:
			imported = true
			if cancellation == nil {
				resultErr = errors.Join(resultErr, err)
			}
		default:
		}
		if !imported && cancellation == nil {
			resultErr = errors.Join(resultErr, errors.New("import sender did not complete"))
		}
	}
	if exporting {
		select {
		case err := <-exportResult:
			resultErr = errors.Join(resultErr, err)
		default:
			resultErr = errors.Join(resultErr, errors.New("export receiver did not complete"))
		}
	}
	resultErr = errors.Join(resultErr, bridge.drain())
	resultErr = errors.Join(resultErr, cancellation)
	if onlyCanceled(resultErr) {
		if exporting {
			_, _ = fmt.Fprintln(streams.Err, "soteria: canceled after export began; partial or completed host output is not rolled back; cgroup and ExecStopPost cleanup confirmed")
		} else {
			_, _ = fmt.Fprintln(streams.Err, "soteria: canceled; no export; service cgroup stopped and fixed ExecStopPost completed successfully")
		}
		return InfrastructureFailure, resultErr
	}
	if resultErr != nil {
		return InfrastructureFailure, fmt.Errorf("session infrastructure failure (child status %d): %w", code, resultErr)
	}
	_, _ = fmt.Fprintln(streams.Err, "soteria: cleanup: service cgroup stopped and fixed ExecStopPost completed successfully")
	return code, nil
}

func waitStarter(waited <-chan error, starter *exec.Cmd) error {
	timer := time.NewTimer(2*stopTimeout + 2*controlTimeout)
	defer timer.Stop()
	select {
	case err := <-waited:
		if err != nil {
			return fmt.Errorf("authorized starter failed: %w", err)
		}
		return nil
	case <-timer.C:
		_ = starter.Process.Kill()
		return errors.New("authorized starter did not confirm bounded service shutdown; cleanup remains unverified")
	}
}

func validPhase(phase string) bool {
	switch phase {
	case "Validating", "Preparing", "NetworkReady", "Running", "Exporting", "Stopping", "Finished", "Failed":
		return true
	}
	return false
}
