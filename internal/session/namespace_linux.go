//go:build linux && amd64

package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/entrypoint"
	"github.com/Lfardell1/Soteria/internal/filesystem"
	"github.com/Lfardell1/Soteria/internal/network"
	"github.com/Lfardell1/Soteria/internal/protocol"
	"github.com/Lfardell1/Soteria/internal/toolkit"
	"golang.org/x/sys/unix"
)

func namespaceWorker(parent context.Context) (int, error) {
	environment, err := currentService()
	if err != nil {
		return InfrastructureFailure, err
	}
	if err := requirePrivateNamespaces(); err != nil {
		return InfrastructureFailure, err
	}
	// The later bwrap exec explicitly adds only its fresh proof socket and JSON
	// status pipe. None of these inherited supervisor handles can reach it.
	if err := unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return InfrastructureFailure, fmt.Errorf("require close_range(CLOEXEC) descriptor hygiene: %w", err)
	}
	control := os.NewFile(3, "root supervisor control")
	defer control.Close()
	credentials, err := unix.GetsockoptUcred(3, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || credentials.Uid != 0 || credentials.Gid != 0 || int(credentials.Pid) != os.Getppid() {
		return InfrastructureFailure, errors.New("namespace worker requires its root supervisor's private socketpair")
	}
	connection, err := connectionFromFile(control)
	if err != nil {
		return InfrastructureFailure, err
	}
	defer connection.Close()
	writer := &packetWriter{connection: connection}
	_ = connection.SetReadDeadline(time.Now().Add(controlTimeout))
	var initial namespaceMessage
	_, err = receivePacket(connection, &initial, 0)
	if err != nil {
		return InfrastructureFailure, err
	}
	_ = connection.SetReadDeadline(time.Time{})
	if initial.Plan == nil || initial != (namespaceMessage{Version: protocolVersion, Kind: "init", Plan: initial.Plan}) {
		return InfrastructureFailure, errors.New("invalid root namespace plan")
	}
	plan := *initial.Plan
	if err := plan.Request.validate(); err != nil {
		return InfrastructureFailure, err
	}
	terminal := "dumb"
	if plan.Request.Interactive {
		terminal = "xterm-256color"
	}
	if !plan.Request.Import || plan.Request.Terminal != terminal {
		return InfrastructureFailure, errors.New("namespace requires its always-present import stream and fixed terminal type")
	}
	if plan.Caller.UID == 0 || plan.Caller.GID == 0 || plan.Caller.UID == ^uint32(0) || plan.Caller.GID == ^uint32(0) {
		return InfrastructureFailure, errors.New("namespace plan lacks authenticated non-root credentials")
	}
	files := make([]*os.File, 5)
	for i := range files {
		files[i] = os.NewFile(uintptr(4+i), "authorized namespace stream")
	}
	defer func() { _ = closeNamespaceFiles(files) }()
	if err := validateIO(files, plan.Request, plan.Caller); err != nil {
		return InfrastructureFailure, err
	}
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	stopRead := context.AfterFunc(ctx, func() { _ = connection.SetReadDeadline(time.Now()) })
	defer stopRead()
	controlState := &supervisorControl{}
	events := monitorSupervisor(ctx, connection, cancel, controlState)
	result := executeNamespace(ctx, environment, plan, files, writer, events, cancel, controlState)
	if err := sendNamespace(writer, namespaceMessage{Version: protocolVersion, Kind: "result", Result: &result}); err != nil {
		return InfrastructureFailure, err
	}
	// The private result carries child status and independent cleanup failures.
	// The root supervisor/starter owns final service and ExecStopPost verification.
	return 0, nil
}

func sendNamespace(writer *packetWriter, message namespaceMessage, files ...*os.File) error {
	if err := writer.connection.SetWriteDeadline(time.Now().Add(controlTimeout)); err != nil {
		return err
	}
	return writer.send(message, files...)
}

func validateSupervisorMessage(message namespaceMessage) error {
	expected := namespaceMessage{Version: protocolVersion, Kind: message.Kind}
	switch message.Kind {
	case "cancel", "run":
	case "network":
		if len(message.Link) > 15 {
			return errors.New("invalid moved interface name")
		}
		expected.Link = message.Link
	case "signal":
		switch syscall.Signal(message.Signal) {
		case syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT:
		default:
			return errors.New("invalid supervisor signal")
		}
		expected.Signal = message.Signal
	case "resize":
		if message.Rows == 0 || message.Cols == 0 {
			return errors.New("invalid terminal dimensions")
		}
		expected.Rows, expected.Cols = message.Rows, message.Cols
	case "export-result":
		if message.Code != 0 && message.Code != InfrastructureFailure || len(message.Text) > 4096 || message.Code == 0 && message.Text != "" {
			return errors.New("invalid export acknowledgement")
		}
		expected.Code, expected.Text = message.Code, message.Text
	default:
		return errors.New("unexpected root supervisor operation")
	}
	if message != expected {
		return errors.New("unexpected root supervisor fields")
	}
	return nil
}

type supervisorControl struct {
	signaled  atomic.Bool
	exporting atomic.Bool
}

func monitorSupervisor(ctx context.Context, connection *net.UnixConn, cancel context.CancelCauseFunc, state *supervisorControl) <-chan namespaceMessage {
	events := make(chan namespaceMessage, 4)
	go func() {
		defer close(events)
		for {
			var message namespaceMessage
			_, err := receivePacket(connection, &message, 0)
			if err != nil {
				cancel(errors.Join(errors.New("root supervisor lifeline disconnected"), err))
				return
			}
			if err := validateSupervisorMessage(message); err != nil {
				cancel(err)
				return
			}
			if message.Kind == "cancel" {
				cancel(context.Canceled)
				return
			}
			if message.Kind == "signal" {
				state.signaled.Store(true)
				if state.exporting.Load() {
					cancel(errors.New("signal received during export; partial output is not rolled back"))
					return
				}
			}
			if message.Kind == "resize" {
				// The non-root frontend already resized its own fresh PTY slave.
				// Never issue a root ioctl against a caller-selected terminal here.
				continue
			}
			select {
			case events <- message:
			case <-ctx.Done():
				return
			}
		}
	}()
	return events
}

func nextSupervisor(ctx context.Context, events <-chan namespaceMessage, kind string) (namespaceMessage, error) {
	if err := ctx.Err(); err != nil {
		return namespaceMessage{}, context.Cause(ctx)
	}
	select {
	case <-ctx.Done():
		return namespaceMessage{}, context.Cause(ctx)
	case event, open := <-events:
		if !open || event.Kind != kind {
			return namespaceMessage{}, fmt.Errorf("expected %s authorization from root supervisor", kind)
		}
		if err := ctx.Err(); err != nil {
			return namespaceMessage{}, context.Cause(ctx)
		}
		return event, nil
	}
}

func executeNamespace(ctx context.Context, environment serviceEnvironment, plan namespacePlan, files []*os.File, writer *packetWriter, events <-chan namespaceMessage, cancel context.CancelCauseFunc, controlState *supervisorControl) protocol.Result {
	return New().Run(ctx, func(ctx context.Context, owner *Session) protocol.Result {
		result := protocol.Result{ChildExit: InfrastructureFailure}
		fail := func(err error) protocol.Result {
			result.Error = boundedDiagnostic(err)
			return result
		}
		facts := func() error {
			return sendNamespace(writer, namespaceMessage{Version: protocolVersion, Kind: "facts", Facts: &result.Facts})
		}
		if err := owner.Acquire(ctx, "authorized streams", func(context.Context) (func() error, error) {
			return func() error { return closeNamespaceFiles(files) }, nil
		}); err != nil {
			return fail(err)
		}
		if err := owner.Advance(ctx, Preparing); err != nil {
			return fail(err)
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			return fail(fmt.Errorf("make mount propagation recursively private: %w", err))
		}
		if err := ctx.Err(); err != nil {
			return fail(context.Cause(ctx))
		}
		runtimeDirectory, err := openRootDirectory(toolkit.Root, false)
		if err != nil {
			return fail(fmt.Errorf("curated runtime lookup ancestors are untrusted: %w", err))
		}
		if err := runtimeDirectory.Close(); err != nil {
			return fail(err)
		}
		inventory, err := toolkit.Verify(toolkit.Root)
		if err != nil {
			return fail(fmt.Errorf("verified curated runtime is required: %w", err))
		}
		result.Facts.RuntimeDigest = inventory.Digest
		if err := facts(); err != nil {
			return fail(err)
		}
		executable, err := resolveRuntimeCommand(plan.Request.Command[0])
		if err != nil {
			return fail(err)
		}
		quiescent := true
		var workspace *filesystem.Workspace
		workspaceBytes, _ := config.ParseSize(plan.Request.Config.Resources.WorkspaceSize)
		if err := owner.Acquire(ctx, "private tmpfs", func(context.Context) (func() error, error) {
			var err error
			workspace, err = filesystem.Mount(environment.Directory, workspaceBytes, plan.Caller.UID, plan.Caller.GID)
			if workspace == nil {
				return nil, err
			}
			return func() error {
				if !quiescent {
					return errors.New("refuse tmpfs teardown while owned descendant quiescence is unverified; systemd cgroup shutdown is required")
				}
				return workspace.Close()
			}, err
		}); err != nil {
			return fail(err)
		}
		result.Facts.Filesystem = "bounded private writable tmpfs with nosuid,nodev verified"
		result.Facts.TmpfsSwap = "unverified; workspace files may be swapped to host storage"
		if workspace.Noswap {
			result.Facts.TmpfsSwap = "tmpfs noswap verified"
		}
		if err := facts(); err != nil {
			return fail(err)
		}
		for _, warning := range workspace.Warnings {
			if err := sendNamespace(writer, namespaceMessage{Version: protocolVersion, Kind: "warning", Text: warning}); err != nil {
				return fail(err)
			}
		}
		if err := ctx.Err(); err != nil {
			return fail(context.Cause(ctx))
		}
		if err := network.PrepareOffline(); err != nil {
			return fail(fmt.Errorf("prepare closed private network namespace: %w", err))
		}
		if err := ctx.Err(); err != nil {
			return fail(context.Cause(ctx))
		}
		namespace, err := os.Open("/proc/self/ns/net")
		if err != nil {
			return fail(err)
		}
		err = sendNamespace(writer, namespaceMessage{Version: protocolVersion, Kind: "namespace", Workspace: filepath.Base(workspace.Root)}, namespace)
		if err := errors.Join(err, namespace.Close()); err != nil {
			return fail(err)
		}
		moved, err := nextSupervisor(ctx, events, "network")
		if err != nil {
			return fail(err)
		}
		var tunnel *network.Tunnel
		if plan.Request.Config.Network.Mode == "wireguard" {
			if moved.Link != "st"+environment.ID[:13] {
				return fail(errors.New("root supervisor did not move the exact owned WireGuard link"))
			}
			if err := ctx.Err(); err != nil {
				return fail(context.Cause(ctx))
			}
			profile, err := network.LoadProfile(plan.Request.Config.Network.Profile)
			if err != nil {
				return fail(err)
			}
			if err := owner.Acquire(ctx, "owned WireGuard tunnel", func(ctx context.Context) (func() error, error) {
				var err error
				tunnel, err = network.ConfigureWireGuard(ctx, moved.Link, profile)
				if tunnel == nil {
					return nil, err
				}
				return tunnel.Close, err
			}); err != nil {
				return fail(err)
			}
			servers := make([]string, len(profile.DNS))
			for i, address := range profile.DNS {
				servers[i] = address.String()
			}
			profile = network.Profile{}
			if err := ctx.Err(); err != nil {
				return fail(context.Cause(ctx))
			}
			if err := workspace.SetResolver(servers); err != nil {
				return fail(err)
			}
			readyCtx, stopReady := context.WithTimeout(ctx, 30*time.Second)
			err = tunnel.WaitReady(readyCtx)
			stopReady()
			if err != nil {
				return fail(err)
			}
		} else if moved.Link != "" {
			return fail(errors.New("offline namespace unexpectedly received an external interface"))
		}
		result.Facts.Network = "private loopback only; no external interfaces or routes; native IPv6 disabled and verified"
		if tunnel != nil {
			result.Facts.Network = "owned IPv4 full-tunnel WireGuard route, fresh authenticated handshake and configured-resolver probe verified; no plaintext fallback"
		}
		if err := facts(); err != nil {
			return fail(err)
		}
		if err := ctx.Err(); err != nil {
			return fail(context.Cause(ctx))
		}
		directory, err := workspace.OpenImport()
		if err != nil {
			return fail(err)
		}
		err = runTransferHelper(ctx, "receive", plan, directory, files[3], nil)
		err = errors.Join(err, directory.Close(), closeNamespaceFile(files, 3))
		if err != nil {
			return fail(fmt.Errorf("non-root workspace import: %w", err))
		}
		if !plan.Request.Export {
			if err := closeNamespaceFile(files, 4); err != nil {
				return fail(err)
			}
		}
		if err := owner.Advance(ctx, NetworkReady); err != nil {
			return fail(err)
		}
		if err := sendNamespace(writer, namespaceMessage{Version: protocolVersion, Kind: "ready"}); err != nil {
			return fail(err)
		}
		if _, err := nextSupervisor(ctx, events, "run"); err != nil {
			return fail(err)
		}
		arguments, err := bubblewrapArguments(workspace, plan.Caller, plan.Request, executable)
		if err != nil {
			return fail(err)
		}
		command := exec.Command(bubblewrapExecutable, arguments...)
		command.Env = entrypoint.Environment(plan.Request.Interactive)
		command.Stdin, command.Stdout, command.Stderr = files[0], files[1], files[2]
		var payloadCleanup error
		if err := owner.Acquire(ctx, "owned payload descendants", func(context.Context) (func() error, error) {
			return func() error { return payloadCleanup }, nil
		}); err != nil {
			return fail(err)
		}
		if err := owner.Advance(ctx, Running); err != nil {
			return fail(err)
		}
		payload := runPayload(ctx, command, plan.Caller, events, func() func() {
			return monitorTunnel(ctx, tunnel, cancel)
		})
		quiescent, payloadCleanup = payload.quiescent, payload.cleanupErr
		result.ChildStarted, result.ChildExit = payload.started, payload.code
		for i := 0; i < 3; i++ {
			payloadCleanup = errors.Join(payloadCleanup, closeNamespaceFile(files, i))
		}
		payload.cleanupErr = payloadCleanup
		if payload.err != nil {
			return fail(payload.err)
		}
		if err := ctx.Err(); err != nil {
			return fail(context.Cause(ctx))
		}
		if !payload.exportable() || !plan.Request.Export || controlState.signaled.Load() {
			return result
		}
		controlState.exporting.Store(true)
		if controlState.signaled.Load() || ctx.Err() != nil {
			return result
		}
		if err := owner.Advance(ctx, Exporting); err != nil {
			return fail(err)
		}
		directory, err = workspace.OpenExport()
		if err != nil {
			return fail(err)
		}
		if err := sendNamespace(writer, namespaceMessage{Version: protocolVersion, Kind: "exporting"}); err != nil {
			return fail(errors.Join(err, directory.Close()))
		}
		err = runTransferHelper(ctx, "send", plan, directory, nil, files[4])
		err = errors.Join(err, directory.Close(), closeNamespaceFile(files, 4))
		if err != nil {
			return fail(fmt.Errorf("non-root workspace export (partial output is not rolled back): %w", err))
		}
		acknowledgement, err := nextSupervisor(ctx, events, "export-result")
		if err != nil {
			return fail(err)
		}
		if acknowledgement.Code != 0 {
			return fail(errors.New("caller did not confirm successful export; partial output is not rolled back"))
		}
		return result
	})
}

func closeNamespaceFile(files []*os.File, index int) error {
	file := files[index]
	files[index] = nil
	if file != nil {
		return file.Close()
	}
	return nil
}

func closeNamespaceFiles(files []*os.File) error {
	var result error
	for i := range files {
		result = errors.Join(result, closeNamespaceFile(files, i))
	}
	return result
}

func monitorTunnel(parent context.Context, tunnel *network.Tunnel, cancel context.CancelCauseFunc) func() {
	if tunnel == nil {
		return func() {}
	}
	ctx, stop := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var failedSince time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := tunnel.Check(ctx); err != nil {
					if ctx.Err() != nil {
						return
					}
					if failedSince.IsZero() {
						failedSince = time.Now()
					} else if time.Since(failedSince) >= 30*time.Second {
						cancel(errors.New("WireGuard interface/route/resolver readiness failed for 30 seconds; workload stopped without plaintext fallback"))
						return
					}
				} else {
					failedSince = time.Time{}
				}
			}
		}
	}()
	return func() { stop(); <-done }
}

type payloadResult struct {
	started    bool
	code       int
	err        error
	cleanupErr error
	quiescent  bool
	signaled   bool
}

func (r payloadResult) exportable() bool {
	return r.started && r.code == 0 && r.err == nil && r.cleanupErr == nil && r.quiescent && !r.signaled
}

type bubblewrapStatus struct {
	ChildPID *int   `json:"child-pid,omitempty"`
	ExitCode *int   `json:"exit-code,omitempty"`
	Cgroup   uint64 `json:"cgroup-namespace,omitempty"`
	IPC      uint64 `json:"ipc-namespace,omitempty"`
	Mount    uint64 `json:"mnt-namespace,omitempty"`
	Network  uint64 `json:"net-namespace,omitempty"`
	PID      uint64 `json:"pid-namespace,omitempty"`
	UTS      uint64 `json:"uts-namespace,omitempty"`
}

type bubblewrapEvent struct {
	status bubblewrapStatus
	err    error
}

// The fixed bwrap monitor is the only writer. Bound the whole stream and reject
// duplicate, mixed, missing, reordered, or out-of-range status documents.
func readBubblewrapStatus(reader io.Reader) <-chan bubblewrapEvent {
	events := make(chan bubblewrapEvent, 4)
	go func() {
		defer close(events)
		decoder := json.NewDecoder(io.LimitReader(reader, 16<<10))
		for index := 0; ; index++ {
			var raw json.RawMessage
			err := decoder.Decode(&raw)
			if err != nil {
				events <- bubblewrapEvent{err: err}
				return
			}
			var status bubblewrapStatus
			if err := strictJSON(raw, &status); err != nil {
				events <- bubblewrapEvent{err: fmt.Errorf("invalid Bubblewrap status: %w", err)}
				return
			}
			valid := index == 0 && status.ChildPID != nil && *status.ChildPID > 1 && status.ExitCode == nil
			if index == 1 {
				valid = status.ExitCode != nil && *status.ExitCode >= 0 && *status.ExitCode <= 255 && status.ChildPID == nil && status.Cgroup == 0 && status.IPC == 0 && status.Mount == 0 && status.Network == 0 && status.PID == 0 && status.UTS == 0
			}
			if !valid {
				events <- bubblewrapEvent{err: errors.New("unexpected Bubblewrap launch/exit status sequence")}
				return
			}
			events <- bubblewrapEvent{status: status}
		}
	}()
	return events
}

type entryProofEvent struct {
	kind        byte
	credentials *unix.Ucred
	err         error
}

func readEntryProof(connection *net.UnixConn) <-chan entryProofEvent {
	events := make(chan entryProofEvent, 4)
	go func() {
		defer close(events)
		for i := 0; i < 3; i++ {
			kind, credentials, err := entrypoint.ReceiveProof(connection)
			events <- entryProofEvent{kind, credentials, err}
			if err != nil || kind == entrypoint.ProofFailed {
				return
			}
		}
		events <- entryProofEvent{err: errors.New("too many entrypoint proof packets")}
	}()
	return events
}

func runPayload(ctx context.Context, command *exec.Cmd, caller identity, events <-chan namespaceMessage, afterExec func() func()) (result payloadResult) {
	result.code, result.quiescent = InfrastructureFailure, true
	if err := ctx.Err(); err != nil {
		result.err = context.Cause(ctx)
		return result
	}
	// This dedicated worker has no concurrent child waiters once bwrap starts.
	// Its imports have already finished, and exports cannot start until ECHILD.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		result.err = fmt.Errorf("require dedicated descendant subreaper: %w", err)
		return result
	}
	cgroup, err := readProcFile("/proc/self/cgroup")
	if err != nil {
		result.err = err
		return result
	}
	proof, peer, err := socketPair()
	if err != nil {
		result.err = err
		return result
	}
	defer proof.Close()
	defer peer.Close()
	raw, err := proof.SyscallConn()
	if err != nil {
		result.err = err
		return result
	}
	var passcredErr error
	err = raw.Control(func(fd uintptr) { passcredErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) })
	if err := errors.Join(err, passcredErr); err != nil {
		result.err = err
		return result
	}
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		result.err = err
		return result
	}
	defer statusRead.Close()
	defer statusWrite.Close()
	if len(command.ExtraFiles) != 0 {
		result.err = errors.New("Bubblewrap descriptor whitelist must start empty")
		return result
	}
	// FD 3 is a new proof socket, never a service/control endpoint. FD 4 is
	// consumed and closed by bwrap itself before executing the fixed wrappers.
	command.ExtraFiles = []*os.File{peer, statusWrite}
	if err := unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		result.err = fmt.Errorf("seal the final workload descriptor whitelist: %w", err)
		return result
	}
	if err := ctx.Err(); err != nil {
		result.err = context.Cause(ctx)
		return result
	}
	if err := command.Start(); err != nil {
		result.err = fmt.Errorf("start fixed Bubblewrap isolation chain: %w", err)
		return result
	}
	result.quiescent = false
	_ = peer.Close()
	_ = statusWrite.Close()
	if afterExec != nil {
		stop := afterExec()
		defer stop()
	}
	statusEvents := readBubblewrapStatus(statusRead)
	proofEvents := readEntryProof(proof)
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	var init, payload *ownedProcess
	defer func() {
		if payload != nil {
			_ = payload.close()
		}
		if init != nil {
			_ = init.close()
		}
	}()
	var reportedCode *int
	var ready *unix.Ucred
	var accepted, proofEOF, proofFailed, stopping, monitorKilled bool
	var monitorCode int
	pendingSignals := make(map[unix.Signal]bool)
	launchTimer := time.NewTimer(setupTimeout)
	defer launchTimer.Stop()
	launchDeadline := launchTimer.C
	var stopTimer, readTimer *time.Timer
	var stopDeadline, readDeadline <-chan time.Time
	defer func() {
		if stopTimer != nil {
			stopTimer.Stop()
		}
		if readTimer != nil {
			readTimer.Stop()
		}
	}()
	stop := func(cause error) {
		result.err = errors.Join(result.err, cause)
		if stopping || waited == nil {
			return
		}
		stopping = true
		launchTimer.Stop()
		launchDeadline = nil
		if payload != nil && proofEOF {
			result.err = errors.Join(result.err, payload.signal(unix.SIGTERM))
			stopTimer = time.NewTimer(time.Second)
		} else {
			if init != nil {
				result.cleanupErr = errors.Join(result.cleanupErr, init.signal(unix.SIGKILL))
			}
			_ = command.Process.Kill()
			monitorKilled = true
			stopTimer = time.NewTimer(2 * time.Second)
		}
		stopDeadline = stopTimer.C
	}
	accept := func() {
		if init == nil || ready == nil || accepted || stopping || waited == nil {
			return
		}
		var err error
		payload, err = bindPayload(int(ready.Pid), init, caller, string(cgroup))
		if err != nil {
			stop(fmt.Errorf("verify kernel-authenticated payload ownership: %w", err))
			return
		}
		if err := entrypoint.AcceptProof(proof); err != nil {
			stop(fmt.Errorf("accept trusted payload proof: %w", err))
			return
		}
		accepted = true
	}
	cancelled := ctx.Done()
	for waited != nil || statusEvents != nil || proofEvents != nil {
		select {
		case <-cancelled:
			cancelled = nil
			stop(context.Cause(ctx))
		case <-launchDeadline:
			launchDeadline = nil
			stop(errors.New("trusted payload launch exceeded its setup deadline"))
		case <-stopDeadline:
			if monitorKilled {
				result.cleanupErr = errors.Join(result.cleanupErr, errors.New("Bubblewrap monitor could not be reaped; cgroup shutdown required and no export permitted"))
				return result
			}
			if init != nil {
				result.cleanupErr = errors.Join(result.cleanupErr, init.signal(unix.SIGKILL))
			}
			_ = command.Process.Kill()
			monitorKilled = true
			stopTimer.Reset(2 * time.Second)
		case <-readDeadline:
			result.err = errors.Join(result.err, errors.New("trusted launch status did not close after descendant cleanup"))
			return result
		case event, open := <-events:
			if !open {
				events = nil
				continue
			}
			if err := validateSupervisorMessage(event); err != nil || event.Kind != "signal" && event.Kind != "resize" {
				stop(errors.Join(errors.New("unexpected control while command is running"), err))
				continue
			}
			if event.Kind == "resize" {
				continue
			}
			result.signaled = true
			signal := unix.Signal(event.Signal)
			if payload == nil || !proofEOF {
				pendingSignals[signal] = true
			} else if err := payload.signal(signal); err != nil {
				stop(fmt.Errorf("signal the owned workload pidfd: %w", err))
			}
		case event, open := <-statusEvents:
			if !open {
				statusEvents = nil
				continue
			}
			if event.err != nil {
				statusEvents = nil
				if !errors.Is(event.err, io.EOF) {
					stop(event.err)
				}
				continue
			}
			if event.status.ChildPID != nil {
				if waited == nil {
					stop(errors.New("Bubblewrap monitor exited before namespace-init ownership was bound"))
					continue
				}
				init, err = bindNamespaceInit(*event.status.ChildPID, command.Process.Pid, string(cgroup))
				if err != nil {
					stop(fmt.Errorf("verify reported namespace init ownership: %w", err))
				} else {
					accept()
				}
			} else {
				reportedCode = event.status.ExitCode
				result.code = *reportedCode
			}
		case event, open := <-proofEvents:
			if !open {
				proofEvents = nil
				continue
			}
			if event.err != nil {
				proofEvents = nil
				if errors.Is(event.err, io.EOF) {
					proofEOF = true
					if accepted && !proofFailed {
						result.started = true
						launchTimer.Stop()
						launchDeadline = nil
						for signal := range pendingSignals {
							if err := payload.signal(signal); err != nil {
								stop(err)
							}
						}
					}
				} else {
					stop(event.err)
				}
				continue
			}
			if event.credentials.Uid != caller.UID || event.credentials.Gid != caller.GID || ready != nil && event.credentials.Pid != ready.Pid {
				stop(errors.New("launch proof kernel credentials do not match the authenticated workload"))
				continue
			}
			if event.kind == entrypoint.ProofFailed {
				proofFailed = true
				stop(errors.New("trusted credential/filesystem verification or workload exec failed"))
			} else if ready != nil {
				stop(errors.New("duplicate trusted launch proof"))
			} else {
				ready = event.credentials
				accept()
			}
		case waitErr := <-waited:
			// Cmd.Wait must finish BEFORE any Wait4(-1), or a global wait could
			// steal its monitor status. Monitor exit alone is not a barrier.
			waited = nil
			if stopTimer != nil {
				stopTimer.Stop()
				stopDeadline = nil
			}
			monitorCode, err = commandStatus(waitErr)
			result.err = errors.Join(result.err, err)
			barrierErr := drainOwnedDescendants(init, string(cgroup), 3*time.Second)
			result.quiescent = barrierErr == nil
			result.cleanupErr = errors.Join(result.cleanupErr, barrierErr)
			readTimer = time.NewTimer(time.Second)
			readDeadline = readTimer.C
		}
	}
	// A signal can be queued at the same instant as monitor exit. It must still
	// suppress exports even when a handler made the initial command exit zero.
	for {
		select {
		case event, open := <-events:
			if !open {
				events = nil
				continue
			}
			if event.Kind == "signal" {
				result.signaled = true
			} else if event.Kind != "resize" {
				result.err = errors.Join(result.err, errors.New("unexpected control after command exit"))
			}
		default:
			result.started = accepted && proofEOF && !proofFailed
			if reportedCode != nil {
				result.code = *reportedCode
			}
			if !result.started || reportedCode == nil || monitorCode != result.code {
				result.err = errors.Join(result.err, errors.New("workload start/exit was not established by both trusted entry proof and Bubblewrap status"))
			}
			if ctx.Err() != nil {
				result.err = errors.Join(result.err, context.Cause(ctx))
			}
			return result
		}
	}
}

type processIdentity struct {
	pid       int
	parent    int
	uid       [4]uint32
	gid       [4]uint32
	nspid     []int
	start     uint64
	namespace unix.Stat_t
	userns    unix.Stat_t
	cgroup    string
}

type ownedProcess struct {
	identity processIdentity
	pidfd    int
}

func (process *ownedProcess) signal(signal unix.Signal) error {
	err := unix.PidfdSendSignal(process.pidfd, signal, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func (process *ownedProcess) close() error { return unix.Close(process.pidfd) }

func sameNamespace(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

func readProcFile(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	if len(data) > 64<<10 {
		return nil, errors.New("kernel ownership evidence exceeds its bound")
	}
	return data, nil
}

func readProcessIdentity(pid int) (processIdentity, error) {
	identity := processIdentity{pid: pid}
	if pid <= 0 {
		return identity, errors.New("invalid process identity")
	}
	base := "/proc/" + strconv.Itoa(pid)
	status, err := readProcFile(base + "/status")
	if err != nil {
		return identity, err
	}
	fields := make(map[string][]string)
	for _, line := range strings.Split(string(status), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 0 {
			if _, exists := fields[parts[0]]; exists {
				return identity, errors.New("duplicate kernel process evidence")
			}
			fields[parts[0]] = parts[1:]
		}
	}
	if len(fields["PPid:"]) != 1 {
		return identity, errors.New("missing kernel parent identity")
	}
	identity.parent, err = strconv.Atoi(fields["PPid:"][0])
	if err != nil || identity.parent < 0 {
		return identity, errors.New("invalid kernel parent identity")
	}
	for name, values := range map[string]*[4]uint32{"Uid:": &identity.uid, "Gid:": &identity.gid} {
		if len(fields[name]) != len(values) {
			return identity, errors.New("missing kernel process credentials")
		}
		for i, text := range fields[name] {
			n, err := strconv.ParseUint(text, 10, 32)
			if err != nil {
				return identity, err
			}
			values[i] = uint32(n)
		}
	}
	for _, text := range fields["NSpid:"] {
		n, err := strconv.Atoi(text)
		if err != nil || n <= 0 {
			return identity, errors.New("invalid kernel namespace PID evidence")
		}
		identity.nspid = append(identity.nspid, n)
	}
	if len(identity.nspid) == 0 || identity.nspid[0] != pid {
		return identity, errors.New("missing kernel namespace PID evidence")
	}
	stat, err := readProcFile(base + "/stat")
	if err != nil {
		return identity, err
	}
	identity.start, err = processStart(string(stat), pid)
	if err != nil {
		return identity, err
	}
	if err := unix.Stat(base+"/ns/pid", &identity.namespace); err != nil {
		return identity, err
	}
	if err := unix.Stat(base+"/ns/user", &identity.userns); err != nil {
		return identity, err
	}
	cgroup, err := readProcFile(base + "/cgroup")
	identity.cgroup = string(cgroup)
	return identity, err
}

func processStart(stat string, pid int) (uint64, error) {
	opening, closing := strings.IndexByte(stat, '('), strings.LastIndex(stat, ") ")
	if opening <= 0 || closing < opening || strings.TrimSpace(stat[:opening]) != strconv.Itoa(pid) {
		return 0, errors.New("invalid kernel process stat identity")
	}
	fields := strings.Fields(stat[closing+2:])
	if len(fields) < 20 {
		return 0, errors.New("incomplete kernel process stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, errors.New("invalid kernel process start time")
	}
	return start, nil
}

// Validate before opening a pidfd, then revalidate against PID reuse and an
// intervening parent/credential/namespace change before granting signal authority.
func openOwnedProcess(pid int, validate func(processIdentity) error) (*ownedProcess, error) {
	before, err := readProcessIdentity(pid)
	if err != nil {
		return nil, err
	}
	if err := validate(before); err != nil {
		return nil, err
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("require owned process pidfd: %w", err)
	}
	after, err := readProcessIdentity(pid)
	if err == nil {
		err = validate(after)
	}
	if err != nil || before.start != after.start || !sameNamespace(before.namespace, after.namespace) || !sameNamespace(before.userns, after.userns) {
		return nil, errors.Join(errors.New("owned process identity changed while binding pidfd"), err, unix.Close(fd))
	}
	return &ownedProcess{identity: after, pidfd: fd}, nil
}

func bindNamespaceInit(pid, monitor int, cgroup string) (*ownedProcess, error) {
	var parentNS, userNS unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &parentNS); err != nil {
		return nil, err
	}
	if err := unix.Stat("/proc/self/ns/user", &userNS); err != nil {
		return nil, err
	}
	owned, err := openOwnedProcess(pid, func(process processIdentity) error {
		if process.pid == os.Getpid() || process.pid == monitor || process.parent != monitor && process.parent != os.Getpid() || process.cgroup != cgroup || process.uid != [4]uint32{} || process.gid != [4]uint32{} || len(process.nspid) < 2 || process.nspid[len(process.nspid)-1] != 1 || sameNamespace(process.namespace, parentNS) || !sameNamespace(process.userns, userNS) {
			return errors.New("reported PID is not this monitor's root namespace init in the exact service cgroup and a fresh PID namespace")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/proc/"+strconv.Itoa(pid)+"/ns/pid", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(err, owned.close())
	}
	parent, ioctlErr := unix.IoctlRetInt(fd, unix.NS_GET_PARENT)
	closeErr := unix.Close(fd)
	if ioctlErr != nil {
		return nil, errors.Join(errors.New("cannot establish the new PID namespace's direct parent"), ioctlErr, closeErr, owned.close())
	}
	unix.CloseOnExec(parent)
	var actualParent unix.Stat_t
	statErr := unix.Fstat(parent, &actualParent)
	closeErr = errors.Join(closeErr, unix.Close(parent))
	if statErr != nil || !sameNamespace(actualParent, parentNS) || closeErr != nil {
		return nil, errors.Join(errors.New("reported init is not in the directly owned new PID namespace"), statErr, closeErr, owned.close())
	}
	return owned, nil
}

func bindPayload(pid int, init *ownedProcess, caller identity, cgroup string) (*ownedProcess, error) {
	return openOwnedProcess(pid, func(process processIdentity) error {
		uid := [4]uint32{caller.UID, caller.UID, caller.UID, caller.UID}
		gid := [4]uint32{caller.GID, caller.GID, caller.GID, caller.GID}
		if caller.UID == 0 || caller.GID == 0 || process.parent != init.identity.pid || process.cgroup != cgroup || process.uid != uid || process.gid != gid || !sameNamespace(process.namespace, init.identity.namespace) || !sameNamespace(process.userns, init.identity.userns) || len(process.nspid) < 2 || process.nspid[len(process.nspid)-1] != 2 {
			return errors.New("proof PID is not the initial non-root payload under the owned namespace init")
		}
		var actual, expected unix.Stat_t
		if err := unix.Stat("/proc/"+strconv.Itoa(pid)+"/exe", &actual); err != nil {
			return err
		}
		if err := unix.Stat(toolkit.Root+entrypoint.Path, &expected); err != nil {
			return err
		}
		if actual.Dev != expected.Dev || actual.Ino != expected.Ino {
			return errors.New("proof did not originate in the immutable trusted entrypoint")
		}
		return nil
	})
}

// Call only after Cmd.Wait has reaped the monitor. Killing namespace PID 1
// initiates kernel teardown, but only ECHILD proves every adopted writer was
// actually reaped. No timeout path authorizes export or tmpfs detachment.
func drainOwnedDescendants(init *ownedProcess, cgroup string, timeout time.Duration) error {
	var result error
	if init != nil {
		result = init.signal(unix.SIGKILL)
	}
	deadline := time.Now().Add(timeout)
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			return result
		}
		if err != nil {
			return errors.Join(result, fmt.Errorf("reap adopted owned descendants: %w", err))
		}
		if pid > 0 {
			continue
		}
		if !time.Now().Before(deadline) {
			return errors.Join(result, errors.New("owned descendant reaping exceeded its bound before ECHILD; no export or tmpfs teardown is permitted"))
		}
		if err := killAdoptedChildren(cgroup); err != nil {
			return errors.Join(result, err)
		}
		timer := time.NewTimer(min(10*time.Millisecond, time.Until(deadline)))
		<-timer.C
	}
}

func killAdoptedChildren(cgroup string) error {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return err
	}
	seen := make(map[int]bool)
	for _, task := range tasks {
		data, err := readProcFile("/proc/self/task/" + task.Name() + "/children")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, text := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(text)
			if err != nil || pid <= 0 || len(seen) >= 100000 {
				return errors.New("invalid or unbounded adopted-child ownership list")
			}
			if seen[pid] {
				continue
			}
			seen[pid] = true
			child, err := openOwnedProcess(pid, func(process processIdentity) error {
				if process.parent != os.Getpid() || process.cgroup != cgroup {
					return errors.New("refuse to signal a process not adopted by this exact worker and cgroup")
				}
				return nil
			})
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
				continue
			}
			if err != nil {
				return err
			}
			if err := errors.Join(child.signal(unix.SIGKILL), child.close()); err != nil {
				return err
			}
		}
	}
	return nil
}

func reapBounded(waited <-chan error, command *exec.Cmd, grace time.Duration) error {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-waited:
		return nil
	case <-timer.C:
	}
	_ = command.Process.Kill()
	timer.Reset(2 * time.Second)
	select {
	case <-waited:
		return nil
	case <-timer.C:
		return errors.New("owned child could not be reaped; systemd cgroup shutdown is required and cleanup remains unverified")
	}
}

func commandStatus(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exited *exec.ExitError
	if !errors.As(err, &exited) {
		return InfrastructureFailure, fmt.Errorf("wait for command: %w", err)
	}
	return stateStatus(exited.ProcessState)
}

func stateStatus(state *os.ProcessState) (int, error) {
	if state == nil {
		return InfrastructureFailure, errors.New("command process state is unavailable")
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok {
		return InfrastructureFailure, errors.New("command returned an unsupported process status")
	}
	if status.Signaled() {
		return 128 + int(status.Signal()), nil
	}
	if status.Exited() {
		return status.ExitStatus(), nil
	}
	return InfrastructureFailure, errors.New("command did not reach a terminal process state")
}
