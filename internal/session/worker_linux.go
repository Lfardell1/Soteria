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
	"strings"
	"syscall"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/network"
	bus "github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type namespacePlan struct {
	Request wireRequest `json:"request"`
	Caller  identity    `json:"caller"`
}

type namespaceMessage struct {
	Version   int            `json:"version"`
	Kind      string         `json:"kind"`
	Plan      *namespacePlan `json:"plan,omitempty"`
	Workspace string         `json:"workspace,omitempty"`
	Link      string         `json:"link,omitempty"`
	Code      int            `json:"code,omitempty"`
	Text      string         `json:"text,omitempty"`
	Signal    int            `json:"signal,omitempty"`
	Cancelled bool           `json:"cancelled,omitempty"`
}

type incomingNamespace struct {
	message namespaceMessage
	files   []*os.File
	err     error
}

func readNamespace(ctx context.Context, connection *net.UnixConn) <-chan incomingNamespace {
	channel := make(chan incomingNamespace, 8)
	go func() {
		defer close(channel)
		for {
			var message namespaceMessage
			files, err := receivePacket(connection, &message, -1)
			select {
			case channel <- incomingNamespace{message, files, err}:
			case <-ctx.Done():
				_ = closeFiles(files)
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return channel
}

func serviceWorker(parent context.Context) (serviceCode int, resultErr error) {
	environment, err := currentService()
	if err != nil {
		return InfrastructureFailure, err
	}
	currentNetwork, currentErr := os.Stat("/proc/self/ns/net")
	hostNetwork, hostErr := os.Stat("/proc/1/ns/net")
	if currentErr != nil || hostErr != nil || !os.SameFile(currentNetwork, hostNetwork) {
		return InfrastructureFailure, errors.New("service MainPID must remain in the host network namespace")
	}
	caller, err := authenticatePeer(int(os.Stdin.Fd()))
	if err != nil {
		return InfrastructureFailure, err
	}
	connection, err := connectionFromFile(os.Stdin)
	if err != nil {
		return InfrastructureFailure, err
	}
	defer connection.Close()
	writer := &packetWriter{connection: connection}
	childCode := InfrastructureFailure
	defer func() {
		message := controlMessage{Version: protocolVersion, Kind: "result", Code: childCode}
		message.Cancelled = onlyCanceled(resultErr)
		if message.Cancelled {
			serviceCode, resultErr = 0, nil
		} else if resultErr != nil {
			message.Text = boundedDiagnostic(fmt.Errorf("child status %d; %w", childCode, resultErr))
			serviceCode = InfrastructureFailure
		}
		_ = connection.SetWriteDeadline(time.Now().Add(controlTimeout))
		if err := writer.send(message); err != nil {
			serviceCode, resultErr = InfrastructureFailure, errors.Join(resultErr, err)
		}
	}()
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	// Cover request receipt, D-Bus authentication, limits, verification, and
	// namespace preparation, not just the final namespace stage. D-Bus uses
	// this lifetime too, so a stuck setup exchange is interrupted on expiry.
	setupTimer := time.AfterFunc(setupTimeout, func() {
		cancel(errors.New("session setup exceeded its 120-second deadline"))
	})
	defer setupTimer.Stop()
	_ = connection.SetReadDeadline(time.Now().Add(setupTimeout))
	stopClose := context.AfterFunc(ctx, func() { _ = connection.SetReadDeadline(time.Now()) })
	defer stopClose()
	var initial controlMessage
	files, err := receivePacket(connection, &initial, -1)
	if err != nil {
		return InfrastructureFailure, fmt.Errorf("receive bounded service request: %w", err)
	}
	defer func() { _ = closeFiles(files) }()
	_ = connection.SetReadDeadline(time.Time{})
	if err := validateInitial(initial, files); err != nil {
		return InfrastructureFailure, err
	}
	directory, err := openRootDirectory(environment.Directory, true)
	if err != nil {
		return InfrastructureFailure, err
	}
	defer directory.Close()
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, err
	}
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return InfrastructureFailure, fmt.Errorf("lock exact service runtime directory: %w", err)
	}
	owner := ownerRecord{Version: 1, ID: environment.ID, Invocation: environment.Invocation, Caller: caller}
	if err := createRecord(directory, ownerFile, owner); err != nil {
		return InfrastructureFailure, fmt.Errorf("record authenticated session owner: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, context.Cause(ctx)
	}
	events := monitorCaller(ctx, connection, cancel)
	if err := writer.send(controlMessage{Version: protocolVersion, Kind: "accepted", ID: environment.ID}); err != nil {
		return InfrastructureFailure, err
	}
	if err := writer.send(controlMessage{Version: protocolVersion, Kind: "phase", Phase: "Validating"}); err != nil {
		return InfrastructureFailure, err
	}
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, context.Cause(ctx)
	}
	manager, err := connectSystemd(ctx)
	if err != nil {
		return InfrastructureFailure, err
	}
	defer manager.Close()
	if initial.Kind == "cleanup" {
		if err := cleanupOwned(ctx, manager, initial.Target, caller); err != nil {
			return InfrastructureFailure, err
		}
		childCode = 0
		return 0, nil
	}
	request := *initial.Request
	if err := validateIO(files, request, caller); err != nil {
		return InfrastructureFailure, err
	}
	memory, _ := config.ParseSize(request.Config.Resources.MemoryMax)
	warnings, err := configureLimits(ctx, manager, environment.ID, memory, request.Config.Resources.TasksMax)
	if err != nil {
		return InfrastructureFailure, err
	}
	if len(warnings) == 0 {
		if err := writer.send(controlMessage{Version: protocolVersion, Kind: "fact", Text: "anonymous service memory: memory.swap.max=0 verified (does not cover the caller process)"}); err != nil {
			return InfrastructureFailure, err
		}
	}
	for _, warning := range append(warnings, "LimitCORE=0 is a mitigation only: piped core collectors, hibernation, host snapshots, and caller-side buffers are unverified and outside the volatile-workspace guarantee") {
		if err := writer.send(controlMessage{Version: protocolVersion, Kind: "warning", Text: warning}); err != nil {
			return InfrastructureFailure, err
		}
	}
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, err
	}
	if err := runtimePrerequisites(true); err != nil {
		return InfrastructureFailure, err
	}
	childCode, resultErr = superviseNamespace(ctx, environment, caller, request, files, directory, writer, events, setupTimer)
	files = nil // superviseNamespace closes the parent's copies on every path.
	if resultErr != nil {
		return InfrastructureFailure, resultErr
	}
	return 0, nil
}

func validateInitial(message controlMessage, files []*os.File) error {
	if message.Version != protocolVersion || message.ID != "" || message.Phase != "" || message.Text != "" || message.Code != 0 || message.Signal != 0 || message.Cancelled {
		return errors.New("invalid initial service request")
	}
	switch message.Kind {
	case "run":
		if message.Request == nil || message.Target != "" {
			return errors.New("run requires policy, not a caller identity or target")
		}
		if err := message.Request.validate(); err != nil {
			return err
		}
		count := 3
		if message.Request.Import {
			count++
		}
		if message.Request.Export {
			count++
		}
		if len(files) != count {
			return errors.New("request descriptor count does not match explicit stdio/transfer streams")
		}
	case "cleanup":
		if message.Request != nil || !validSessionID(message.Target) || len(files) != 0 {
			return errors.New("cleanup requires only one exact session ID, no descriptors or run policy")
		}
	default:
		return errors.New("unknown initial service operation")
	}
	return nil
}

func validateIO(files []*os.File, request wireRequest, caller identity) error {
	var terminalDevice uint64
	for i, file := range files {
		var st unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &st); err != nil {
			return err
		}
		if i < 3 && request.Interactive {
			if st.Mode&unix.S_IFMT != unix.S_IFCHR || !term.IsTerminal(int(file.Fd())) || st.Uid != caller.UID || i > 0 && terminalDevice != st.Rdev {
				return errors.New("interactive stdio must be one caller-owned dedicated PTY")
			}
			terminalDevice = st.Rdev
		} else if st.Mode&unix.S_IFMT != unix.S_IFIFO {
			return errors.New("headless stdio and transfer descriptors must be pipes, not host directories/files/sockets")
		}
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		if err != nil {
			return err
		}
		readable := i == 0 || i == 3 && request.Import
		if readable && flags&unix.O_ACCMODE == unix.O_WRONLY || !readable && flags&unix.O_ACCMODE == unix.O_RDONLY {
			return errors.New("wrong stream descriptor access mode")
		}
	}
	return nil
}

func monitorCaller(ctx context.Context, connection *net.UnixConn, cancel context.CancelCauseFunc) <-chan controlMessage {
	events := make(chan controlMessage, 4)
	go func() {
		defer close(events)
		for {
			var message controlMessage
			_, err := receivePacket(connection, &message, 0)
			if err != nil {
				cancel(errors.Join(errors.New("caller control/lifeline disconnected"), err))
				return
			}
			if message.Version != protocolVersion || message.Request != nil || message.Target != "" || message.ID != "" || message.Phase != "" || message.Cancelled {
				cancel(errors.New("unexpected caller control fields"))
				return
			}
			switch message.Kind {
			case "cancel":
				cancel(context.Canceled)
				return
			case "signal":
				if message.Signal != int(syscall.SIGINT) && message.Signal != int(syscall.SIGQUIT) || message.Code != 0 || message.Text != "" {
					cancel(errors.New("invalid caller signal"))
					return
				}
			case "export-result":
				if message.Signal != 0 || message.Code != 0 && message.Code != InfrastructureFailure || len(message.Text) > 4096 {
					cancel(errors.New("invalid export acknowledgement"))
					return
				}
			default:
				cancel(errors.New("unexpected caller control message"))
				return
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

func superviseNamespace(ctx context.Context, environment serviceEnvironment, caller identity, request wireRequest, files []*os.File, directory *os.File, frontend *packetWriter, events <-chan controlMessage, setupTimer *time.Timer) (int, error) {
	defer func() { _ = closeFiles(files) }()
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, context.Cause(ctx)
	}
	connection, peer, err := socketPair()
	if err != nil {
		return InfrastructureFailure, err
	}
	defer connection.Close()
	defer peer.Close()
	writer := &packetWriter{connection: connection}
	command := namespaceCommand(environment, peer, files)
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, context.Cause(ctx)
	}
	if err := command.Start(); err != nil {
		return InfrastructureFailure, fmt.Errorf("fork private network/mount worker: %w", err)
	}
	_ = peer.Close()
	_ = closeFiles(files)
	files = nil
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	if err := writer.send(namespaceMessage{Version: protocolVersion, Kind: "init", Plan: &namespacePlan{request, caller}}); err != nil {
		_ = command.Process.Kill()
		return InfrastructureFailure, errors.Join(err, reapBounded(waited, command, time.Second))
	}
	if err := frontend.send(controlMessage{Version: protocolVersion, Kind: "phase", Phase: "Preparing"}); err != nil {
		_ = command.Process.Kill()
		return InfrastructureFailure, errors.Join(err, reapBounded(waited, command, time.Second))
	}
	readerCtx, stopReader := context.WithCancel(context.Background())
	defer stopReader()
	packets := readNamespace(readerCtx, connection)
	var owned *network.OwnedLink
	var resultErr error
	code := InfrastructureFailure
	var moved, running, exporting, acknowledged, reported, reaped, eof bool
	cancelled := ctx.Done()
	var killTimer *time.Timer
	var kill <-chan time.Time
	var abandonTimer *time.Timer
	var abandon <-chan time.Time
	defer func() {
		if killTimer != nil {
			killTimer.Stop()
		}
		if abandonTimer != nil {
			abandonTimer.Stop()
		}
	}()
waitLoop:
	for !reaped || !eof {
		select {
		case <-cancelled:
			cancelled = nil
			resultErr = errors.Join(resultErr, context.Cause(ctx))
			_ = writer.send(namespaceMessage{Version: protocolVersion, Kind: "cancel"})
			killTimer = time.NewTimer(stopTimeout / 2)
			kill = killTimer.C
		case <-kill:
			kill = nil
			_ = command.Process.Kill()
			abandonTimer = time.NewTimer(2 * time.Second)
			abandon = abandonTimer.C
			// Surviving workload descendants belong to this service cgroup.
			// Returning exits MainPID; systemd then kills the complete cgroup
			// before ExecStopPost, even if bwrap's parent-death mechanism failed.
		case <-abandon:
			resultErr = errors.Join(resultErr, errors.New("namespace worker could not be reaped within its shutdown bound; cleanup remains unverified"))
			break waitLoop
		case waitErr := <-waited:
			reaped, waited = true, nil
			if waitErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("namespace worker: %w", waitErr))
			}
		case event, open := <-events:
			if !open {
				events = nil
				continue
			}
			if event.Kind == "signal" {
				if running && ctx.Err() == nil {
					if err := writer.send(namespaceMessage{Version: protocolVersion, Kind: "signal", Signal: event.Signal}); err != nil {
						resultErr = errors.Join(resultErr, err)
						_ = command.Process.Kill()
					}
				}
			} else if event.Kind == "export-result" {
				if !exporting || acknowledged {
					resultErr = errors.Join(resultErr, errors.New("unexpected export acknowledgement"))
					_ = command.Process.Kill()
					continue
				}
				acknowledged = true
				if event.Code != 0 {
					resultErr = errors.Join(resultErr, errors.New("caller export failed; partial exports are not rolled back"))
				}
				if err := writer.send(namespaceMessage{Version: protocolVersion, Kind: "export-result", Code: event.Code}); err != nil {
					resultErr = errors.Join(resultErr, err)
				}
			}
		case packet, open := <-packets:
			if !open || packet.err != nil {
				eof, packets = true, nil
				if !reported {
					resultErr = errors.Join(resultErr, errors.New("namespace worker closed without a cleanup/result report"), packet.err)
				}
				continue
			}
			message := packet.message
			if message.Version != protocolVersion || message.Plan != nil || len(packet.files) != 0 && message.Kind != "namespace" {
				_ = closeFiles(packet.files)
				resultErr = errors.Join(resultErr, errors.New("invalid namespace control message"))
				_ = command.Process.Kill()
				continue
			}
			switch message.Kind {
			case "namespace":
				if moved || len(packet.files) != 1 || ctx.Err() != nil {
					_ = closeFiles(packet.files)
					if ctx.Err() != nil {
						resultErr = errors.Join(resultErr, context.Cause(ctx))
					} else {
						resultErr = errors.Join(resultErr, errors.New("unexpected namespace handoff"))
						_ = command.Process.Kill()
					}
					continue
				}
				moved = true
				err := recordWorkspace(directory, message.Workspace)
				linkName := ""
				if err == nil && request.Config.Network.Mode == "wireguard" {
					if err = ctx.Err(); err == nil {
						owned, err = network.CreateAndMove(environment.ID, int(packet.files[0].Fd()), environment.Directory)
						if owned != nil {
							linkName = owned.Name
						}
					}
				}
				err = errors.Join(err, closeFiles(packet.files))
				if err == nil {
					err = ctx.Err()
				}
				if err == nil {
					err = writer.send(namespaceMessage{Version: protocolVersion, Kind: "network", Link: linkName})
				}
				if err != nil {
					resultErr = errors.Join(resultErr, err)
					_ = writer.send(namespaceMessage{Version: protocolVersion, Kind: "cancel"})
					if !onlyCanceled(err) {
						_ = command.Process.Kill()
					}
				}
			case "ready":
				if !moved || running || ctx.Err() != nil {
					if ctx.Err() != nil {
						resultErr = errors.Join(resultErr, context.Cause(ctx))
					} else {
						resultErr = errors.Join(resultErr, errors.New("unexpected workload readiness"))
						_ = command.Process.Kill()
					}
					continue
				}
				if !setupTimer.Stop() {
					resultErr = errors.Join(resultErr, errors.New("setup authorization expired before workload readiness"))
					_ = writer.send(namespaceMessage{Version: protocolVersion, Kind: "cancel"})
					continue
				}
				if err := frontend.send(controlMessage{Version: protocolVersion, Kind: "phase", Phase: "NetworkReady"}); err == nil {
					err = frontend.send(controlMessage{Version: protocolVersion, Kind: "phase", Phase: "Running"})
					if err == nil {
						err = writer.send(namespaceMessage{Version: protocolVersion, Kind: "run"})
					}
					if err == nil {
						running = true
					} else {
						resultErr = errors.Join(resultErr, err)
						_ = command.Process.Kill()
					}
				} else {
					resultErr = errors.Join(resultErr, err)
					_ = command.Process.Kill()
				}
			case "exporting":
				if !running || exporting || !request.Export || ctx.Err() != nil {
					resultErr = errors.Join(resultErr, errors.New("unexpected or cancelled export phase"))
					_ = command.Process.Kill()
					continue
				}
				exporting = true
				if err := frontend.send(controlMessage{Version: protocolVersion, Kind: "phase", Phase: "Exporting"}); err != nil {
					resultErr = errors.Join(resultErr, err)
					_ = command.Process.Kill()
				}
			case "warning", "fact":
				if err := frontend.send(controlMessage{Version: protocolVersion, Kind: message.Kind, Text: message.Text}); err != nil {
					resultErr = errors.Join(resultErr, err)
					_ = command.Process.Kill()
				}
			case "result":
				if reported || message.Code < 0 || message.Code > 255 {
					resultErr = errors.Join(resultErr, errors.New("invalid namespace result"))
				} else {
					reported, code = true, message.Code
					if message.Cancelled {
						resultErr = errors.Join(resultErr, context.Canceled)
					} else if message.Text != "" {
						resultErr = errors.Join(resultErr, errors.New(message.Text))
					}
				}
			default:
				resultErr = errors.Join(resultErr, errors.New("unexpected namespace message"))
				_ = command.Process.Kill()
			}
		}
	}
	if exporting && !acknowledged {
		resultErr = errors.Join(resultErr, errors.New("export receiver completion was not acknowledged"))
	}
	if owned != nil {
		resultErr = errors.Join(resultErr, owned.Cleanup())
	}
	if err := frontend.send(controlMessage{Version: protocolVersion, Kind: "phase", Phase: "Stopping"}); err != nil {
		resultErr = errors.Join(resultErr, err)
	}
	if ctx.Err() != nil {
		resultErr = errors.Join(resultErr, context.Cause(ctx))
	}
	return code, resultErr
}

func namespaceCommand(environment serviceEnvironment, peer *os.File, files []*os.File) *exec.Cmd {
	command := exec.Command(installedExecutable, "__namespace")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "SOTERIA_SESSION_ID=" + environment.ID, "INVOCATION_ID=" + environment.Invocation, "RUNTIME_DIRECTORY=" + environment.Directory}
	command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
	command.ExtraFiles = append([]*os.File{peer}, files...)
	// Clone before the new Go runtime starts. MainPID remains in the host netns
	// and never calls setns/unshare from a live multithreaded Go process.
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWNS, Setsid: true}
	return command
}

func serviceCleanup(ctx context.Context) (resultErr error) {
	environment, err := currentService()
	if err != nil {
		return err
	}
	// ExecStopPost can use the private inherited stdin endpoint for a bounded
	// diagnostic, but the starter also inspects its actual exit status via D-Bus.
	defer func() {
		if connection, err := connectionFromFile(os.Stdin); err == nil {
			defer connection.Close()
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			message := controlMessage{Version: protocolVersion, Kind: "cleanup-result"}
			if resultErr != nil {
				message.Code, message.Text = InfrastructureFailure, boundedDiagnostic(resultErr)
			}
			_ = (&packetWriter{connection: connection}).send(message)
		}
	}()
	directory, err := openRootDirectory(environment.Directory, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("cleanup refused: session runtime remains locked by a live process")
	}
	var owner *ownerRecord
	record, err := readOwner(directory, environment.ID)
	if err == nil {
		if record.Invocation != environment.Invocation {
			return errors.New("cleanup invocation does not match this exact owned runtime")
		}
		owner = &record
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := network.CleanupResidual(environment.ID, environment.Directory); err != nil {
		return err
	}
	return removeRuntime(directory, environment.ID, owner)
}

func cleanupOwned(ctx context.Context, manager serviceManager, id string, caller identity) error {
	if !validSessionID(id) {
		return errors.New("invalid cleanup identity")
	}
	directory, err := openRootDirectory(runtimePath(id), true)
	if err != nil {
		return fmt.Errorf("refuse cleanup without an accessible root-owned runtime record: %w", err)
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("refuse cleanup of active or locked session")
	}
	owner, err := readOwner(directory, id)
	if err != nil {
		return fmt.Errorf("refuse cleanup without positive authenticated ownership: %w", err)
	}
	if owner.Caller != caller {
		return errors.New("refuse cleanup of a session owned by another authenticated caller")
	}
	callCtx, cancel := context.WithTimeout(ctx, controlTimeout)
	states, err := manager.GetAllPropertiesContext(callCtx, unitName(id))
	cancel()
	if err != nil {
		// Missing units are not proof of inactivity by themselves. Only the
		// explicit D-Bus no-such-unit error plus an absent/empty fixed cgroup is.
		if !isNoSuchUnit(err) {
			return fmt.Errorf("refuse cleanup: cannot establish unit inactivity: %w", err)
		}
	} else {
		if err := requireInactiveInvocation(states, owner.Invocation); err != nil {
			return err
		}
	}
	if err := requireEmptyCgroup(id); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := network.CleanupResidual(id, runtimePath(id)); err != nil {
		return err
	}
	return removeRuntime(directory, id, &owner)
}

func requireInactiveInvocation(states map[string]any, invocationID string) error {
	job, jobOK := states["Job"].([]any)
	if !jobOK || len(job) != 2 || job[0] != uint32(0) || job[1] != bus.ObjectPath("/") {
		return errors.New("refuse cleanup while a unit job is queued or unverifiable")
	}
	active, _ := states["ActiveState"].(string)
	sub, _ := states["SubState"].(string)
	main, mainOK := states["MainPID"].(uint32)
	control, controlOK := states["ControlPID"].(uint32)
	if !mainOK || !controlOK || main != 0 || control != 0 || !((active == "inactive" && sub == "dead") || (active == "failed" && sub == "failed")) {
		return errors.New("refuse cleanup of an active, stopping, or unverifiable session")
	}
	if invocation, ok := states["InvocationID"].([]byte); !ok || fmt.Sprintf("%x", invocation) != invocationID {
		return errors.New("refuse cleanup of a unit with different invocation ownership")
	}
	return nil
}

func requireEmptyCgroup(id string) error {
	data, err := os.ReadFile("/sys/fs/cgroup" + cgroupPath(id) + "/cgroup.events")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refuse cleanup without an empty service cgroup: %w", err)
	}
	for _, text := range strings.Split(string(data), "\n") {
		line := strings.Fields(text)
		if len(line) == 2 && line[0] == "populated" && line[1] == "0" {
			return nil
		}
	}
	return errors.New("refuse cleanup: service cgroup is populated or unverifiable")
}

func isNoSuchUnit(err error) bool {
	var failure bus.Error
	if errors.As(err, &failure) {
		return failure.Name == "org.freedesktop.systemd1.NoSuchUnit" || failure.Name == "org.freedesktop.DBus.Error.UnknownObject"
	}
	var pointer *bus.Error
	return errors.As(err, &pointer) && pointer != nil && (pointer.Name == "org.freedesktop.systemd1.NoSuchUnit" || pointer.Name == "org.freedesktop.DBus.Error.UnknownObject")
}
