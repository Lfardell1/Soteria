//go:build linux && amd64

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	systemd "github.com/coreos/go-systemd/v22/dbus"
	bus "github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// This interface is precisely the systemd D-Bus boundary, not a replacement
// session implementation. Unit tests inspect real properties and final states.
type serviceManager interface {
	StartTransientUnitContext(context.Context, string, string, []systemd.Property, chan<- string) (int, error)
	StopUnitContext(context.Context, string, string, chan<- string) (int, error)
	GetAllPropertiesContext(context.Context, string) (map[string]any, error)
	SetUnitPropertiesContext(context.Context, string, bool, ...systemd.Property) error
}

func connectSystemd(ctx context.Context) (*systemd.Conn, error) {
	// No DBUS_* environment lookup, remote transports, alternate user bus, or
	// shell-based systemd-run fallback is accepted.
	lifetime, stopLifetime := context.WithCancel(ctx)
	deadline := time.AfterFunc(controlTimeout, stopLifetime)
	manager, err := systemd.NewConnection(func() (*bus.Conn, error) {
		connection, err := bus.Dial("unix:path=/run/dbus/system_bus_socket", bus.WithContext(lifetime))
		if err != nil {
			return nil, fmt.Errorf("system bus unavailable: %w", err)
		}
		if err := connection.Auth([]bus.Auth{bus.AuthExternal("0")}); err != nil {
			_ = connection.Close()
			return nil, err
		}
		if !connection.SupportsUnixFDs() {
			_ = connection.Close()
			return nil, errors.New("system D-Bus UNIX_FD passing is required; no unsafe fallback")
		}
		if err := connection.Hello(); err != nil {
			_ = connection.Close()
			return nil, err
		}
		return connection, nil
	})
	if !deadline.Stop() {
		if manager != nil {
			manager.Close()
		}
		stopLifetime()
		return nil, errors.New("system D-Bus authentication/initialization exceeded its five-second deadline")
	}
	if err != nil {
		stopLifetime()
		return nil, err
	}
	return manager, nil
}

type execSpec struct {
	Path          string
	Arguments     []string
	IgnoreFailure bool
}

func property(name string, value any) systemd.Property {
	return systemd.Property{Name: name, Value: bus.MakeVariant(value)}
}

func serviceProperties(id string, input *os.File) []systemd.Property {
	return []systemd.Property{
		property("Description", "Soteria experimental disposable session"),
		property("Type", "exec"),
		property("ExitType", "main"),
		property("Restart", "no"),
		property("RemainAfterExit", false),
		property("KillMode", "control-group"),
		property("SendSIGKILL", true),
		property("OOMPolicy", "kill"),
		property("TimeoutStartUSec", uint64(setupTimeout/time.Microsecond)),
		property("TimeoutStopUSec", uint64(stopTimeout/time.Microsecond)),
		property("PrivateMounts", true),
		property("NoNewPrivileges", true),
		property("Delegate", false),
		property("Slice", "system.slice"),
		property("MemoryAccounting", true),
		property("TasksAccounting", true),
		property("MemoryMax", uint64(1<<30)),
		property("TasksMax", uint64(256)),
		property("LimitCORE", uint64(0)),
		property("LimitCORESoft", uint64(0)),
		property("UMask", uint32(0o077)),
		property("RuntimeDirectory", []string{"soteria-" + id}),
		property("RuntimeDirectoryMode", uint32(0o700)),
		// Preserve failed cleanup evidence/authority. ExecStopPost itself removes
		// only recorded empty directories on success, never recursive user trees.
		property("RuntimeDirectoryPreserve", "yes"),
		property("WorkingDirectory", "/"),
		property("Environment", []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "SOTERIA_SESSION_ID=" + id}),
		property("StandardInputFileDescriptor", bus.UnixFD(input.Fd())),
		property("StandardOutput", "null"),
		property("StandardError", "null"),
		property("ExecStart", []execSpec{{installedExecutable, []string{installedExecutable, "__worker"}, false}}),
		property("ExecStopPost", []execSpec{{installedExecutable, []string{installedExecutable, "__cleanup"}, false}}),
		// Pin even a very short-lived transient unit on this system-bus
		// connection until the starter has inspected ExecStopPost and Result.
		property("AddRef", true),
		property("CollectMode", "inactive-or-failed"),
	}
}

func startService(ctx context.Context) (int, error) {
	if _, err := authenticatePeer(int(os.Stdin.Fd())); err != nil {
		return InfrastructureFailure, err
	}
	if err := runtimePrerequisites(false); err != nil {
		return InfrastructureFailure, err
	}
	connection, err := connectionFromFile(os.Stdin)
	if err != nil {
		return InfrastructureFailure, err
	}
	defer connection.Close()
	writer := &packetWriter{connection: connection}
	managerContext, stopManager := context.WithCancel(context.Background())
	defer stopManager()
	manager, err := connectSystemd(managerContext)
	if err != nil {
		return InfrastructureFailure, err
	}
	defer manager.Close()
	id, err := randomID()
	if err != nil {
		return InfrastructureFailure, err
	}
	if err := ctx.Err(); err != nil {
		return InfrastructureFailure, err
	}
	startCtx, cancel := context.WithTimeout(ctx, controlTimeout)
	_, err = manager.StartTransientUnitContext(startCtx, unitName(id), "fail", serviceProperties(id, os.Stdin), nil)
	cancel()
	if err != nil {
		// A lost D-Bus reply is ambiguous. Stop this exact generated unit; never
		// retry creation under another name or fall back to an unsupervised child.
		stopErr := stopService(manager, id)
		verifyCtx, stopVerify := context.WithTimeout(context.Background(), 2*stopTimeout+controlTimeout)
		cleanupErr := waitService(verifyCtx, manager, id)
		stopVerify()
		failure := errors.Join(fmt.Errorf("start transient service: %w", err), stopErr, cleanupErr)
		_ = connection.SetWriteDeadline(time.Now().Add(controlTimeout))
		_ = writer.send(controlMessage{Version: protocolVersion, Kind: "service", ID: id, Code: InfrastructureFailure, Text: boundedDiagnostic(failure)})
		return InfrastructureFailure, failure
	}
	_ = writer.send(controlMessage{Version: protocolVersion, Kind: "started", ID: id})
	// The starter never competes with the worker for request reads. Polling HUP
	// observes the CLI lifeline independently, including while worker setup hangs.
	lifeline, stopLifeline := context.WithCancel(context.Background())
	defer stopLifeline()
	disconnected := make(chan struct{})
	go watchDisconnect(lifeline, connection, disconnected)
	stateCtx, stopState := context.WithCancel(context.Background())
	defer stopState()
	final := make(chan error, 1)
	go func() { final <- waitService(stateCtx, manager, id) }()
	select {
	case err = <-final:
	case <-ctx.Done():
		err = errors.Join(ctx.Err(), stopService(manager, id))
		err = errors.Join(err, awaitStopped(final))
	case <-disconnected:
		err = errors.Join(errors.New("caller lifeline disconnected"), stopService(manager, id))
		err = errors.Join(err, awaitStopped(final))
	}
	message := controlMessage{Version: protocolVersion, Kind: "service", ID: id}
	if err != nil {
		message.Code, message.Text = InfrastructureFailure, boundedDiagnostic(err)
	}
	_ = connection.SetWriteDeadline(time.Now().Add(controlTimeout))
	sendErr := writer.send(message)
	if err != nil || sendErr != nil {
		return InfrastructureFailure, errors.Join(err, sendErr)
	}
	return 0, nil
}

func awaitStopped(final <-chan error) error {
	timer := time.NewTimer(2*stopTimeout + controlTimeout)
	defer timer.Stop()
	select {
	case err := <-final:
		return err
	case <-timer.C:
		return errors.New("systemd did not confirm final service/ExecStopPost state before shutdown deadline")
	}
}

func stopService(manager serviceManager, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	_, err := manager.StopUnitContext(ctx, unitName(id), "replace", nil)
	return err
}

func watchDisconnect(ctx context.Context, connection *net.UnixConn, disconnected chan<- struct{}) {
	raw, err := connection.SyscallConn()
	if err != nil {
		close(disconnected)
		return
	}
	for ctx.Err() == nil {
		closed := false
		err := raw.Control(func(fd uintptr) {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLHUP | unix.POLLRDHUP}}
			_, pollErr := unix.Poll(poll, 100)
			closed = pollErr != nil && !errors.Is(pollErr, unix.EINTR) || poll[0].Revents&(unix.POLLHUP|unix.POLLRDHUP|unix.POLLERR|unix.POLLNVAL) != 0
		})
		if err != nil || closed {
			close(disconnected)
			return
		}
	}
}

func waitService(ctx context.Context, manager serviceManager, id string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		callCtx, cancel := context.WithTimeout(ctx, controlTimeout)
		properties, err := manager.GetAllPropertiesContext(callCtx, unitName(id))
		cancel()
		if err != nil {
			return fmt.Errorf("cannot verify final systemd cleanup state: %w", err)
		}
		done, stateErr := finalServiceState(properties)
		if done {
			if stateErr != nil {
				return stateErr
			}
			return requireEmptyCgroup(id)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type execStatus struct {
	Path           string
	Arguments      []string
	IgnoreFailure  bool
	Start          uint64
	StartMonotonic uint64
	Exit           uint64
	ExitMonotonic  uint64
	PID            uint32
	Code           int32
	Status         int32
}

func finalServiceState(properties map[string]any) (bool, error) {
	job, ok := properties["Job"].([]any)
	if !ok || len(job) != 2 {
		return true, errors.New("cannot verify the service's pending job state")
	}
	jobID, ok := job[0].(uint32)
	if !ok {
		return true, errors.New("invalid systemd job state")
	}
	if jobID != 0 {
		return false, nil
	}
	if job[1] != bus.ObjectPath("/") {
		return true, errors.New("cannot establish absence of a pending systemd job")
	}
	active, activeOK := properties["ActiveState"].(string)
	sub, subOK := properties["SubState"].(string)
	if !activeOK || !subOK {
		return true, errors.New("cannot verify the service's active/sub state")
	}
	if (active != "inactive" || sub != "dead") && (active != "failed" || sub != "failed") {
		return false, nil
	}
	controlPID, ok := properties["ControlPID"].(uint32)
	if !ok || controlPID != 0 {
		return false, nil
	}
	var commands []execStatus
	if err := bus.Store([]any{properties["ExecStopPost"]}, &commands); err != nil || len(commands) != 1 {
		return true, errors.New("cannot verify execution of the fixed ExecStopPost cleanup helper")
	}
	cleanup := commands[0]
	if cleanup.Path != installedExecutable || len(cleanup.Arguments) != 2 || cleanup.Arguments[0] != installedExecutable || cleanup.Arguments[1] != "__cleanup" || cleanup.IgnoreFailure || cleanup.Exit == 0 || cleanup.Code != 1 || cleanup.Status != 0 {
		return true, errors.New("ExecStopPost cleanup failed or its successful completion could not be established")
	}
	result, _ := properties["Result"].(string)
	code, codeOK := properties["ExecMainCode"].(int32)
	status, statusOK := properties["ExecMainStatus"].(int32)
	if active != "inactive" || result != "success" || !codeOK || !statusOK || code != 1 || status != 0 {
		return true, fmt.Errorf("systemd session infrastructure failed (result=%s, main code=%d status=%d)", result, code, status)
	}
	return true, nil
}

func configureLimits(ctx context.Context, manager serviceManager, id string, memory, tasks uint64) ([]string, error) {
	return applyLimits(ctx, manager, id, memory, tasks, readCgroupNumber)
}

func applyLimits(ctx context.Context, manager serviceManager, id string, memory, tasks uint64, readNumber func(string) (uint64, error)) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, controlTimeout)
	err := manager.SetUnitPropertiesContext(callCtx, unitName(id), true, property("MemoryMax", memory), property("TasksMax", tasks))
	cancel()
	if err != nil {
		return nil, fmt.Errorf("required memory/task containment unavailable: %w", err)
	}
	root := "/sys/fs/cgroup" + cgroupPath(id)
	effectiveMemory, memoryErr := readNumber(root + "/memory.max")
	effectiveTasks, tasksErr := readNumber(root + "/pids.max")
	if memoryErr != nil || tasksErr != nil || effectiveMemory == 0 || effectiveMemory > memory || effectiveTasks != tasks {
		return nil, errors.Join(errors.New("required cgroup memory.max/pids.max were not applied; refusing uncontained startup"), memoryErr, tasksErr)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	callCtx, cancel = context.WithTimeout(ctx, controlTimeout)
	swapErr := manager.SetUnitPropertiesContext(callCtx, unitName(id), true, property("MemorySwapMax", uint64(0)))
	cancel()
	swap, verifyErr := readNumber(root + "/memory.swap.max")
	if swapErr != nil || verifyErr != nil || swap != 0 {
		return []string{"MemorySwapMax=0 is unavailable or unverified; anonymous service memory may be swapped to host storage"}, nil
	}
	return nil, nil
}

func boundedDiagnostic(err error) string {
	if err == nil {
		return ""
	}
	text := strings.Map(func(c rune) rune {
		if c < 0x20 && c != '\n' && c != '\t' || c == 0x7f {
			return '?'
		}
		return c
	}, err.Error())
	if len(text) > 4096 {
		text = text[:4096] + " (diagnostic truncated)"
	}
	return text
}
