//go:build linux && amd64

package session

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	systemd "github.com/coreos/go-systemd/v22/dbus"
	bus "github.com/godbus/dbus/v5"
)

const testID = "0123456789abcdef0123456789abcdef"

func TestUnitUsesOnlyFixedArgvAndPrivateFD(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	properties := make(map[string]bus.Variant)
	for _, item := range serviceProperties(testID, read) {
		properties[item.Name] = item.Value
	}
	for name, expected := range map[string]any{
		"Type": "exec", "ExitType": "main", "Restart": "no", "RemainAfterExit": false,
		"KillMode": "control-group", "SendSIGKILL": true, "OOMPolicy": "kill", "PrivateMounts": true,
		"MemoryMax": uint64(1 << 30), "TasksMax": uint64(256), "Delegate": false,
		"StandardOutput": "null", "StandardError": "null", "LimitCORE": uint64(0), "AddRef": true,
		"CollectMode":      "inactive-or-failed",
		"RuntimeDirectory": []string{"soteria-" + testID}, "RuntimeDirectoryMode": uint32(0o700),
	} {
		if !reflect.DeepEqual(properties[name].Value(), expected) {
			t.Errorf("property %s=%v, need %v", name, properties[name], expected)
		}
	}
	if properties["StandardInputFileDescriptor"].Signature().String() != "h" {
		t.Fatal("stdin handoff is not D-Bus UNIX_FD")
	}
	if _, exists := properties["PrivateNetwork"]; exists {
		t.Fatal("host supervisor was put in a private network before WireGuard birth")
	}
	for propertyName, argument := range map[string]string{"ExecStart": "__worker", "ExecStopPost": "__cleanup"} {
		commands, ok := properties[propertyName].Value().([]execSpec)
		if !ok || len(commands) != 1 || commands[0].Path != installedExecutable || commands[0].IgnoreFailure || !reflect.DeepEqual(commands[0].Arguments, []string{installedExecutable, argument}) {
			t.Fatalf("non-fixed or failure-ignoring root command: %s=%v", propertyName, commands)
		}
	}
	for _, value := range properties["Environment"].Value().([]string) {
		if strings.Contains(value, "SUDO_UID") || strings.Contains(value, "HOME=") || strings.Contains(value, "DBUS_") {
			t.Fatalf("host authority/environment inherited: %q", value)
		}
	}
}

func successfulServiceState() map[string]any {
	return map[string]any{
		"ActiveState": "inactive", "SubState": "dead", "ControlPID": uint32(0),
		"Result": "success", "ExecMainCode": int32(1), "ExecMainStatus": int32(0),
		"Job":          []any{uint32(0), bus.ObjectPath("/")},
		"ExecStopPost": []execStatus{{Path: installedExecutable, Arguments: []string{installedExecutable, "__cleanup"}, Start: 1, Exit: 2, PID: 10, Code: 1, Status: 0}},
	}
}

func TestFinalStateWaitsForExecStopPost(t *testing.T) {
	state := successfulServiceState()
	state["ActiveState"], state["SubState"], state["ControlPID"] = "deactivating", "stop-post", uint32(10)
	if done, _ := finalServiceState(state); done {
		t.Fatal("returned before ExecStopPost completed")
	}
	state = successfulServiceState()
	state["Job"] = []any{uint32(7), bus.ObjectPath("/job/7")}
	if done, _ := finalServiceState(state); done {
		t.Fatal("returned before queued job completed")
	}
	state = successfulServiceState()
	if done, err := finalServiceState(state); !done || err != nil {
		t.Fatalf("successful cleanup not accepted: done=%v err=%v", done, err)
	}
	state["ExecStopPost"] = []execStatus{{Path: installedExecutable, Arguments: []string{installedExecutable, "__cleanup"}, Exit: 2, Code: 1, Status: 125}}
	if done, err := finalServiceState(state); !done || err == nil || !strings.Contains(err.Error(), "cleanup") {
		t.Fatalf("cleanup error was hidden: done=%v err=%v", done, err)
	}
	state = successfulServiceState()
	state["ExecStopPost"] = []execStatus{}
	if _, err := finalServiceState(state); err == nil {
		t.Fatal("missing cleanup execution treated as success")
	}
	state = successfulServiceState()
	state["Result"] = "oom-kill"
	if _, err := finalServiceState(state); err == nil {
		t.Fatal("OOM treated as a child exit success")
	}
}

type testManager struct {
	setCalls int
	set      func([]systemd.Property) error
}

func (*testManager) StartTransientUnitContext(context.Context, string, string, []systemd.Property, chan<- string) (int, error) {
	return 0, errors.New("not expected")
}
func (*testManager) StopUnitContext(context.Context, string, string, chan<- string) (int, error) {
	return 0, errors.New("not expected")
}
func (*testManager) GetAllPropertiesContext(context.Context, string) (map[string]any, error) {
	return nil, errors.New("not expected")
}
func (manager *testManager) SetUnitPropertiesContext(_ context.Context, _ string, _ bool, properties ...systemd.Property) error {
	manager.setCalls++
	if manager.set != nil {
		return manager.set(properties)
	}
	return errors.New("not expected")
}

func TestCanceledSetupCannotAcquireMoreResourceControls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager := new(testManager)
	if _, err := configureLimits(ctx, manager, testID, 1<<30, 256); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if manager.setCalls != 0 {
		t.Fatal("canceled setup changed service resources")
	}
}

func TestNoSuchUnitRequiresStructuredBusError(t *testing.T) {
	if isNoSuchUnit(errors.New("org.freedesktop.systemd1.NoSuchUnit")) {
		t.Fatal("unstructured text error accepted as inactivity authority")
	}
	if !isNoSuchUnit(bus.Error{Name: "org.freedesktop.systemd1.NoSuchUnit"}) {
		t.Fatal("structured no-such-unit error not recognized")
	}
	if !isNoSuchUnit(&bus.Error{Name: "org.freedesktop.DBus.Error.UnknownObject"}) {
		t.Fatal("structured collected-unit error pointer not recognized")
	}
}

func TestResourceLimitsFailClosedButSwapIsReportedSeparately(t *testing.T) {
	manager := new(testManager)
	if _, err := applyLimits(context.Background(), manager, testID, 1<<30, 256, func(string) (uint64, error) {
		t.Fatal("read cgroup after required systemd controls failed")
		return 0, nil
	}); err == nil || manager.setCalls != 1 {
		t.Fatalf("required resource containment silently fell back: calls=%d err=%v", manager.setCalls, err)
	}
	manager = new(testManager)
	manager.set = func(properties []systemd.Property) error {
		if manager.setCalls == 1 {
			if len(properties) != 2 || properties[0].Name != "MemoryMax" || properties[1].Name != "TasksMax" {
				t.Fatalf("resource limits not established first: %v", properties)
			}
			return nil
		}
		if len(properties) != 1 || properties[0].Name != "MemorySwapMax" || properties[0].Value.Value() != uint64(0) {
			t.Fatalf("swap suppression not attempted separately: %v", properties)
		}
		return errors.New("swap control unsupported")
	}
	read := func(name string) (uint64, error) {
		switch name {
		case "/sys/fs/cgroup" + cgroupPath(testID) + "/memory.max":
			return 1 << 30, nil
		case "/sys/fs/cgroup" + cgroupPath(testID) + "/pids.max":
			return 256, nil
		default:
			return 0, os.ErrNotExist
		}
	}
	warnings, err := applyLimits(context.Background(), manager, testID, 1<<30, 256, read)
	if err != nil || len(warnings) != 1 || manager.setCalls != 2 || !strings.Contains(warnings[0], "swapped") {
		t.Fatalf("swap uncertainty was hidden or blocked required controls incorrectly: %v %v", warnings, err)
	}
	manager = &testManager{set: func([]systemd.Property) error { return nil }}
	if _, err := applyLimits(context.Background(), manager, testID, 1<<30, 256, func(string) (uint64, error) { return 0, os.ErrNotExist }); err == nil || manager.setCalls != 1 {
		t.Fatal("missing actual cgroup controls accepted or startup continued")
	}
}

func TestCancellationNeverHidesCleanupError(t *testing.T) {
	if !onlyCanceled(errors.Join(context.Canceled, context.Canceled)) {
		t.Fatal("typed cancellation was lost")
	}
	if onlyCanceled(errors.Join(context.Canceled, errors.New("unmount failed"))) {
		t.Fatal("cleanup failure was hidden behind cancellation")
	}
	if onlyCanceled(errors.New("context canceled")) {
		t.Fatal("untrusted diagnostic text became typed cancellation")
	}
}
