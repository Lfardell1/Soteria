//go:build linux && amd64

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/entrypoint"
	"github.com/Lfardell1/Soteria/internal/filesystem"
	"github.com/Lfardell1/Soteria/internal/toolkit"
	"golang.org/x/sys/unix"
)

func testWorkspace() *filesystem.Workspace {
	root := "/run/soteria-" + testID + "/workspace-123"
	return &filesystem.Workspace{Root: root, Home: root + "/home/workspace", Work: root + "/work", Temp: root + "/tmp", Run: root + "/run", Var: root + "/var", Etc: root + "/etc"}
}

func TestBubblewrapCredentialAndMountBoundary(t *testing.T) {
	request := wireRequest{Config: config.Default(), Command: []string{"bash", "--noprofile"}, Terminal: "xterm-256color"}
	args, err := bubblewrapArguments(testWorkspace(), identity{UID: 1001, GID: 1002}, request, "/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	payload := slices.Index(args, "/usr/bin/setpriv")
	if payload < 0 {
		t.Fatal("missing fixed credential entrypoint")
	}
	for _, forbidden := range []string{"--unshare-all", "--unshare-net", "--unshare-user", "--userns", "--uid", "--gid", "--share-net", "--preserve-fds"} {
		if slices.Contains(args[:payload], forbidden) {
			t.Errorf("unsafe namespace/descriptor flag: %s", forbidden)
		}
	}
	for _, expected := range []string{"--unshare-pid", "--unshare-ipc", "--unshare-uts", "--new-session", "--die-with-parent", "--clearenv"} {
		if !slices.Contains(args[:payload], expected) {
			t.Errorf("missing required boundary %s", expected)
		}
	}
	capabilities := []string{}
	for i := 0; i < payload; i++ {
		if args[i] == "--cap-add" {
			capabilities = append(capabilities, args[i+1])
		}
		if args[i] == "--ro-bind" && args[i+2] == "/" && args[i+1] != toolkit.Root {
			t.Fatal("host root exposed")
		}
		if args[i] == "--bind" && !strings.HasPrefix(args[i+1], testWorkspace().Root+"/") {
			t.Fatalf("unowned writable bind: %s", args[i+1])
		}
	}
	if !reflect.DeepEqual(capabilities, []string{"CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"}) {
		t.Fatalf("unexpected retained root entrypoint capabilities: %v", capabilities)
	}
	wanted := []string{"/usr/bin/setpriv", "--reuid=1001", "--regid=1002", "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", entrypoint.Path, "1001", "1002", "--", "/bin/bash", "--noprofile"}
	if !reflect.DeepEqual(args[payload:], wanted) {
		t.Fatalf("credential wrapper/argv changed: %v", args[payload:])
	}
	status := slices.Index(args, "--json-status-fd")
	if status < 0 || args[status+1] != "4" {
		t.Fatal("missing private bwrap JSON status pipe on fd 4")
	}
	if index := slices.Index(args, "/usr/bin/setsid"); index < 0 || args[index+1] != "/usr/bin/setpriv" {
		t.Fatal("headless payload does not exec through setsid in place")
	}
	for _, argument := range args[:payload] {
		if argument == "/home" || argument == "/sys" || argument == "/run/dbus" || argument == "/dev/pts/0" {
			t.Fatalf("host sensitive mount exposed: %q", argument)
		}
	}
}

func TestInteractiveUsesTrustedControllingTTYWrapper(t *testing.T) {
	request := wireRequest{Config: config.Default(), Command: []string{"bash"}, Interactive: true}
	args, err := bubblewrapArguments(testWorkspace(), identity{UID: 1000, GID: 1000}, request, "/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	index := slices.Index(args, "/usr/bin/setsid")
	if index < 0 || !reflect.DeepEqual(args[index:index+3], []string{"/usr/bin/setsid", "--ctty", "/usr/bin/setpriv"}) {
		t.Fatalf("no real controlling-terminal chain: %v", args)
	}
	for _, flag := range []string{"--fork", "--wait", "--as-pid-1"} {
		if slices.Contains(args[:slices.Index(args, entrypoint.Path)], flag) {
			t.Fatalf("status-mangling or init-replacing flag %s", flag)
		}
	}
	if _, err := bubblewrapArguments(testWorkspace(), identity{}, request, "/bin/bash"); err == nil {
		t.Fatal("root identity accepted")
	}
}

func TestNamespaceIsClonedAtExecWithOnlySelectedFDs(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	files := []*os.File{read, write, write}
	command := namespaceCommand(serviceEnvironment{ID: testID, Invocation: testID, Directory: runtimePath(testID)}, read, files)
	if command.Path != installedExecutable || !reflect.DeepEqual(command.Args, []string{installedExecutable, "__namespace"}) {
		t.Fatalf("non-fixed privileged namespace argv: %v", command.Args)
	}
	if command.SysProcAttr == nil || command.SysProcAttr.Cloneflags != unix.CLONE_NEWNET|unix.CLONE_NEWNS || !command.SysProcAttr.Setsid {
		t.Fatal("namespaces are not created atomically at exec")
	}
	if !reflect.DeepEqual(command.ExtraFiles, []*os.File{read, read, write, write}) {
		t.Fatal("namespace inherits more than its private control socket and selected stream descriptors")
	}
	if command.Stdin != nil || command.Stdout != io.Discard || command.Stderr != io.Discard {
		t.Fatal("namespace entrypoint inherited caller terminal/control on stdio")
	}
}

// Only a normal test subprocess is executed. No namespace, mount, network,
// systemd, sudo, bwrap, or privileged setup operation is invoked by these tests.
func TestProcessFixture(t *testing.T) {
	switch os.Getenv("SOTERIA_SESSION_TEST_PROCESS") {
	case "exit17":
		os.Exit(17)
	case "signal":
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		os.Exit(99)
	case "wait":
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		<-timer.C
		os.Exit(99)
	case "subreaper", "subreaper-timeout", "subreaper-refuse":
		if err := subreaperFixture(os.Getenv("SOTERIA_SESSION_TEST_PROCESS")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(90)
		}
		os.Exit(0)
	case "orphan-monitor":
		pidStream := os.NewFile(3, "private writer PID")
		liveStream := os.NewFile(4, "private live writer")
		command := fixtureCommand(t, "orphan-writer")
		command.ExtraFiles = []*os.File{liveStream}
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := command.Start(); err != nil {
			os.Exit(91)
		}
		_, _ = fmt.Fprintln(pidStream, command.Process.Pid)
		_ = command.Process.Release()
		os.Exit(0)
	case "orphan-writer":
		liveStream := os.NewFile(3, "private live writer")
		grandchild := fixtureCommand(t, "wait")
		if err := grandchild.Start(); err != nil {
			os.Exit(92)
		}
		_ = grandchild.Process.Release()
		for {
			if _, err := liveStream.Write([]byte{'W'}); err != nil {
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func fixtureCommand(t *testing.T, mode string) *exec.Cmd {
	t.Helper()
	name, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(name, "-test.run=^TestProcessFixture$")
	command.Env = fixtureEnvironment(mode)
	command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
	return command
}

func fixtureEnvironment(mode string) []string {
	var environment []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "SOTERIA_SESSION_TEST_PROCESS=") {
			environment = append(environment, value)
		}
	}
	return append(environment, "SOTERIA_SESSION_TEST_PROCESS="+mode)
}

func TestChildConventionalStatusPropagation(t *testing.T) {
	for _, item := range []struct {
		mode string
		code int
	}{{"exit17", 17}, {"signal", 128 + int(syscall.SIGKILL)}} {
		t.Run(item.mode, func(t *testing.T) {
			code, err := commandStatus(fixtureCommand(t, item.mode).Run())
			if err != nil || code != item.code {
				t.Fatalf("status lost: got %d,%v want %d", code, err, item.code)
			}
		})
	}
}

func TestCanceledPayloadNeverStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	command := fixtureCommand(t, "exit17")
	result := runPayload(ctx, command, identity{UID: 1001, GID: 1002}, nil, nil)
	if result.code != InfrastructureFailure || !errors.Is(result.err, context.Canceled) || command.Process != nil || !result.quiescent {
		t.Fatalf("canceled startup acquired a child: %+v process=%v", result, command.Process)
	}
}

func TestOwnedPidfdSignalsOnlyValidatedChild(t *testing.T) {
	command := fixtureCommand(t, "wait")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	cgroup, err := readProcFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var inspected int
	child, err := openOwnedProcess(command.Process.Pid, func(process processIdentity) error {
		inspected++
		if process.parent != os.Getpid() || process.cgroup != string(cgroup) {
			return errors.New("not our private child")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	if inspected != 2 {
		t.Fatal("ownership was not checked both before and after pidfd_open")
	}
	if _, err := openOwnedProcess(command.Process.Pid, func(processIdentity) error { return errors.New("not authorized") }); err == nil {
		t.Fatal("ownership rejection granted a pidfd")
	}
	if _, err := bindNamespaceInit(command.Process.Pid, os.Getpid(), string(cgroup)); err == nil {
		t.Fatal("ordinary same-PID-namespace child was accepted as a new namespace init")
	}
	if err := child.signal(unix.SIGTERM); err != nil {
		t.Fatal(err)
	}
	code, err := commandStatus(command.Wait())
	if err != nil || code != 128+int(syscall.SIGTERM) {
		t.Fatalf("owned pidfd signal lost: %d %v", code, err)
	}
}

func TestSubreaperBarrierReapsEveryAdoptedWriter(t *testing.T) {
	for _, mode := range []string{"subreaper", "subreaper-timeout", "subreaper-refuse"} {
		t.Run(mode, func(t *testing.T) {
			command := fixtureCommand(t, mode)
			var diagnostic strings.Builder
			command.Stderr = &diagnostic
			if err := command.Run(); err != nil {
				t.Fatalf("private ordinary-process fixture failed: %v %s", err, diagnostic.String())
			}
		})
	}
}

func subreaperFixture(mode string) (resultErr error) {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return err
	}
	cgroup, err := readProcFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, drainOwnedDescendants(nil, string(cgroup), 2*time.Second)) }()
	if mode != "subreaper" {
		name, err := os.Executable()
		if err != nil {
			return err
		}
		command := exec.Command(name, "-test.run=^TestProcessFixture$")
		command.Env = fixtureEnvironment("wait")
		command.Stdout, command.Stderr = io.Discard, io.Discard
		if err := command.Start(); err != nil {
			return err
		}
		defer command.Process.Release()
		if mode == "subreaper-timeout" {
			if err := drainOwnedDescendants(nil, string(cgroup), 0); err == nil || !strings.Contains(err.Error(), "before ECHILD") {
				return errors.New("live writer was incorrectly treated as a complete quiescence barrier")
			}
		} else if err := drainOwnedDescendants(nil, "not-the-owned-cgroup", time.Second); err == nil {
			return errors.New("mismatched cgroup granted adopted-child kill authority")
		}
		if err := command.Process.Signal(syscall.Signal(0)); err != nil {
			return errors.New("failed/unauthorized cleanup unexpectedly killed the live child")
		}
		return nil
	}
	pidRead, pidWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pidRead.Close()
	defer pidWrite.Close()
	liveRead, liveWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer liveRead.Close()
	defer liveWrite.Close()
	name, err := os.Executable()
	if err != nil {
		return err
	}
	monitor := exec.Command(name, "-test.run=^TestProcessFixture$")
	monitor.Env = fixtureEnvironment("orphan-monitor")
	monitor.ExtraFiles = []*os.File{pidWrite, liveWrite}
	monitor.Stdout, monitor.Stderr = io.Discard, io.Discard
	if err := monitor.Start(); err != nil {
		return err
	}
	_ = pidWrite.Close()
	_ = liveWrite.Close()
	if err := monitor.Wait(); err != nil {
		return err
	}
	pidBytes, err := io.ReadAll(pidRead)
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		return err
	}
	if err := liveRead.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	var ready [1]byte
	if _, err := io.ReadFull(liveRead, ready[:]); err != nil || ready[0] != 'W' {
		return errors.Join(errors.New("writer did not remain active after monitor exit"), err)
	}
	process, err := readProcessIdentity(pid)
	if err != nil || process.parent != os.Getpid() {
		return errors.Join(errors.New("monitor exit did not leave the active writer adopted by the subreaper"), err)
	}
	if err := drainOwnedDescendants(nil, string(cgroup), 2*time.Second); err != nil {
		return err
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(-1, &status, unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
		return errors.New("descendant drain did not reach ECHILD")
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("an adopted writer survived the cleanup barrier")
	}
	return nil
}

func TestTransferHelperRefusesRootBeforeOpeningAnything(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only refusal assertion; no privileged operation is performed")
	}
	if code, err := transferHelper(context.Background(), []string{"receive", "100", "10"}); code != InfrastructureFailure || err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("root transfer accepted: code=%d err=%v", code, err)
	}
}

func TestCapabilityEvidenceParsingFailsClosed(t *testing.T) {
	for _, value := range []string{"CapEff:\t0000000000000001\n", "CapEff:\tinvalid\n", "CapPrm:\t0000000000000000\n", ""} {
		if zeroStatusCapability(value, "CapEff:") {
			t.Errorf("false zero-capability evidence: %q", value)
		}
	}
	if !zeroStatusCapability("CapEff:\t0000000000000000\n", "CapEff:") {
		t.Fatal("zero capability evidence not recognized")
	}
}
