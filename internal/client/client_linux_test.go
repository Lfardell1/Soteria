//go:build linux && amd64

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/protocol"
	"github.com/Lfardell1/Soteria/internal/transfer"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

const testSessionID = "0123456789abcdef0123456789abcdef"

var testStdout = []byte{'o', 'u', 't', 0, '\xff', '\n'}
var testStderr = []byte{'e', 'r', 'r', 0, '\xfe', '\n'}

func TestFixedStarterCommand(t *testing.T) {
	conn, peer, err := protocol.Pair()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer peer.Close()
	cmd := starterCommand(peer, os.Stderr)
	if cmd.Path != "/usr/bin/sudo" || !reflect.DeepEqual(cmd.Args, []string{"/usr/bin/sudo", "--", protocol.StarterPath}) {
		t.Fatalf("unexpected privileged argv: %#v", cmd.Args)
	}
	if cmd.Stdin != peer || cmd.Stdout != io.Discard || cmd.Stderr != os.Stderr || len(cmd.ExtraFiles) != 0 {
		t.Fatal("starter standard streams or inherited descriptors changed")
	}
	if !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}) {
		t.Fatalf("non-fixed starter environment: %#v", cmd.Env)
	}
}

func TestPublicClientRejectsUIDZero(t *testing.T) {
	if os.Getuid() != 0 && os.Geteuid() != 0 {
		t.Skip("root rejection applies only to UID 0; never launch a real starter in tests")
	}
	for _, fn := range []func() (int, error){
		func() (int, error) { return Run(context.Background(), Request{}, Streams{}) },
		func() (int, error) { return Cleanup(context.Background(), testSessionID, Streams{}) },
	} {
		code, err := fn()
		if code != InfrastructureExit || err == nil || !strings.Contains(err.Error(), "non-root") {
			t.Fatalf("root was not rejected: code=%d err=%v", code, err)
		}
	}
}

func TestShellRejectsNonTTYBeforeLaunchingStarter(t *testing.T) {
	f := newFixture(t, "never-start")
	f.client.launch = func(*os.File, *os.File) (*exec.Cmd, error) {
		t.Fatal("non-TTY shell reached starter")
		return nil, errors.New("unexpected starter")
	}
	request := f.request()
	request.RequireTTY = true
	code, err := f.run(request)
	if code != InfrastructureExit || err == nil || !strings.Contains(err.Error(), "shell requires terminal") {
		t.Fatalf("non-TTY shell code=%d err=%v", code, err)
	}
}

type fixture struct {
	t       *testing.T
	dir     string
	streams Streams
	signals chan os.Signal
	client  engineClient
	mode    string
	notify  *os.File
}

func newFixture(t *testing.T, mode string) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), mode: mode, signals: make(chan os.Signal, 8)}
	for _, directory := range []string{"imports", "outputs", "destination"} {
		if err := os.Mkdir(filepath.Join(f.dir, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	open := func(name string) *os.File {
		file, err := os.Create(filepath.Join(f.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return file
	}
	f.streams = Streams{In: open("stdin"), Out: open("stdout"), Err: open("stderr")}
	if _, err := f.streams.In.Write([]byte("input\x00\xff\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.streams.In.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	f.client = defaultClient()
	f.client.setupTimeout = 3 * time.Second
	f.client.drainTimeout = 250 * time.Millisecond
	f.client.stopTimeout = time.Second
	f.client.signals = func() (<-chan os.Signal, func()) { return f.signals, func() {} }
	f.client.launch = func(peer, stderr *os.File) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestEngineProcess$")
		cmd.Env = append(os.Environ(), "SOTERIA_CLIENT_TEST_PROCESS=1", "SOTERIA_CLIENT_TEST_MODE="+f.mode, "SOTERIA_CLIENT_TEST_DIR="+f.dir)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = peer, io.Discard, stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if f.notify != nil {
			cmd.ExtraFiles = []*os.File{f.notify}
		}
		return cmd, cmd.Start()
	}
	return f
}

func (f *fixture) request() Request {
	return Request{Config: config.Default(), Argv: []string{"example-tool", "arg with spaces", "$(not-a-shell)", ";", "--flag"}}
}

func (f *fixture) read(name string) []byte {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		f.t.Fatal(err)
	}
	return data
}

func (f *fixture) run(request Request) (int, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return f.client.run(ctx, request, f.streams)
}

func TestDirectArgvBinaryStreamsAndStdinEOFLifeline(t *testing.T) {
	f := newFixture(t, "stdio")
	if _, err := f.streams.Out.WriteString("prefix:"); err != nil {
		t.Fatal(err)
	}
	code, err := f.run(f.request())
	if code != 7 || err != nil {
		t.Fatalf("code=%d err=%v stderr=%s", code, err, f.read("stderr"))
	}
	if got := f.read("stdout"); !bytes.Equal(got, append([]byte("prefix:"), testStdout...)) {
		t.Fatalf("stdout/offset changed: %q", got)
	}
	stderr := f.read("stderr")
	if !bytes.Contains(stderr, testStderr) || !bytes.Contains(stderr, []byte("stdin eof control alive")) {
		t.Fatalf("stderr or control lifeline missing: %q", stderr)
	}
}

func TestImportsAreInspectedOnlyAfterReady(t *testing.T) {
	f := newFixture(t, "late-import")
	request := f.request()
	request.Imports = []string{filepath.Join(f.dir, "late-input")}
	code, err := f.run(request)
	if code != 0 || err != nil {
		t.Fatalf("code=%d err=%v stderr=%s", code, err, f.read("stderr"))
	}
	if got := f.read("imports/late-input"); string(got) != "created before ready, not before start" {
		t.Fatalf("unexpected import: %q", got)
	}
}

func TestExportAuthorizationAndAcknowledgement(t *testing.T) {
	for _, mode := range []string{"export", "export-phase"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode)
			request := f.request()
			request.ExportDirectory = filepath.Join(f.dir, "destination")
			code, err := f.run(request)
			if code != 0 || err != nil {
				t.Fatalf("code=%d err=%v stderr=%s", code, err, f.read("stderr"))
			}
			if got := f.read("destination/answer"); string(got) != "explicit output" {
				t.Fatalf("export=%q", got)
			}
		})
	}
}

func TestExportFailureIsLocalRedactedAndNoOverwrite(t *testing.T) {
	f := newFixture(t, "export-collision")
	request := f.request()
	request.ExportDirectory = filepath.Join(f.dir, "destination")
	if err := os.WriteFile(filepath.Join(request.ExportDirectory, "answer"), []byte("keep existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, err := f.run(request)
	if code != InfrastructureExit || err == nil {
		t.Fatalf("code=%d err=%v stderr=%s", code, err, f.read("stderr"))
	}
	if string(f.read("destination/answer")) != "keep existing" {
		t.Fatal("existing destination was overwritten")
	}
	if !strings.Contains(string(f.read("stderr")), "without overwrite") {
		t.Fatalf("detailed caller-side export error missing: %s", f.read("stderr"))
	}
}

func TestNeverPublishWithoutExportingOrAfterFailure(t *testing.T) {
	for _, tc := range []struct {
		mode string
		code int
	}{
		{"failed-export-stream", 9}, {"missing-export-event", InfrastructureExit}, {"disconnect", InfrastructureExit},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newFixture(t, tc.mode)
			request := f.request()
			request.ExportDirectory = filepath.Join(f.dir, "destination")
			code, err := f.run(request)
			if code != tc.code {
				t.Fatalf("code=%d want=%d err=%v stderr=%s", code, tc.code, err, f.read("stderr"))
			}
			entries, err := os.ReadDir(request.ExportDirectory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("unauthorized export: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestAllowedSignalsAreForwardedWithoutClosingLifeline(t *testing.T) {
	f := newFixture(t, "signal")
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	f.notify = write
	request := f.request()
	request.ExportDirectory = filepath.Join(f.dir, "destination")
	done := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		code, err := f.run(request)
		done <- struct {
			code int
			err  error
		}{code, err}
	}()
	_ = read.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ready [1]byte
	if _, err := io.ReadFull(read, ready[:]); err != nil {
		t.Fatal(err)
	}
	f.signals <- syscall.SIGUSR1 // Not a protocol-approved signal.
	f.signals <- syscall.SIGTERM
	result := <-done
	if result.code != 143 || result.err != nil {
		t.Fatalf("code=%d err=%v stderr=%s", result.code, result.err, f.read("stderr"))
	}
	entries, err := os.ReadDir(request.ExportDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("signal exported output: %v %v", entries, err)
	}
}

func TestReadyTimeoutAndContextCancellationDoNotOpenImports(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprint(cancel), func(t *testing.T) {
			f := newFixture(t, "never-ready")
			f.client.setupTimeout = 150 * time.Millisecond
			request := f.request()
			request.Imports = []string{filepath.Join(f.dir, "does-not-exist")}
			ctx := context.Background()
			if cancel {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 75*time.Millisecond)
				defer stop()
			}
			start := time.Now()
			code, err := f.client.run(ctx, request, f.streams)
			if code != InfrastructureExit || err == nil || strings.Contains(err.Error(), "import") || time.Since(start) > 2*time.Second {
				t.Fatalf("code=%d err=%v duration=%v", code, err, time.Since(start))
			}
			if cancel && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}

func TestPendingSignalPreventsImportHandoff(t *testing.T) {
	f := newFixture(t, "pending-signal")
	request := f.request()
	request.Imports = []string{filepath.Join(f.dir, "must-not-be-inspected")}
	f.signals <- syscall.SIGTERM
	code, err := f.run(request)
	if code != InfrastructureExit || err == nil || strings.Contains(err.Error(), "import:") {
		t.Fatalf("pending signal opened an import or started workload: code=%d err=%v stderr=%s", code, err, f.read("stderr"))
	}
}

func TestBoundedDrainAndSetupResult(t *testing.T) {
	for _, mode := range []string{"hold-output", "setup-failure", "bad-fds"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode)
			f.client.drainTimeout = 75 * time.Millisecond
			start := time.Now()
			code, err := f.run(f.request())
			if code != InfrastructureExit || time.Since(start) > 2*time.Second {
				t.Fatalf("code=%d err=%v duration=%v stderr=%s", code, err, time.Since(start), f.read("stderr"))
			}
		})
	}
}

func TestCleanupIsFirstRequestWithNoDescriptors(t *testing.T) {
	for _, mode := range []string{"cleanup", "cleanup-failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode)
			code, err := f.client.cleanup(context.Background(), testSessionID, f.streams)
			want := 0
			if mode == "cleanup-failure" {
				want = InfrastructureExit
			}
			if code != want || err != nil {
				t.Fatalf("code=%d err=%v stderr=%s", code, err, f.read("stderr"))
			}
		})
	}
}

func TestChildAndCleanupStatuses(t *testing.T) {
	for _, child := range []int{0, 1, 42, 125, 126, 127, 130, 143, 255, -1, 256} {
		f := newFixture(t, "exit-"+strconv.Itoa(child))
		code, err := f.run(f.request())
		want := child
		if want < 0 || want > 255 {
			want = InfrastructureExit
		}
		if code != want || err != nil {
			t.Fatalf("child=%d code=%d err=%v stderr=%s", child, code, err, f.read("stderr"))
		}
	}
	f := newFixture(t, "child-cleanup-failure")
	code, err := f.run(f.request())
	if code != InfrastructureExit || err != nil || !strings.Contains(string(f.read("stderr")), "exit=9; cleanup failed: residual removal failed") {
		t.Fatalf("child and cleanup results lost: code=%d err=%v stderr=%s", code, err, f.read("stderr"))
	}
}

func TestRepeatedBlockedStdinDoesNotLeakOrChangeFlags(t *testing.T) {
	f := newFixture(t, "no-stdin")
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close() // Deliberately held open without input throughout all sessions.
	f.streams.In = read
	flags := fileFlags(t, read)
	beforeFDs, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	beforeGoroutines := runtime.NumGoroutine()
	for i := 0; i < 12; i++ {
		code, err := f.run(f.request())
		if code != 0 || err != nil {
			t.Fatalf("iteration=%d code=%d err=%v stderr=%s", i, code, err, f.read("stderr"))
		}
		if got := fileFlags(t, read); got != flags {
			t.Fatalf("stdin flags changed: before=%#x after=%#x", flags, got)
		}
	}
	afterFDs, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(afterFDs) != len(beforeFDs) || runtime.NumGoroutine() > beforeGoroutines+1 {
		t.Fatalf("session leak: fds %d -> %d; goroutines %d -> %d", len(beforeFDs), len(afterFDs), beforeGoroutines, runtime.NumGoroutine())
	}
}

func fileFlags(t *testing.T, file *os.File) int {
	t.Helper()
	var flags int
	var inner error
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	err = raw.Control(func(fd uintptr) { flags, inner = unix.FcntlInt(fd, unix.F_GETFL, 0) })
	if err != nil || inner != nil {
		t.Fatal(errors.Join(err, inner))
	}
	return flags
}

func TestFreshPTYRawModeResizeAndRestoration(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if err := pty.Setsize(slave, &pty.Winsize{Rows: 37, Cols: 101}); err != nil {
		t.Fatal(err)
	}
	c, err := prepareIO(Streams{In: slave, Out: slave, Err: os.Stderr}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	caller, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || caller.Lflag&(unix.ICANON|unix.ISIG|unix.ECHO) != 0 {
		t.Fatalf("caller not raw: %#v %v", caller, err)
	}
	fresh, err := unix.IoctlGetTermios(int(c.files[0].Fd()), unix.TCGETS)
	if err != nil || fresh.Lflag&unix.ISIG == 0 || fresh.Cc[unix.VINTR] != 3 || fresh.Cc[unix.VSUSP] != 26 {
		t.Fatalf("fresh PTY lost Ctrl-C/Ctrl-Z line discipline: %#v %v", fresh, err)
	}
	var hostStat, childStat unix.Stat_t
	_ = unix.Fstat(int(slave.Fd()), &hostStat)
	_ = unix.Fstat(int(c.files[0].Fd()), &childStat)
	if hostStat.Rdev == childStat.Rdev || childStat.Uid != uint32(os.Getuid()) {
		t.Fatal("command PTY is not fresh and caller-owned")
	}
	size, err := unix.IoctlGetWinsize(int(c.files[0].Fd()), unix.TIOCGWINSZ)
	if err != nil || size.Row != 37 || size.Col != 101 {
		t.Fatalf("initial size=%v err=%v", size, err)
	}
	if err := pty.Setsize(slave, &pty.Winsize{Rows: 44, Cols: 132}); err != nil {
		t.Fatal(err)
	}
	rows, cols, err := c.resize()
	if err != nil || rows != 44 || cols != 132 {
		t.Fatalf("resize=%d,%d err=%v", rows, cols, err)
	}
	if err := c.close(); err != nil {
		t.Fatal(err)
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal not restored: before=%#v after=%#v err=%v", before, after, err)
	}
}

func TestPTYProtocolResizeAndControlCharacters(t *testing.T) {
	f := newFixture(t, "tty")
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.Setsize(slave, &pty.Winsize{Rows: 37, Cols: 101}); err != nil {
		t.Fatal(err)
	}
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	f.streams.In, f.streams.Out = slave, slave
	request := f.request()
	request.RequireTTY = true
	type outcome struct {
		code int
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		code, err := f.run(request)
		done <- outcome{code, err}
	}()
	reader, err := takeRelay(master)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var captured bytes.Buffer
	readUntil := func(marker string) {
		t.Helper()
		buffer := make([]byte, 1024)
		for !strings.Contains(captured.String(), marker) {
			if err := waitFD(ctx, reader.fd, unix.POLLIN); err != nil {
				t.Fatalf("waiting for %q: %v output=%q stderr=%s", marker, err, &captured, f.read("stderr"))
			}
			n, err := unix.Read(reader.fd, buffer)
			if errors.Is(err, unix.EAGAIN) {
				continue
			}
			if err != nil || n == 0 {
				t.Fatalf("PTY read waiting for %q: %v output=%q", marker, err, &captured)
			}
			captured.Write(buffer[:n])
		}
	}
	readUntil("WORKLOAD-READY")
	if err := pty.Setsize(slave, &pty.Winsize{Rows: 44, Cols: 132}); err != nil {
		t.Fatal(err)
	}
	f.signals <- syscall.SIGWINCH
	readUntil("SIZE:44:132")
	if _, err := unix.Write(reader.fd, []byte{3}); err != nil {
		t.Fatal(err)
	}
	readUntil("GOT-INT")
	if _, err := unix.Write(reader.fd, []byte{26}); err != nil {
		t.Fatal(err)
	}
	readUntil("GOT-TSTP")
	result := <-done
	if result.code != 0 || result.err != nil {
		t.Fatalf("code=%d err=%v stderr=%s", result.code, result.err, f.read("stderr"))
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("caller terminal not restored after session: before=%#v after=%#v err=%v", before, after, err)
	}
}

func TestTerminalRestoredOnDisconnectAndFailedCommand(t *testing.T) {
	for _, mode := range []string{"tty-disconnect", "tty-failed-command"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode)
			master, slave, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			defer slave.Close()
			before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			f.streams.In, f.streams.Out = slave, slave
			code, err := f.run(f.request())
			want := InfrastructureExit
			if mode == "tty-failed-command" {
				want = 9
			}
			if code != want {
				t.Fatalf("code=%d err=%v stderr=%s", code, err, f.read("stderr"))
			}
			after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("terminal not restored after failure: before=%#v after=%#v err=%v", before, after, err)
			}
		})
	}
}

func TestBlockedImportIsCanceledAndClosed(t *testing.T) {
	f := newFixture(t, "blocked-import")
	request := f.request()
	path := filepath.Join(f.dir, "large-input")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	request.Imports = []string{path}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	code, err := f.client.run(ctx, request, f.streams)
	if code != InfrastructureExit || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("blocked import cancellation code=%d err=%v duration=%v stderr=%s", code, err, time.Since(start), f.read("stderr"))
	}
}

func TestSocketStdinIsRelayedWithoutSharedFlagChanges(t *testing.T) {
	f := newFixture(t, "stdio")
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	input, peer := os.NewFile(uintptr(fds[0]), "socket stdin"), os.NewFile(uintptr(fds[1]), "socket peer")
	defer input.Close()
	defer peer.Close()
	f.streams.In = input
	flags := fileFlags(t, input)
	if _, err := peer.Write([]byte("input\x00\xff\n")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Shutdown(fds[1], unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	code, err := f.run(f.request())
	if code != 7 || err != nil || fileFlags(t, input) != flags {
		t.Fatalf("code=%d err=%v flags before=%#x after=%#x stderr=%s", code, err, flags, fileFlags(t, input), f.read("stderr"))
	}
}

func TestBlockedHostOutputCanBeCanceled(t *testing.T) {
	f := newFixture(t, "unused")
	if err := os.WriteFile(filepath.Join(f.dir, "source"), bytes.Repeat([]byte{1}, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(filepath.Join(f.dir, "source"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	src, err := hostRelay(source, false)
	if err != nil {
		t.Fatal(err)
	}
	defer src.close()
	dst, err := hostRelay(write, true)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.close()
	flags := fileFlags(t, write)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if err := copyRelay(ctx, dst, src); !errors.Is(err, context.DeadlineExceeded) || fileFlags(t, write) != flags {
		t.Fatalf("blocked output cancellation=%v flags changed=%t", err, fileFlags(t, write) != flags)
	}
}

func TestDiagnosticsCannotBlockOnFullStderr(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	fd, err := hostRelay(write, true)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.close()
	buffer := make([]byte, 64<<10)
	for {
		_, err := unix.Write(fd.fd, buffer)
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	flags := fileFlags(t, write)
	start := time.Now()
	localDiagnostic(write, "a status message must not hold the raw terminal forever")
	if time.Since(start) > time.Second || fileFlags(t, write) != flags {
		t.Fatalf("diagnostics blocked or modified caller flags: duration=%v", time.Since(start))
	}
}

func TestConfigIsCanonicalizedBeforeStartPacket(t *testing.T) {
	f := newFixture(t, "stdio")
	request := f.request()
	request.Config.Resources.MemoryMax = strings.Repeat(" ", 100000) + "1G "
	code, err := f.run(request)
	if code != 7 || err != nil || len(request.Config.Resources.MemoryMax) < 100000 {
		t.Fatalf("valid padded config could not start or was mutated: code=%d err=%v stderr=%s", code, err, f.read("stderr"))
	}
}

// The fake privileged side is a real process under the test's existing
// credentials. It only uses private IPC and temporary files, never sudo/systemd.
func TestEngineProcess(t *testing.T) {
	if os.Getenv("SOTERIA_CLIENT_TEST_PROCESS") != "1" {
		return
	}
	if err := engineProcess(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "fake engine:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func engineProcess() error {
	mode, directory := os.Getenv("SOTERIA_CLIENT_TEST_MODE"), os.Getenv("SOTERIA_CLIENT_TEST_DIR")
	conn, err := protocol.FromFile(os.Stdin)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	peer, err := conn.Peer()
	if err != nil || peer.Uid != uint32(os.Getuid()) || peer.Pid != int32(os.Getppid()) {
		return fmt.Errorf("socketpair kernel credentials: %v %v", peer, err)
	}
	first, files, err := conn.Receive()
	if err != nil || len(files) != 0 || first.UID != 0 || first.GID != 0 || len(first.Argv) != 0 {
		protocol.CloseFiles(files)
		return fmt.Errorf("invalid first request: %#v fds=%d err=%v", first, len(files), err)
	}
	if strings.HasPrefix(mode, "cleanup") {
		if first.Type != "cleanup" || first.SessionID != testSessionID || first.Config != nil {
			return errors.New("cleanup was not the first request")
		}
		result := protocol.Result{Facts: protocol.Facts{Cleanup: "completed"}}
		if mode == "cleanup-failure" {
			result.CleanupError = "residual ownership not verified"
		}
		return conn.Send(protocol.Message{Type: "result", Result: &result})
	}
	if first.Type != "start" || first.Config == nil || first.Config.Validate() != nil || first.TTY || first.Export {
		return errors.New("invalid start request")
	}
	if mode == "never-ready" {
		_, files, err := conn.Receive()
		protocol.CloseFiles(files)
		if err == nil {
			return errors.New("client sent files or argv before ready")
		}
		return nil
	}
	if mode == "setup-failure" {
		return conn.Send(protocol.Message{Type: "result", Result: &protocol.Result{Error: "setup rejected"}})
	}
	if mode == "bad-fds" {
		return conn.Send(protocol.Message{Type: "warning", Warning: "unexpected fd"}, os.Stderr)
	}
	if mode == "late-import" {
		if err := os.WriteFile(filepath.Join(directory, "late-input"), []byte("created before ready, not before start"), 0o600); err != nil {
			return err
		}
	}
	facts := protocol.Facts{Filesystem: "tmpfs", Network: "offline", Cleanup: "pending"}
	if err := conn.Send(protocol.Message{Type: "ready", SessionID: testSessionID, Facts: &facts}); err != nil {
		return err
	}
	run, files, err := conn.Receive()
	if err != nil {
		return err
	}
	defer protocol.CloseFiles(files)
	if mode == "pending-signal" {
		if run.Type != "signal" || run.Signal != int(syscall.SIGTERM) || len(files) != 0 {
			return errors.New("pending signal was not handled before workload descriptors")
		}
		return nil
	}
	if run.Type != "run" || len(files) != 5 || run.Config != nil || run.TTY != strings.HasPrefix(mode, "tty") {
		return fmt.Errorf("invalid run request: %#v fds=%d", run, len(files))
	}
	expected := []string{"example-tool", "arg with spaces", "$(not-a-shell)", ";", "--flag"}
	if !reflect.DeepEqual(run.Argv, expected) {
		encoded, _ := json.Marshal(run.Argv)
		return fmt.Errorf("argv was not direct: %s", encoded)
	}
	for i, file := range files {
		var st unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &st); err != nil {
			return err
		}
		if run.TTY && i < 3 {
			if !isTerminal(file) || st.Uid != uint32(os.Getuid()) || st.Mode&unix.S_IFMT != unix.S_IFCHR {
				return errors.New("command fd is not a caller-owned slave terminal")
			}
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFIFO {
			return fmt.Errorf("fd%d is not a fresh FIFO: %v", i, err)
		}
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		want := unix.O_WRONLY
		if i == 0 || i == 3 {
			want = unix.O_RDONLY
		}
		if err != nil || flags&unix.O_ACCMODE != want {
			return fmt.Errorf("fd%d direction flags=%#x want=%#x err=%v", i, flags, want, err)
		}
	}
	maxBytes, _ := config.ParseSize(first.Config.Transfers.MaxBytes)
	limits := transfer.Limits{MaxBytes: maxBytes, MaxFiles: first.Config.Transfers.MaxFiles}
	if mode == "blocked-import" {
		_, fds, _ := conn.Receive()
		protocol.CloseFiles(fds)
		return nil
	}
	if err := transfer.Receive(context.Background(), files[3], filepath.Join(directory, "imports"), limits); err != nil {
		return fmt.Errorf("imports (including empty terminal stream and EOF): %w", err)
	}
	_ = files[3].Close()
	if run.TTY {
		if mode == "tty-disconnect" {
			return nil
		}
		if mode == "tty-failed-command" {
			protocol.CloseFiles(files)
			return conn.Send(protocol.Message{Type: "result", Result: &protocol.Result{ChildStarted: true, ChildExit: 9}})
		}
		return ttyEngineProcess(conn, files)
	}
	if mode != "no-stdin" && mode != "signal" {
		input, err := io.ReadAll(files[0])
		if err != nil || !bytes.Equal(input, []byte("input\x00\xff\n")) {
			return fmt.Errorf("stdin: %q %v", input, err)
		}
		if err := conn.Send(protocol.Message{Type: "warning", Warning: "stdin eof control alive"}); err != nil {
			return err
		}
	}
	if _, err := files[1].Write(testStdout); err != nil {
		return err
	}
	if _, err := files[2].Write(testStderr); err != nil {
		return err
	}
	result := protocol.Result{ChildStarted: true, ChildExit: 0, Facts: facts}
	if mode == "stdio" {
		result.ChildExit = 7
	}
	if strings.HasPrefix(mode, "exit-") {
		result.ChildExit, err = strconv.Atoi(strings.TrimPrefix(mode, "exit-"))
		if err != nil {
			return err
		}
	}
	if mode == "child-cleanup-failure" {
		result.ChildExit, result.CleanupError = 9, "residual removal failed"
	}
	if mode == "signal" {
		notify := os.NewFile(3, "test notification")
		_, err := notify.Write([]byte{1})
		_ = notify.Close()
		if err != nil {
			return err
		}
		message, files, err := conn.Receive()
		protocol.CloseFiles(files)
		if err != nil || message.Type != "signal" || message.Signal != int(syscall.SIGTERM) {
			return fmt.Errorf("expected allowed signal: %#v %v", message, err)
		}
		result.ChildExit = 143
	}
	if run.Export && mode != "signal" {
		if err := os.WriteFile(filepath.Join(directory, "outputs", "answer"), []byte("explicit output"), 0o600); err != nil {
			return err
		}
		sources, err := transfer.Outputs(filepath.Join(directory, "outputs"))
		if err != nil {
			return err
		}
		if err := transfer.Send(context.Background(), files[4], sources, limits); err != nil {
			return err
		}
		_ = files[4].Close()
		// Bytes can already be queued, but no publication may occur until the
		// independently authenticated exporting event is received.
		time.Sleep(75 * time.Millisecond)
		entries, err := os.ReadDir(filepath.Join(directory, "destination"))
		if err != nil || mode != "export-collision" && len(entries) != 0 {
			return fmt.Errorf("export was consumed before authorization: %v %v", entries, err)
		}
		switch mode {
		case "failed-export-stream":
			result.ChildExit = 9
		case "missing-export-event":
		case "disconnect":
			return nil
		default:
			event := protocol.Message{Type: "exporting"}
			if mode == "export-phase" {
				event = protocol.Message{Type: "phase", Phase: "exporting"}
			}
			if err := conn.Send(event); err != nil {
				return err
			}
			ack, fds, err := conn.Receive()
			protocol.CloseFiles(fds)
			if err != nil || len(fds) != 0 || ack.Type != "export-result" {
				return fmt.Errorf("export acknowledgement: %#v %v", ack, err)
			}
			if mode == "export-collision" {
				if ack.Error != "export failed after partial publication" {
					return fmt.Errorf("export error was not redacted: %q", ack.Error)
				}
				result.Error = ack.Error
			} else if ack.Error != "" {
				return fmt.Errorf("unexpected export failure: %q", ack.Error)
			}
		}
	}
	_ = files[0].Close()
	_ = files[4].Close()
	if mode != "hold-output" {
		_ = files[1].Close()
		_ = files[2].Close()
	}
	if err := conn.Send(protocol.Message{Type: "result", Result: &result}); err != nil {
		return err
	}
	if mode == "hold-output" {
		_, fds, _ := conn.Receive()
		protocol.CloseFiles(fds)
	}
	return nil
}

func ttyEngineProcess(conn *protocol.Conn, files []*os.File) error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTTYWorkloadProcess$")
	cmd.Env = append(os.Environ(), "SOTERIA_TTY_WORKLOAD_TEST=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = files[0], files[1], files[2]
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer cmd.Process.Kill()
	for _, expected := range [][2]uint16{{37, 101}, {44, 132}} {
		resize, fds, err := conn.Receive()
		protocol.CloseFiles(fds)
		if err != nil || resize.Type != "resize" || resize.Rows != expected[0] || resize.Cols != expected[1] {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("resize packet=%#v err=%v", resize, err)
		}
	}
	err := cmd.Wait()
	protocol.CloseFiles(files)
	if err != nil {
		return err
	}
	return conn.Send(protocol.Message{Type: "result", Result: &protocol.Result{ChildStarted: true, ChildExit: 0}})
}

func TestTTYWorkloadProcess(t *testing.T) {
	if os.Getenv("SOTERIA_TTY_WORKLOAD_TEST") != "1" {
		return
	}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTSTP, syscall.SIGWINCH)
	_, _ = fmt.Fprintln(os.Stdout, "WORKLOAD-READY")
	interrupted, suspended := false, false
	for !interrupted || !suspended {
		switch <-signals {
		case syscall.SIGINT:
			interrupted = true
			_, _ = fmt.Fprintln(os.Stdout, "GOT-INT")
		case syscall.SIGTSTP:
			suspended = true
			_, _ = fmt.Fprintln(os.Stdout, "GOT-TSTP")
		case syscall.SIGWINCH:
			size, _ := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ)
			_, _ = fmt.Fprintf(os.Stdout, "SIZE:%d:%d\n", size.Row, size.Col)
		}
	}
	os.Exit(0)
}
