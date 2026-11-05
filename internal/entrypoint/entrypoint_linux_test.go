//go:build linux && amd64

package entrypoint

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const droppedStatus = "Uid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\nGroups:\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"

func TestStatusRequiresAllIdentityAndCapabilityEvidence(t *testing.T) {
	if err := verifyStatus(droppedStatus, 1001, 1002); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ from, to string }{
		{"1001\t1001\t1001\t1001", "1001\t1001\t0\t1001"},
		{"1002\t1002\t1002\t1002", "1002\t0\t1002\t1002"},
		{"Groups:\n", "Groups:\t1002\n"},
		{"Groups:\n", ""},
		{"NoNewPrivs:\t1", "NoNewPrivs:\t0"},
		{"NoNewPrivs:\t1\n", ""},
		{"Uid:\t1001\t1001\t1001\t1001", "Uid:\t1001\t1001\t1001"},
	} {
		if err := verifyStatus(strings.Replace(droppedStatus, mutation.from, mutation.to, 1), 1001, 1002); err == nil {
			t.Errorf("accepted invalid credential evidence: %q", mutation.to)
		}
	}
	for _, capability := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		for _, replacement := range []string{capability + ":\t0000000000000001\n", capability + ":\tinvalid\n", ""} {
			status := strings.Replace(droppedStatus, capability+":\t0000000000000000\n", replacement, 1)
			if err := verifyStatus(status, 1001, 1002); err == nil {
				t.Errorf("accepted missing/nonzero %s", capability)
			}
		}
	}
	if err := verifyStatus(droppedStatus+"CapBnd:\t0\n", 1001, 1002); err == nil {
		t.Fatal("accepted duplicate evidence")
	}
	for _, ids := range [][2]uint32{{0, 1002}, {1001, 0}, {^uint32(0), 1002}, {1001, ^uint32(0)}} {
		if err := verifyStatus(droppedStatus, ids[0], ids[1]); err == nil {
			t.Fatal("accepted a root or invalid identity")
		}
	}
}

func TestEntryArgumentsAreFixedAndDirect(t *testing.T) {
	args := []string{"1001", "1002", "--", "/usr/bin/python3", "-c", "literal ; \"quoted\" $text", ""}
	uid, gid, argv, err := parseArguments(args)
	if err != nil || uid != 1001 || gid != 1002 || !reflect.DeepEqual(argv, args[3:]) {
		t.Fatalf("direct argv changed: %d %d %q %v", uid, gid, argv, err)
	}
	for _, invalid := range [][]string{
		nil, {"1001", "1002", "/bin/bash"}, {"0", "1002", "--", "/bin/bash"},
		{"1001", "0", "--", "/bin/bash"}, {"01001", "1002", "--", "/bin/bash"},
		{"+1001", "1002", "--", "/bin/bash"}, {"4294967295", "1002", "--", "/bin/bash"},
		{"1001", "1002", "--", "bash"}, {"1001", "1002", "--", "/work/evil"},
		{"1001", "1002", "--", "/bin/../bin/bash"}, {"1001", "1002", "--", "/usr/bin/-bad"},
		{"1001", "1002", "--", "/bin/bash", "\x00"}, {"1001", "1002", "--", "/bin/bash", "\xff"},
		{"1001", "1002", "--", "/bin/bash", strings.Repeat("x", 32<<10)},
	} {
		if _, _, _, err := parseArguments(invalid); err == nil {
			t.Errorf("accepted unsafe entrypoint arguments %q", invalid)
		}
	}
}

func TestWritablePathsRequireCallerOwnedNosuidNodevTmpfs(t *testing.T) {
	stat := unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: 1001, Gid: 1002}
	fs := unix.Statfs_t{Type: unix.TMPFS_MAGIC, Flags: unix.ST_NOSUID | unix.ST_NODEV}
	if err := verifyWritable("/work", stat, fs, 1001, 1002); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*unix.Stat_t, *unix.Statfs_t){
		func(st *unix.Stat_t, _ *unix.Statfs_t) { st.Uid = 0 },
		func(st *unix.Stat_t, _ *unix.Statfs_t) { st.Gid = 0 },
		func(st *unix.Stat_t, _ *unix.Statfs_t) { st.Mode = unix.S_IFREG | 0o700 },
		func(st *unix.Stat_t, _ *unix.Statfs_t) { st.Mode = unix.S_IFDIR | 0o777 },
		func(_ *unix.Stat_t, fs *unix.Statfs_t) { fs.Type = unix.EXT4_SUPER_MAGIC },
		func(_ *unix.Stat_t, fs *unix.Statfs_t) { fs.Flags |= unix.ST_RDONLY },
		func(_ *unix.Stat_t, fs *unix.Statfs_t) { fs.Flags &^= unix.ST_NOSUID },
		func(_ *unix.Stat_t, fs *unix.Statfs_t) { fs.Flags &^= unix.ST_NODEV },
	} {
		st, f := stat, fs
		mutation(&st, &f)
		if err := verifyWritable("/work", st, f, 1001, 1002); err == nil {
			t.Errorf("accepted invalid writable mount: %+v %+v", st, f)
		}
	}
	stat.Mode = unix.S_IFDIR | 0o1777
	if err := verifyWritable("/tmp", stat, fs, 1001, 1002); err != nil {
		t.Fatal(err)
	}
	stat.Mode &^= unix.S_ISVTX
	if err := verifyWritable("/tmp", stat, fs, 1001, 1002); err == nil {
		t.Fatal("accepted non-sticky temporary directory")
	}
}

func TestEnvironmentIsSanitizedAndTerminalIsFixed(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/host/unsafe.so")
	t.Setenv("TERM", "untrusted-terminal")
	t.Setenv("HOME", "/host/home")
	for _, tty := range []bool{false, true} {
		env := Environment(tty)
		joined := strings.Join(env, "\n")
		if strings.Contains(joined, "/host/") || strings.Contains(joined, "LD_PRELOAD") || strings.Contains(joined, "untrusted-terminal") {
			t.Fatalf("inherited host environment: %q", env)
		}
		term := "TERM=dumb"
		if tty {
			term = "TERM=xterm-256color"
		}
		if !strings.Contains(joined, term) {
			t.Fatalf("wrong fixed terminal environment: %q", env)
		}
	}
}

func proofPair(t *testing.T, credentials bool) (*net.UnixConn, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	local := os.NewFile(uintptr(fds[0]), "proof test owner")
	peer := os.NewFile(uintptr(fds[1]), "proof test peer")
	t.Cleanup(func() { _ = peer.Close() })
	if credentials {
		if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
			t.Fatal(err)
		}
	}
	c, err := net.FileConn(local)
	_ = local.Close()
	if err != nil {
		t.Fatal(err)
	}
	connection := c.(*net.UnixConn)
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return connection, peer
}

func TestProofUsesKernelSenderCredentialsAndClosesAtExec(t *testing.T) {
	connection, peer := proofPair(t, true)
	name, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(peer.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(name, "-test.run=^TestEntryProofFixture$")
	command.Env = append(os.Environ(), "SOTERIA_ENTRY_TEST=proof", "SOTERIA_PROOF_INODE="+strconv.FormatUint(st.Ino, 10))
	command.ExtraFiles = []*os.File{peer}
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()
	_ = peer.Close()
	kind, credentials, err := ReceiveProof(connection)
	if err != nil || kind != ProofReady || credentials.Pid != int32(command.Process.Pid) || credentials.Uid != uint32(os.Getuid()) || credentials.Gid != uint32(os.Getgid()) {
		t.Fatalf("proof is not authenticated by the kernel: kind=%q cred=%+v err=%v", kind, credentials, err)
	}
	if err := AcceptProof(connection); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReceiveProof(connection); !errors.Is(err, io.EOF) {
		t.Fatalf("proof socket survived exec: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("proof fixture: %v %s", err, diagnostic.String())
	}
}

func TestProofRejectsMissingCredentialsMalformedFramesAndFDs(t *testing.T) {
	for _, test := range []struct {
		name        string
		credentials bool
		data        []byte
		rights      bool
	}{
		{"missing credentials", false, []byte{ProofReady}, false},
		{"unknown stage", true, []byte{'X'}, false},
		{"oversized", true, bytes.Repeat([]byte{ProofReady}, 20), false},
		{"descriptor", true, []byte{ProofReady}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, peer := proofPair(t, test.credentials)
			var ancillary []byte
			if test.rights {
				read, write, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer read.Close()
				defer write.Close()
				ancillary = unix.UnixRights(int(read.Fd()))
			}
			if _, err := unix.SendmsgN(int(peer.Fd()), test.data, ancillary, nil, unix.MSG_NOSIGNAL); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReceiveProof(connection); err == nil {
				t.Fatal("accepted malformed or unauthenticated proof")
			}
		})
	}
}

// These subprocesses use only ordinary inherited sockets and exec. They never
// run bwrap/setpriv, change credentials, mount, or create namespaces.
func TestEntryProofFixture(t *testing.T) {
	switch os.Getenv("SOTERIA_ENTRY_TEST") {
	case "proof":
		if err := unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC); err != nil {
			panic(err)
		}
		if _, err := unix.SendmsgN(3, []byte{ProofReady}, nil, nil, unix.MSG_NOSIGNAL); err != nil {
			panic(err)
		}
		var ack [2]byte
		n, _, _, _, err := unix.Recvmsg(3, ack[:], nil, 0)
		if err != nil || n != 1 || ack[0] != ProofAccept {
			panic("proof acknowledgement missing")
		}
		name, err := os.Executable()
		if err != nil {
			panic(err)
		}
		if err := os.Setenv("SOTERIA_ENTRY_TEST", "after-exec"); err != nil {
			panic(err)
		}
		if err := unix.Exec(name, []string{name, "-test.run=^TestEntryProofFixture$"}, os.Environ()); err != nil {
			panic(err)
		}
	case "after-exec":
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			panic(err)
		}
		for _, entry := range entries {
			target, _ := os.Readlink("/proc/self/fd/" + entry.Name())
			if target == "socket:["+os.Getenv("SOTERIA_PROOF_INODE")+"]" {
				panic("launch-proof socket leaked through exec")
			}
		}
		os.Exit(0)
	}
}

func FuzzEntryStatus(f *testing.F) {
	f.Add(droppedStatus)
	f.Add("CapBnd:\tffffffffffffffff\n")
	f.Fuzz(func(t *testing.T, text string) { _ = verifyStatus(text, 1001, 1002) })
}

func ExampleEnvironment() {
	for _, item := range Environment(false) {
		if strings.HasPrefix(item, "TERM=") {
			fmt.Println(item)
		}
	}
	// Output: TERM=dumb
}
