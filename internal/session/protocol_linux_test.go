//go:build linux && amd64

package session

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
	"golang.org/x/sys/unix"
)

func testConnections(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	left, peer, err := socketPair()
	if err != nil {
		t.Fatal(err)
	}
	right, err := connectionFromFile(peer)
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	_ = left.SetDeadline(time.Now().Add(3 * time.Second))
	_ = right.SetDeadline(time.Now().Add(3 * time.Second))
	return left, right
}

func TestPacketFDHandoffAndCloseOnExec(t *testing.T) {
	left, right := testConnections(t)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	message := controlMessage{Version: protocolVersion, Kind: "run", Request: &wireRequest{Config: config.Default(), Command: []string{"cat"}}}
	if err := (&packetWriter{connection: left}).send(message, read); err != nil {
		t.Fatal(err)
	}
	var received controlMessage
	files, err := receivePacket(right, &received, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(files)
	if received.Request == nil || received.Request.Command[0] != "cat" {
		t.Fatalf("packet lost request: %+v", received)
	}
	flags, err := unix.FcntlInt(files[0].Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received FD is not atomically CLOEXEC: flags=%d err=%v", flags, err)
	}
	if _, err := write.Write([]byte("bytes")); err != nil {
		t.Fatal(err)
	}
	var buffer [5]byte
	if _, err := io.ReadFull(files[0], buffer[:]); err != nil || string(buffer[:]) != "bytes" {
		t.Fatalf("received FD does not name original pipe: %q %v", buffer, err)
	}
}

func TestRejectedPacketClosesTransferredFDs(t *testing.T) {
	left, right := testConnections(t)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if err := (&packetWriter{connection: left}).send(controlMessage{Version: 1, Kind: "unexpected"}, read); err != nil {
		t.Fatal(err)
	}
	var message controlMessage
	if files, err := receivePacket(right, &message, 0); err == nil || files != nil {
		t.Fatalf("unexpected descriptors accepted: %v %v", files, err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatalf("rejected message leaked descriptors: before=%d after=%d err=%v", len(before), len(after), err)
	}
}

func TestStrictRequestRejectsAuthorityAndAmbiguity(t *testing.T) {
	for _, text := range []string{
		`{"version":1,"kind":"run","uid":0}`,
		`{"version":1,"kind":"run","kind":"cleanup"}`,
		`{"version":1,"Kind":"run"}`,
		`{"version":1,"kind":"run","request":null}`,
		`{"version":1,"kind":"run"} {}`,
		`{"version":1,"kind":"run","sudo_uid":1000}`,
	} {
		var message controlMessage
		if err := strictJSON([]byte(text), &message); err == nil {
			t.Errorf("ambiguous/authority-bearing request accepted: %s", text)
		}
	}
	var message controlMessage
	if err := strictJSON([]byte(`{"version":1,"kind":"cleanup","target":"0123456789abcdef0123456789abcdef"}`), &message); err != nil {
		t.Fatal(err)
	}
}

func TestOversizedPacketRejected(t *testing.T) {
	left, right := testConnections(t)
	if _, _, err := left.WriteMsgUnix([]byte(strings.Repeat("x", maxPacket+1)), nil, nil); err != nil {
		t.Fatal(err)
	}
	var message controlMessage
	if _, err := receivePacket(right, &message, 0); err == nil {
		t.Fatal("oversized packet accepted")
	}
}

func TestPeerAuthorityIsKernelSocketpairCreator(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	caller, err := authenticatePeer(fds[0])
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		if err == nil || !strings.Contains(err.Error(), "nonzero caller UID and GID") {
			t.Fatalf("root creator not rejected at the credential boundary: %v", err)
		}
		return
	}
	if err != nil || caller.UID != uint32(os.Geteuid()) || caller.GID != uint32(os.Getegid()) {
		t.Fatalf("identity did not come from kernel: %+v %v", caller, err)
	}
}

func TestCommandStdinEOFIsNotLifelineEOF(t *testing.T) {
	left, right := testConnections(t)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	_ = monitorCaller(ctx, right, cancel)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	_ = write.Close()
	var data [1]byte
	if _, err := read.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("not an ordinary stdin EOF: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("ordinary stdin EOF canceled session")
	}
	_ = left.Close()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("private control EOF did not cancel session")
	}
}

func TestValidateInitialRejectsRequestsWithWrongStreamCount(t *testing.T) {
	message := controlMessage{Version: 1, Kind: "run", Request: &wireRequest{Config: config.Default(), Command: []string{"bash"}, Import: true, Export: true}}
	if err := validateInitial(message, make([]*os.File, 4)); err == nil {
		t.Fatal("missing import/export descriptor accepted")
	}
	if err := validateInitial(message, make([]*os.File, 5)); err != nil {
		t.Fatal(err)
	}
	message.Kind, message.Target, message.Request = "cleanup", "0123456789abcdef0123456789abcdef", nil
	if err := validateInitial(message, nil); err != nil {
		t.Fatal(err)
	}
	message.ID = "forged authority"
	if err := validateInitial(message, nil); err == nil {
		t.Fatal("unexpected authority field accepted")
	}
}
