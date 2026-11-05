//go:build linux && amd64

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"unicode/utf8"
	"unsafe"

	"github.com/Lfardell1/Soteria/internal/config"
	"golang.org/x/sys/unix"
)

const (
	protocolVersion = 1
	maxPacket       = 64 << 10
	maxDescriptors  = 8
)

// There is deliberately no UID, GID, host pathname, environment, or root argv
// in the public request. Authority comes exclusively from SO_PEERCRED.
type wireRequest struct {
	Config      config.Config `json:"config"`
	Command     []string      `json:"command"`
	Interactive bool          `json:"interactive"`
	Import      bool          `json:"import"`
	Export      bool          `json:"export"`
	Terminal    string        `json:"terminal,omitempty"`
}

func (r wireRequest) validate() error {
	if err := (Request{Config: r.Config, Command: r.Command, Interactive: r.Interactive}).Validate(); err != nil {
		return err
	}
	if r.Terminal != safeTerminal(r.Terminal) {
		return errors.New("invalid terminal type")
	}
	return nil
}

type controlMessage struct {
	Version   int          `json:"version"`
	Kind      string       `json:"kind"`
	Request   *wireRequest `json:"request,omitempty"`
	Target    string       `json:"target,omitempty"`
	ID        string       `json:"id,omitempty"`
	Phase     string       `json:"phase,omitempty"`
	Text      string       `json:"text,omitempty"`
	Code      int          `json:"code,omitempty"`
	Signal    int          `json:"signal,omitempty"`
	Cancelled bool         `json:"cancelled,omitempty"`
}

type identity struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

func authenticatePeer(fd int) (identity, error) {
	typeID, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typeID != unix.SOCK_SEQPACKET {
		return identity{}, errors.New("control stdin must remain the AF_UNIX SOCK_SEQPACKET socketpair; sudo PTY/I/O policies that replace stdin are unsupported")
	}
	for _, operation := range []uintptr{unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME} {
		if err := requireUnnamedUnix(fd, operation); err != nil {
			return identity{}, err
		}
	}
	credentials, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return identity{}, fmt.Errorf("authenticate socketpair creator: %w", err)
	}
	if credentials.Pid <= 0 || credentials.Uid == 0 || credentials.Gid == 0 || credentials.Uid == ^uint32(0) || credentials.Gid == ^uint32(0) {
		return identity{}, errors.New("socketpair creator must have nonzero caller UID and GID; do not run the frontend with sudo")
	}
	return identity{UID: credentials.Uid, GID: credentials.Gid}, nil
}

func requireUnnamedUnix(fd int, operation uintptr) error {
	// Some x/sys versions collapse both an unnamed socketpair and an empty
	// abstract socket name to "@". Keep the kernel's sockaddr length: exactly
	// sa_family_t, without even an abstract-name NUL, proves an unnamed endpoint.
	var address unix.RawSockaddrUnix
	length := uint32(unix.SizeofSockaddrUnix)
	_, _, errno := unix.Syscall(operation, uintptr(fd), uintptr(unsafe.Pointer(&address)), uintptr(unsafe.Pointer(&length)))
	if errno != 0 {
		return fmt.Errorf("inspect Unix socketpair address: %w", errno)
	}
	if address.Family != unix.AF_UNIX || length != uint32(unsafe.Sizeof(address.Family)) {
		return errors.New("control endpoints must be an unnamed AF_UNIX socketpair")
	}
	return nil
}

func socketPair() (*net.UnixConn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create private control socketpair: %w", err)
	}
	local := os.NewFile(uintptr(fds[0]), "session control")
	remote := os.NewFile(uintptr(fds[1]), "session peer")
	connection, err := net.FileConn(local)
	err = errors.Join(err, local.Close())
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, nil, errors.Join(err, remote.Close())
	}
	return connection.(*net.UnixConn), remote, nil
}

func connectionFromFile(file *os.File) (*net.UnixConn, error) {
	connection, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("expected a Unix control socket")
	}
	return unixConnection, nil
}

// packetWriter serializes messages; SOCK_SEQPACKET keeps data and SCM_RIGHTS
// together, including when the one-shot starter and worker share an endpoint.
type packetWriter struct {
	connection *net.UnixConn
	mu         sync.Mutex
}

func (w *packetWriter) send(value any, files ...*os.File) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxPacket || len(files) > maxDescriptors {
		return errors.New("control packet exceeds protocol bounds")
	}
	var rights []byte
	if len(files) != 0 {
		fds := make([]int, len(files))
		for i, file := range files {
			if file == nil {
				return errors.New("nil control descriptor")
			}
			fds[i] = int(file.Fd())
		}
		rights = unix.UnixRights(fds...)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	n, oob, err := w.connection.WriteMsgUnix(data, rights, nil)
	if err == nil && (n != len(data) || oob != len(rights)) {
		err = io.ErrShortWrite
	}
	return err
}

func receivePacket(connection *net.UnixConn, value any, expectedFDs int) (files []*os.File, err error) {
	data := make([]byte, maxPacket+1)
	oob := make([]byte, unix.CmsgSpace(maxDescriptors*4))
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var n, oobN, flags int
	var receiveErr error
	err = raw.Read(func(fd uintptr) bool {
		n, oobN, flags, _, receiveErr = unix.Recvmsg(int(fd), data, oob, unix.MSG_CMSG_CLOEXEC)
		return !errors.Is(receiveErr, unix.EAGAIN) && !errors.Is(receiveErr, unix.EWOULDBLOCK)
	})
	if err = errors.Join(err, receiveErr); err != nil {
		return nil, err
	}
	// Even rejected/truncated messages can carry descriptors. Close all of them.
	defer func() {
		if err != nil {
			closeFiles(files)
			files = nil
		}
	}()
	messages, err := unix.ParseSocketControlMessage(oob[:oobN])
	if err != nil {
		return nil, fmt.Errorf("parse control descriptors: %w", err)
	}
	unexpectedAncillary := false
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			unexpectedAncillary = true
			continue
		}
		fds, parseErr := unix.ParseUnixRights(&message)
		if parseErr != nil {
			return files, parseErr
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "private session descriptor"))
		}
	}
	if unexpectedAncillary {
		return files, errors.New("unexpected ancillary control data")
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n > maxPacket || len(files) > maxDescriptors {
		return files, errors.New("truncated or oversized control packet")
	}
	if n == 0 {
		return files, io.EOF
	}
	if expectedFDs >= 0 && len(files) != expectedFDs {
		return files, fmt.Errorf("unexpected descriptor count: got %d, need %d", len(files), expectedFDs)
	}
	if err := strictJSON(data[:n], value); err != nil {
		return files, fmt.Errorf("invalid control packet: %w", err)
	}
	return files, nil
}

func strictJSON(data []byte, value any) error {
	if !utf8.Valid(data) {
		return errors.New("JSON is not UTF-8")
	}
	check := json.NewDecoder(bytes.NewReader(data))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting exceeds 16")
		}
		token, err := check.Token()
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("null is not permitted")
		}
		switch token {
		case json.Delim('{'):
			seen := make(map[string]bool)
			for check.More() {
				key, err := check.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate JSON field")
				}
				// Wire names are deliberately lowercase, including nested config.
				for _, c := range name {
					if c >= 'A' && c <= 'Z' {
						return errors.New("incorrectly cased JSON field")
					}
				}
				seen[name] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			_, err = check.Token()
			return err
		case json.Delim('['):
			for check.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			_, err = check.Token()
			return err
		default:
			if _, ok := token.(json.Delim); ok {
				return errors.New("unexpected JSON delimiter")
			}
			return nil
		}
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := check.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func closeFiles(files []*os.File) error {
	var result error
	for _, file := range files {
		if file != nil {
			result = errors.Join(result, file.Close())
		}
	}
	return result
}

func safeTerminal(name string) string {
	if name == "" {
		return ""
	}
	if len(name) > 64 {
		return "xterm-256color"
	}
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '+') {
			return "xterm-256color"
		}
	}
	return name
}

// A cleanup failure joined with cancellation must remain infrastructure failure.
func onlyCanceled(err error) bool {
	if err == nil {
		return false
	}
	if err == context.Canceled {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyCanceled(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyCanceled(wrapped.Unwrap())
	}
	return false
}
