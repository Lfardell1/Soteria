//go:build linux

// Package protocol is the bounded, private transport between the frontend,
// authorized starter, supervisor, and worker. It is not a remote API.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Lfardell1/Soteria/internal/config"
	"golang.org/x/sys/unix"
)

const (
	Version = 1
	MaxPacket = 64 << 10
	MaxFiles = 8
	StarterPath = "/usr/libexec/soteria/soteria-starter"
	EnginePath = "/usr/libexec/soteria/soteria-engine"
	EntryPath = "/usr/libexec/soteria-entry"
	BubblewrapPath = "/usr/bin/bwrap"
	SetupTimeout = 45 * time.Second
	ShutdownTimeout = 10 * time.Second
)

type Facts struct {
	Filesystem string `json:"filesystem"`
	AnonymousSwap string `json:"anonymous_memory_swap"`
	TmpfsSwap string `json:"tmpfs_swap"`
	DumpPolicy string `json:"dump_policy"`
	Network string `json:"network"`
	Cleanup string `json:"cleanup"`
	RuntimeDigest string `json:"runtime_digest,omitempty"`
}

type Result struct {
	ChildStarted bool `json:"child_started"`
	ChildExit int `json:"child_exit"`
	Error string `json:"error,omitempty"`
	CleanupError string `json:"cleanup_error,omitempty"`
	Facts Facts `json:"facts"`
}

func (r Result) ExitCode() int {
	if r.Error != "" || r.CleanupError != "" || !r.ChildStarted || r.ChildExit < 0 || r.ChildExit > 255 {
		return 125
	}
	return r.ChildExit
}

// Message has no host transfer paths or caller-supplied identity in the public
// start/run protocol. UID/GID and Link are accepted only on the private worker
// channel, from the authenticated supervisor.
type Message struct {
	Version int `json:"version"`
	Type string `json:"type"`
	Config *config.Config `json:"config,omitempty"`
	Argv []string `json:"argv,omitempty"`
	TTY bool `json:"tty,omitempty"`
	Export bool `json:"export,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Phase string `json:"phase,omitempty"`
	Error string `json:"error,omitempty"`
	Warning string `json:"warning,omitempty"`
	Facts *Facts `json:"facts,omitempty"`
	Result *Result `json:"result,omitempty"`
	Signal int `json:"signal,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	UID uint32 `json:"uid,omitempty"`
	GID uint32 `json:"gid,omitempty"`
	Link string `json:"link,omitempty"`
}

type Conn struct {
	conn *net.UnixConn
	send sync.Mutex
}

func Pair() (*Conn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil { return nil, nil, err }
	left := os.NewFile(uintptr(fds[0]), "soteria-control")
	right := os.NewFile(uintptr(fds[1]), "soteria-peer")
	conn, err := FromFile(left)
	closeErr := left.Close()
	if err != nil || closeErr != nil {
		if conn != nil { _ = conn.Close() }
		_ = right.Close()
		return nil, nil, errors.Join(err, closeErr)
	}
	return conn, right, nil
}

func FromFile(file *os.File) (*Conn, error) {
	if file == nil { return nil, errors.New("missing control descriptor") }
	typeID, err := unix.GetsockoptInt(int(file.Fd()), unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typeID != unix.SOCK_SEQPACKET { return nil, errors.New("control descriptor must be a UNIX sequenced-packet socket") }
	addr, err := unix.Getsockname(int(file.Fd()))
	if err != nil { return nil, err }
	if _, ok := addr.(*unix.SockaddrUnix); !ok { return nil, errors.New("control descriptor must use AF_UNIX") }
	c, err := net.FileConn(file)
	if err != nil { return nil, err }
	u, ok := c.(*net.UnixConn)
	if !ok { _ = c.Close(); return nil, errors.New("invalid control transport") }
	return &Conn{conn:u}, nil
}

func (c *Conn) Close() error { return c.conn.Close() }
func (c *Conn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

func (c *Conn) File() (*os.File, error) { return c.conn.File() }

func (c *Conn) Peer() (*unix.Ucred, error) {
	var credentials *unix.Ucred
	var inner error
	raw, err := c.conn.SyscallConn()
	if err != nil { return nil, err }
	err = raw.Control(func(fd uintptr) { credentials, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	return credentials, errors.Join(err,inner)
}

func (c *Conn) Send(m Message, files ...*os.File) error {
	m.Version = Version
	if len(files) > MaxFiles { return errors.New("too many control descriptors") }
	data, err := json.Marshal(m)
	if err != nil { return err }
	if len(data) > MaxPacket { return errors.New("control message exceeds 64 KiB") }
	var rights []byte
	if len(files) != 0 {
		fds := make([]int,len(files))
		for i,file := range files { if file == nil { return errors.New("nil control descriptor") }; fds[i] = int(file.Fd()) }
		rights = unix.UnixRights(fds...)
	}
	c.send.Lock()
	defer c.send.Unlock()
	// A disconnected or non-reading frontend must never stall cleanup forever.
	if err := c.conn.SetWriteDeadline(time.Now().Add(ShutdownTimeout)); err != nil { return err }
	n,_,err := c.conn.WriteMsgUnix(data,rights,nil)
	if err == nil && n != len(data) { err = io.ErrShortWrite }
	return err
}

func (c *Conn) Receive() (Message, []*os.File, error) {
	data := make([]byte,MaxPacket+1)
	ancillary := make([]byte,unix.CmsgSpace(MaxFiles*4))
	n,oobn,flags,_,err := c.conn.ReadMsgUnix(data,ancillary)
	if err != nil { return Message{},nil,err }
	if n == 0 { return Message{},nil,io.EOF }
	var files []*os.File
	controls,parseErr := unix.ParseSocketControlMessage(ancillary[:oobn])
	if parseErr == nil {
		for _,control := range controls {
			fds,e := unix.ParseUnixRights(&control)
			if e != nil { parseErr = errors.Join(parseErr,e); continue }
			for _,fd := range fds { unix.CloseOnExec(fd); files = append(files,os.NewFile(uintptr(fd),"soteria-received")) }
		}
	}
	if parseErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n > MaxPacket || len(files) > MaxFiles {
		CloseFiles(files)
		return Message{},nil,errors.New("invalid or truncated control packet")
	}
	var m Message
	if err := Decode(data[:n],&m); err != nil { CloseFiles(files); return Message{},nil,err }
	if m.Version != Version || m.Type == "" { CloseFiles(files); return Message{},nil,errors.New("unsupported control protocol version/type") }
	return m,files,nil
}

func CloseFiles(files []*os.File) { for _,f := range files { if f != nil { _ = f.Close() } } }

// Decode rejects duplicate/case-aliased keys and nulls as well as unknown fields.
func Decode(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxPacket || !utf8.Valid(data) { return errors.New("invalid control JSON size/encoding") }
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := uniqueValue(d,0); err != nil { return err }
	if _,err := d.Token(); err != io.EOF { return errors.New("trailing control JSON") }
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil { return errors.New("invalid control JSON fields") }
	return nil
}

func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 12 { return errors.New("control JSON nesting limit") }
	token,err := d.Token()
	if err != nil { return errors.New("invalid control JSON") }
	if token == nil { return errors.New("null control fields are forbidden") }
	delim,ok := token.(json.Delim)
	if !ok { return nil }
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key,err := d.Token(); if err != nil { return err }
			name,ok := key.(string)
			if !ok || name != strings.ToLower(name) || seen[name] { return errors.New("duplicate/noncanonical control key") }
			seen[name] = true
			if err := uniqueValue(d,depth+1); err != nil { return err }
		}
	case '[':
		for d.More() { if err := uniqueValue(d,depth+1); err != nil { return err } }
	default: return errors.New("invalid control JSON delimiter")
	}
	_,err = d.Token()
	return err
}

func ValidateArgv(argv []string) error {
	if len(argv) == 0 || len(argv) > 256 || argv[0] == "" { return errors.New("command requires 1..256 argv entries") }
	n := 0
	for _,arg := range argv { n += len(arg)+1; if strings.ContainsRune(arg,0) { return errors.New("NUL in command argument") } }
	if n > 32<<10 { return errors.New("command argv exceeds 32 KiB") }
	return nil
}

func ValidateSessionID(id string) error {
	if len(id) != 32 { return errors.New("session ID must be 32 lowercase hexadecimal characters") }
	for _,c := range id { if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') { return fmt.Errorf("invalid session ID") } }
	return nil
}
