//go:build linux && amd64

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const relayPollMilliseconds = 50

// Pipes and terminals are reopened with an independent open-file description.
// dup followed by F_SETFL would also change the caller's O_NONBLOCK flag.
// Regular files keep their shared offset; sockets use per-call MSG_DONTWAIT.
type relayFD struct {
	fd     int
	socket bool
	pty    bool
	once   sync.Once
}

func (f *relayFD) close() {
	if f != nil {
		f.once.Do(func() { _ = unix.Close(f.fd) })
	}
}

func duplicate(file *os.File) (int, error) {
	if file == nil {
		return -1, errors.New("missing standard stream")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	var inner error
	err = raw.Control(func(n uintptr) { fd, inner = unix.FcntlInt(n, unix.F_DUPFD_CLOEXEC, 3) })
	return fd, errors.Join(err, inner)
}

func hostRelay(file *os.File, write bool) (_ *relayFD, err error) {
	pinned, err := duplicate(file)
	if err != nil {
		return nil, err
	}
	defer func() {
		if pinned >= 0 {
			_ = unix.Close(pinned)
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(pinned, &st); err != nil {
		return nil, err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFSOCK:
		fd := pinned
		pinned = -1
		return &relayFD{fd: fd, socket: st.Mode&unix.S_IFMT == unix.S_IFSOCK}, nil
	case unix.S_IFIFO, unix.S_IFCHR:
		if st.Mode&unix.S_IFMT == unix.S_IFCHR {
			if _, err := unix.IoctlGetInt(pinned, unix.TIOCGPTN); err == nil {
				return nil, errors.New("caller standard streams must not be PTY masters; use the terminal slave")
			}
		}
		flags := unix.O_RDONLY
		if write {
			flags = unix.O_WRONLY
		}
		fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pinned), flags|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
		if err != nil {
			return nil, fmt.Errorf("open independent standard-stream descriptor: %w", err)
		}
		return &relayFD{fd: fd}, nil
	default:
		return nil, errors.New("standard stream must be a regular file, pipe, socket or terminal device")
	}
}

func takeRelay(file *os.File) (*relayFD, error) {
	fd, err := duplicate(file)
	closeErr := file.Close()
	if err == nil && closeErr == nil {
		err = unix.SetNonblock(fd, true)
	}
	if err != nil || closeErr != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return nil, errors.Join(err, closeErr)
	}
	return &relayFD{fd: fd}, nil
}

func waitFD(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(poll, relayPollMilliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			if poll[0].Revents&unix.POLLNVAL != 0 {
				return unix.EBADF
			}
			return nil
		}
	}
}

func copyRelay(ctx context.Context, dst, src *relayFD) error {
	buffer := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var n int
		var err error
		if src.socket {
			n, _, err = unix.Recvfrom(src.fd, buffer, unix.MSG_DONTWAIT)
		} else {
			n, err = unix.Read(src.fd, buffer)
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			if err := waitFD(ctx, src.fd, unix.POLLIN); err != nil {
				return err
			}
			continue
		}
		if src.pty && errors.Is(err, unix.EIO) {
			return nil // Linux PTY masters report EIO after the last slave closes.
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if err := writeRelay(ctx, dst, buffer[:n]); err != nil {
			return err
		}
	}
}

func writeRelay(ctx context.Context, dst *relayFD, pending []byte) error {
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		var n int
		var err error
		if dst.socket {
			n, err = unix.SendmsgN(dst.fd, pending, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
		} else {
			n, err = unix.Write(dst.fd, pending)
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			if err := waitFD(ctx, dst.fd, unix.POLLOUT); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		pending = pending[n:]
	}
	return nil
}

func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return false
	}
	isTTY := false
	err = raw.Control(func(fd uintptr) { isTTY = term.IsTerminal(int(fd)) })
	return err == nil && isTTY
}

type commandIO struct {
	files       []*os.File
	hostIn      *relayFD
	hostOut     *relayFD
	hostErr     *relayFD
	input       *relayFD
	output      *relayFD
	errorOutput *relayFD
	terminal    bool
	caller      *os.File
	restore     func() error
}

func prepareIO(streams Streams, tty bool) (_ *commandIO, err error) {
	c := &commandIO{terminal: tty, caller: streams.In}
	defer func() {
		if err != nil {
			_ = c.close()
		}
	}()
	c.hostIn, err = hostRelay(streams.In, false)
	if err != nil {
		return nil, err
	}
	c.hostOut, err = hostRelay(streams.Out, true)
	if err != nil {
		return nil, err
	}
	if tty {
		master, slave, err := pty.Open()
		if err != nil {
			return nil, fmt.Errorf("allocate fresh PTY: %w", err)
		}
		c.files = []*os.File{slave, slave, slave}
		c.input, err = takeRelay(master)
		if err != nil {
			return nil, err
		}
		c.input.pty = true
		c.output = c.input
		if _, _, err := c.resize(); err != nil {
			return nil, err
		}
		raw, err := streams.In.SyscallConn()
		if err != nil {
			return nil, err
		}
		var state *term.State
		var inner error
		err = raw.Control(func(fd uintptr) { state, inner = term.MakeRaw(int(fd)) })
		if err != nil || inner != nil {
			return nil, errors.Join(err, inner)
		}
		c.restore = func() error {
			var inner error
			err := raw.Control(func(fd uintptr) { inner = term.Restore(int(fd), state) })
			return errors.Join(err, inner)
		}
		return c, nil
	}
	c.hostErr, err = hostRelay(streams.Err, true)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 3; i++ {
		read, write, pipeErr := os.Pipe()
		if pipeErr != nil {
			return nil, pipeErr
		}
		child, local := write, read
		if i == 0 {
			child, local = read, write
		}
		c.files = append(c.files, child)
		fd, relayErr := takeRelay(local)
		if relayErr != nil {
			return nil, relayErr
		}
		switch i {
		case 0:
			c.input = fd
		case 1:
			c.output = fd
		case 2:
			c.errorOutput = fd
		}
	}
	return c, nil
}

func (c *commandIO) resize() (uint16, uint16, error) {
	if !c.terminal {
		return 0, 0, nil
	}
	raw, err := c.caller.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var size *unix.Winsize
	var inner error
	err = raw.Control(func(fd uintptr) { size, inner = unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ) })
	if err != nil || inner != nil {
		return 0, 0, errors.Join(err, inner)
	}
	if size.Row == 0 {
		size.Row = 24
	}
	if size.Col == 0 {
		size.Col = 80
	}
	if err := unix.IoctlSetWinsize(c.input.fd, unix.TIOCSWINSZ, size); err != nil {
		return 0, 0, err
	}
	return size.Row, size.Col, nil
}

func (c *commandIO) closeFiles() {
	for _, file := range c.files {
		_ = file.Close()
	}
	c.files = nil
}

func (c *commandIO) close() error {
	c.closeFiles()
	for _, fd := range []*relayFD{c.hostIn, c.hostOut, c.hostErr, c.input, c.output, c.errorOutput} {
		fd.close()
	}
	if c.restore != nil {
		restore := c.restore
		c.restore = nil
		return restore()
	}
	return nil
}

type relayWorkers struct {
	stopInput  context.CancelFunc
	stopOutput context.CancelFunc
	inputDone  chan error
	outputDone []chan error
	failures   chan error
}

func (c *commandIO) start(ctx context.Context) *relayWorkers {
	inputCtx, stopInput := context.WithCancel(ctx)
	outputCtx, stopOutput := context.WithCancel(ctx)
	w := &relayWorkers{stopInput: stopInput, stopOutput: stopOutput, inputDone: make(chan error, 1), failures: make(chan error, 3)}
	go func() {
		err := copyRelay(inputCtx, c.input, c.hostIn)
		if !c.terminal {
			c.input.close() // Workload stdin EOF does not touch the control lifeline.
		}
		if inputCtx.Err() != nil || errors.Is(err, unix.EPIPE) || c.terminal && errors.Is(err, unix.EIO) {
			err = nil
		}
		w.inputDone <- err
		if err != nil {
			w.failures <- fmt.Errorf("stdin relay: %w", err)
		}
	}()
	outputs := [][2]*relayFD{{c.hostOut, c.output}}
	if !c.terminal {
		outputs = append(outputs, [2]*relayFD{c.hostErr, c.errorOutput})
	}
	for _, pair := range outputs {
		done := make(chan error, 1)
		w.outputDone = append(w.outputDone, done)
		go func() {
			err := copyRelay(outputCtx, pair[0], pair[1])
			if outputCtx.Err() != nil {
				err = nil
			}
			done <- err
			if err != nil {
				w.failures <- fmt.Errorf("output relay: %w", err)
			}
		}()
	}
	return w
}

// finish stops stdin immediately, but permits a bounded binary-safe output
// drain after Result. It then cancels polling relays before closing descriptors.
func (w *relayWorkers) finish(drain, stop time.Duration) error {
	w.stopInput()
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), drain)
	defer cancelDrain()
	var result error
	for _, done := range w.outputDone {
		select {
		case err := <-done:
			result = errors.Join(result, err)
		case <-drainCtx.Done():
			result = errors.Join(result, errors.New("output drain deadline exceeded"))
			w.stopOutput()
			select {
			case <-done:
			case <-time.After(stop):
				result = errors.Join(result, errors.New("output relay did not stop"))
			}
		}
	}
	w.stopOutput()
	select {
	case err := <-w.inputDone:
		result = errors.Join(result, err)
	case <-time.After(stop):
		result = errors.Join(result, errors.New("stdin relay did not stop"))
	}
	return result
}
