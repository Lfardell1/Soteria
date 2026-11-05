//go:build linux && amd64

// Package entrypoint verifies the fixed credential transition and replaces
// itself with the workload. It is not a supervisor or a PID-namespace init.
package entrypoint

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const Path = "/usr/libexec/soteria-entry"

// The proof socket is fresh for each launch. Successful exec closes it; a
// returned exec error sends ProofFailed instead. The parent authenticates each
// packet with kernel SCM_CREDENTIALS, not an application-supplied PID.
const (
	ProofReady  byte = 'R'
	ProofFailed byte = 'F'
	ProofAccept byte = 'A'
)

// Environment is also used before the root wrappers execute, so loader and
// interpreter settings from the host cannot affect setsid or setpriv.
func Environment(tty bool) []string {
	terminal := "dumb"
	if tty {
		terminal = "xterm-256color"
	}
	return []string{
		"PATH=/usr/bin:/bin", "HOME=/home/workspace", "USER=workspace", "LOGNAME=workspace",
		"SHELL=/bin/bash", "LANG=C.UTF-8", "TERM=" + terminal, "TMPDIR=/tmp",
		"XDG_RUNTIME_DIR=/run", "XDG_CACHE_HOME=/var/cache",
		"XDG_CONFIG_HOME=/home/workspace/.config", "XDG_DATA_HOME=/home/workspace/.local/share",
		"HISTFILE=/dev/null", "PYTHONHISTFILE=/dev/null",
	}
}

// Run accepts only UID GID -- EXEC ARG..., after setpriv has already dropped
// privileges. On success it does not return. FD 3 is the sole launch-proof
// socket; no proof, namespace, or control descriptor survives workload exec.
func Run(args []string) (resultErr error) {
	uid, gid, argv, err := parseArguments(args)
	if err != nil {
		return err
	}
	if err := requireProofSocket(3); err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			_, _ = unix.SendmsgN(3, []byte{ProofFailed}, nil, nil, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT)
		}
	}()
	if err := unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("seal inherited descriptors: %w", err)
	}
	status, err := readBounded("/proc/self/status", 64<<10)
	if err != nil {
		return err
	}
	if err := verifyStatus(string(status), uid, gid); err != nil {
		return err
	}
	ruid, euid, suid := unix.Getresuid()
	rgid, egid, sgid := unix.Getresgid()
	if ruid != int(uid) || euid != int(uid) || suid != int(uid) || rgid != int(gid) || egid != int(gid) || sgid != int(gid) {
		return errors.New("entrypoint credential transition is incomplete")
	}
	groups, err := unix.Getgroups()
	if err != nil || len(groups) != 0 {
		return errors.New("entrypoint retained supplementary groups")
	}
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || nnp != 1 {
		return errors.New("entrypoint requires no_new_privs")
	}
	if err := verifyFilesystem(uid, gid); err != nil {
		return err
	}
	tty, err := verifyStdio(uid)
	if err != nil {
		return err
	}
	if err := unix.SetsockoptTimeval(3, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		return err
	}
	if n, err := unix.SendmsgN(3, []byte{ProofReady}, nil, nil, unix.MSG_NOSIGNAL); err != nil || n != 1 {
		return errors.Join(errors.New("send credential and filesystem proof"), err)
	}
	var acknowledgement [2]byte
	n, _, flags, _, err := unix.Recvmsg(3, acknowledgement[:], nil, unix.MSG_CMSG_CLOEXEC)
	if err != nil || n != 1 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || acknowledgement[0] != ProofAccept {
		return errors.New("root owner did not accept the exact launch proof")
	}
	if err := unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("seal workload descriptor whitelist: %w", err)
	}
	if err := unix.Exec(argv[0], argv, Environment(tty)); err != nil {
		return fmt.Errorf("execute curated workload: %w", err)
	}
	return errors.New("exec unexpectedly returned")
}

func parseArguments(args []string) (uint32, uint32, []string, error) {
	if len(args) < 4 || args[2] != "--" || len(args) > 259 {
		return 0, 0, nil, errors.New("entrypoint requires UID GID -- EXEC ARG...")
	}
	identities := [2]uint32{}
	for i := range identities {
		n, err := strconv.ParseUint(args[i], 10, 32)
		if err != nil || n == 0 || n == uint64(^uint32(0)) || strconv.FormatUint(n, 10) != args[i] {
			return 0, 0, nil, errors.New("entrypoint requires canonical nonzero workload identities")
		}
		identities[i] = uint32(n)
	}
	name := args[3]
	if path.Clean(name) != name || path.Dir(name) != "/bin" && path.Dir(name) != "/usr/bin" || strings.HasPrefix(path.Base(name), "-") {
		return 0, 0, nil, errors.New("entrypoint requires an absolute curated executable")
	}
	bytes := 0
	for _, arg := range args[3:] {
		bytes += len(arg) + 1
		if !utf8.ValidString(arg) || strings.IndexByte(arg, 0) >= 0 || bytes > 32<<10 {
			return 0, 0, nil, errors.New("invalid workload argument encoding or size")
		}
	}
	return identities[0], identities[1], args[3:], nil
}

func verifyStatus(status string, uid, gid uint32) error {
	fields := make(map[string][]string)
	for _, line := range strings.Split(status, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if _, exists := fields[parts[0]]; exists {
			return errors.New("duplicate process status evidence")
		}
		fields[parts[0]] = parts[1:]
	}
	for _, identity := range []struct {
		name string
		id   uint32
	}{{"Uid:", uid}, {"Gid:", gid}} {
		values := fields[identity.name]
		if len(values) != 4 || identity.id == 0 || identity.id == ^uint32(0) {
			return errors.New("missing non-root real/effective/saved/filesystem identity evidence")
		}
		for _, value := range values {
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil || uint32(n) != identity.id {
				return errors.New("real/effective/saved/filesystem identities do not match the caller")
			}
		}
	}
	if values := fields["Groups:"]; len(values) != 0 {
		return errors.New("supplementary groups are not empty")
	}
	if _, exists := fields["Groups:"]; !exists {
		return errors.New("missing supplementary-group evidence")
	}
	for _, name := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
		values := fields[name]
		if len(values) != 1 {
			return errors.New("missing capability-set evidence")
		}
		n, err := strconv.ParseUint(values[0], 16, 64)
		if err != nil || n != 0 {
			return errors.New("entrypoint retained capabilities, including bounding or ambient capabilities")
		}
	}
	if values := fields["NoNewPrivs:"]; len(values) != 1 || values[0] != "1" {
		return errors.New("missing no_new_privs evidence")
	}
	return nil
}

func verifyFilesystem(uid, gid uint32) error {
	var root unix.Statfs_t
	if err := unix.Statfs("/", &root); err != nil || root.Flags&unix.ST_RDONLY == 0 {
		return errors.New("workload root is not read-only")
	}
	for _, name := range []string{"/home/workspace", "/work", "/tmp", "/run", "/var"} {
		fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open required writable tmpfs %s: %w", name, err)
		}
		var st unix.Stat_t
		var fs unix.Statfs_t
		statErr := unix.Fstat(fd, &st)
		fsErr := unix.Fstatfs(fd, &fs)
		closeErr := unix.Close(fd)
		if err := errors.Join(statErr, fsErr, closeErr); err != nil {
			return err
		}
		if err := verifyWritable(name, st, fs, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func verifyWritable(name string, st unix.Stat_t, fs unix.Statfs_t, uid, gid uint32) error {
	mode := uint32(0o700)
	if name == "/tmp" {
		mode = 0o1777
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Gid != gid || st.Mode&0o7777 != mode {
		return fmt.Errorf("required writable path %s is not the caller-owned private directory", name)
	}
	if fs.Type != unix.TMPFS_MAGIC || fs.Flags&(unix.ST_NOSUID|unix.ST_NODEV) != unix.ST_NOSUID|unix.ST_NODEV || fs.Flags&unix.ST_RDONLY != 0 {
		return fmt.Errorf("required writable path %s is not writable nosuid,nodev tmpfs", name)
	}
	return nil
}

func verifyStdio(uid uint32) (bool, error) {
	_, terminalErr := unix.IoctlGetTermios(0, unix.TCGETS)
	tty := terminalErr == nil
	if terminalErr != nil && !errors.Is(terminalErr, unix.ENOTTY) {
		return false, errors.New("cannot inspect workload terminal")
	}
	var device uint64
	for fd := 0; fd < 3; fd++ {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return false, err
		}
		if !tty {
			if st.Mode&unix.S_IFMT != unix.S_IFIFO {
				return false, errors.New("headless workload stdio must contain only explicit pipes")
			}
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Uid != uid || fd != 0 && st.Rdev != device {
			return false, errors.New("interactive workload stdio must be one caller-owned PTY slave")
		}
		device = st.Rdev
		if _, err := unix.IoctlGetInt(fd, unix.TIOCGPTN); err == nil {
			return false, errors.New("PTY masters must not reach the workload")
		}
	}
	if tty {
		sid, err := unix.Getsid(0)
		ttySID, ttyErr := unix.IoctlGetInt(0, unix.TIOCGSID)
		group, groupErr := unix.IoctlGetInt(0, unix.TIOCGPGRP)
		if err != nil || ttyErr != nil || groupErr != nil || sid != os.Getpid() || ttySID != sid || group != os.Getpid() {
			return false, errors.New("fixed setsid entrypoint did not acquire the fresh controlling terminal")
		}
	}
	return tty, nil
}

func requireProofSocket(fd int) error {
	typeID, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typeID != unix.SOCK_SEQPACKET {
		return errors.New("entrypoint requires its private sequenced-packet proof socket on fd 3")
	}
	if domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN); err != nil || domain != unix.AF_UNIX {
		return errors.New("entrypoint proof socket must be local")
	}
	peer, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || peer.Uid != 0 || peer.Gid != 0 {
		return errors.New("entrypoint proof socket lacks its root owner")
	}
	return nil
}

// ReceiveProof atomically applies CLOEXEC to any received descriptors, rejects
// and closes them, and requires exactly one kernel credential record.
func ReceiveProof(connection *net.UnixConn) (byte, *unix.Ucred, error) {
	data := make([]byte, 2)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(4*8))
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, nil, err
	}
	var n, oobN, flags int
	var readErr error
	err = raw.Read(func(fd uintptr) bool {
		n, oobN, flags, _, readErr = unix.Recvmsg(int(fd), data, oob, unix.MSG_CMSG_CLOEXEC)
		return !errors.Is(readErr, unix.EAGAIN) && !errors.Is(readErr, unix.EWOULDBLOCK)
	})
	if err := errors.Join(err, readErr); err != nil {
		return 0, nil, err
	}
	var credentials *unix.Ucred
	controls, parseErr := unix.ParseSocketControlMessage(oob[:oobN])
	for _, control := range controls {
		switch {
		case control.Header.Level == unix.SOL_SOCKET && control.Header.Type == unix.SCM_CREDENTIALS && credentials == nil:
			credentials, err = unix.ParseUnixCredentials(&control)
			parseErr = errors.Join(parseErr, err)
		case control.Header.Level == unix.SOL_SOCKET && control.Header.Type == unix.SCM_RIGHTS:
			fds, err := unix.ParseUnixRights(&control)
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
			parseErr = errors.Join(parseErr, err, errors.New("unexpected proof descriptor"))
		default:
			parseErr = errors.Join(parseErr, errors.New("unexpected proof ancillary data"))
		}
	}
	if parseErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return 0, nil, errors.New("invalid or truncated launch proof")
	}
	if n == 0 {
		return 0, nil, io.EOF
	}
	if n != 1 || credentials == nil || credentials.Pid <= 0 || data[0] != ProofReady && data[0] != ProofFailed {
		return 0, nil, errors.New("launch proof lacks exact kernel credentials and stage")
	}
	return data[0], credentials, nil
}

// AcceptProof releases only the verified payload PID from its pre-exec wait.
func AcceptProof(connection *net.UnixConn) error {
	if err := connection.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	n, err := connection.Write([]byte{ProofAccept})
	if err == nil && n != 1 {
		err = io.ErrShortWrite
	}
	return err
}

func readBounded(name string, limit int64) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("kernel process evidence exceeds its bound")
	}
	return data, nil
}
