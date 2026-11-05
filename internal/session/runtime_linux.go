//go:build linux && amd64

package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	installedExecutable  = "/usr/libexec/soteria/soteria"
	bubblewrapExecutable = "/usr/bin/bwrap"
	sudoExecutable       = "/usr/bin/sudo"
	setupTimeout         = 120 * time.Second
	stopTimeout          = 15 * time.Second
	controlTimeout       = 5 * time.Second
	ownerFile            = "owner.json"
	workspaceFile        = "workspace.json"
)

func unitName(id string) string    { return "soteria-" + id + ".service" }
func runtimePath(id string) string { return "/run/soteria-" + id }
func cgroupPath(id string) string  { return "/system.slice/" + unitName(id) }

func randomID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

// Internal must be dispatched before public CLI parsing. These are not public
// root subcommands: every root entry verifies its inherited service/socket context.
func Internal(args []string) (handled bool, code int, err error) {
	if len(args) == 0 || !strings.HasPrefix(args[0], "__") {
		return false, 0, nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	if args[0] == "__transfer" {
		code, err = transferHelper(ctx, args[1:])
		return true, code, err
	}
	if len(args) != 1 {
		return true, InfrastructureFailure, errors.New("internal entrypoints do not accept caller arguments")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return true, InfrastructureFailure, errors.New("internal service entrypoint requires its authorized root context")
	}
	// The only executable sudo or systemd may invoke is the installed admin-owned
	// binary. Running a build from a caller-writable tree as root is unsupported.
	if err := verifyInstalledSelf(); err != nil {
		return true, InfrastructureFailure, err
	}
	switch args[0] {
	case "__start":
		code, err = startService(ctx)
	case "__worker":
		code, err = serviceWorker(ctx)
	case "__namespace":
		code, err = namespaceWorker(ctx)
	case "__cleanup":
		err = serviceCleanup(ctx)
		if err != nil {
			code = InfrastructureFailure
		}
	default:
		code, err = InfrastructureFailure, errors.New("unknown internal entrypoint")
	}
	return true, code, err
}

func verifyInstalledSelf() error {
	name, err := os.Executable()
	if err != nil || name != installedExecutable {
		return errors.New("privileged execution requires the installed /usr/libexec/soteria/soteria; no build-tree fallback")
	}
	return verifyRootExecutable(installedExecutable, false)
}

// Resolve distro /bin aliases only for fixed system tools. The privileged
// Soteria executable itself must be a real regular file at the exact fixed path.
func verifyRootExecutable(name string, systemAlias bool) error {
	// Check the original lookup path as well as a distro alias target. A safe
	// target is not sufficient if an attacker can replace its lexical symlink.
	lookup, err := openRootDirectory(filepath.Dir(name), false)
	if err != nil {
		return fmt.Errorf("untrusted executable lookup directory: %w", err)
	}
	if err := lookup.Close(); err != nil {
		return err
	}
	if systemAlias {
		resolved, err := filepath.EvalSymlinks(name)
		if err != nil {
			return fmt.Errorf("required executable %s is unavailable: %w", name, err)
		}
		name = resolved
	}
	parent, err := openRootDirectory(filepath.Dir(name), false)
	if err != nil {
		return fmt.Errorf("untrusted executable ancestor: %w", err)
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("required executable %s is unavailable: %w", name, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	privilegedBits := uint32(unix.S_ISUID | unix.S_ISGID)
	if systemAlias && name == sudoExecutable {
		privilegedBits = unix.S_ISGID // sudo itself is a packaged authorization tool.
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o022 != 0 || st.Mode&0o111 == 0 || st.Mode&privilegedBits != 0 {
		return fmt.Errorf("required executable %s is not a trusted root-owned executable", name)
	}
	if name != sudoExecutable {
		_, err := unix.Fgetxattr(fd, "security.capability", nil)
		if err == nil || (!errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.EOPNOTSUPP)) {
			return fmt.Errorf("required executable %s must not have file capabilities", name)
		}
	}
	return nil
}

func runtimePrerequisites(workload bool) error {
	if err := verifyRootExecutable(installedExecutable, false); err != nil {
		return err
	}
	if workload {
		if err := verifyRootExecutable(bubblewrapExecutable, true); err != nil {
			return err
		}
	}
	booted, err := openRootDirectory("/run/systemd/system", false)
	if err != nil {
		return errors.New("experimental runtime requires a booted systemd system manager")
	}
	_ = booted.Close()
	busDirectory, err := openRootDirectory("/run/dbus", false)
	if err != nil {
		return fmt.Errorf("experimental runtime requires a trusted system bus directory: %w", err)
	}
	var socket unix.Stat_t
	err = unix.Fstatat(int(busDirectory.Fd()), "system_bus_socket", &socket, unix.AT_SYMLINK_NOFOLLOW)
	closeErr := busDirectory.Close()
	if err != nil || closeErr != nil || socket.Uid != 0 || socket.Gid != 0 || socket.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("experimental runtime requires the root-owned system D-Bus socket with UNIX_FD passing")
	}
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("experimental runtime requires unified cgroup v2 memory and pids controls")
	}
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil || !hasWord(string(controllers), "memory") || !hasWord(string(controllers), "pids") {
		return errors.New("cgroup v2 memory and pids controllers are unavailable")
	}
	return nil
}

func hasWord(text, word string) bool {
	for _, field := range strings.Fields(text) {
		if field == word {
			return true
		}
	}
	return false
}

func openRootDirectory(name string, private bool) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errors.New("root directory path is not clean and absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for _, component := range components {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&0o022 != 0 {
			_ = unix.Close(fd)
			return nil, errors.New("directory ancestor is not root-owned and nonwritable")
		}
		if component == "" {
			continue
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(fd)
		if err != nil || closeErr != nil {
			if err == nil {
				_ = unix.Close(next)
			}
			return nil, errors.Join(err, closeErr)
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&0o022 != 0 || private && st.Mode&0o7777 != 0o700 {
		_ = unix.Close(fd)
		return nil, errors.New("runtime directory must be root:root and mode 0700; ancestors must not be writable by others")
	}
	return os.NewFile(uintptr(fd), name), nil
}

type serviceEnvironment struct {
	ID         string
	Invocation string
	Directory  string
}

func currentService() (serviceEnvironment, error) {
	environment := serviceEnvironment{ID: os.Getenv("SOTERIA_SESSION_ID"), Invocation: os.Getenv("INVOCATION_ID"), Directory: os.Getenv("RUNTIME_DIRECTORY")}
	if !validSessionID(environment.ID) || !validSessionID(environment.Invocation) || environment.Directory != runtimePath(environment.ID) {
		return serviceEnvironment{}, errors.New("missing exact systemd service runtime identity")
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || strings.TrimSpace(string(data)) != "0::"+cgroupPath(environment.ID) {
		return serviceEnvironment{}, errors.New("internal worker is not in its fixed nondelegated systemd service cgroup")
	}
	directory, err := openRootDirectory(environment.Directory, true)
	if err != nil {
		return serviceEnvironment{}, err
	}
	return environment, directory.Close()
}

type ownerRecord struct {
	Version    int      `json:"version"`
	ID         string   `json:"id"`
	Invocation string   `json:"invocation"`
	Caller     identity `json:"caller"`
}

type workspaceRecord struct {
	Name   string `json:"name"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func createRecord(directory *os.File, name string, record any) error {
	data, err := json.Marshal(record)
	if err != nil || len(data) > 4096 {
		return errors.New("invalid bounded ownership record")
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Close())
}

func readRecord(directory *os.File, name string, record any) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 || st.Nlink != 1 || st.Size > 4096 {
		return errors.Join(errors.New("untrusted session ownership record"), file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return err
	}
	if len(data) > 4096 {
		return errors.New("ownership record exceeds its bound")
	}
	return strictJSON(data, record)
}

func readOwner(directory *os.File, id string) (ownerRecord, error) {
	var record ownerRecord
	if err := readRecord(directory, ownerFile, &record); err != nil {
		return ownerRecord{}, err
	}
	if record.Version != 1 || record.ID != id || !validSessionID(record.ID) || !validSessionID(record.Invocation) || record.Caller.UID == 0 || record.Caller.GID == 0 || record.Caller.UID == ^uint32(0) || record.Caller.GID == ^uint32(0) {
		return ownerRecord{}, errors.New("ownership record does not identify this exact non-root session")
	}
	return record, nil
}

func recordWorkspace(directory *os.File, name string) error {
	if !strings.HasPrefix(name, "workspace-") || filepath.Base(name) != name || len(name) > 128 {
		return errors.New("invalid acquired workspace basename")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != 0o700 {
		return errors.New("acquired underlying mountpoint is not a private root directory")
	}
	return createRecord(directory, workspaceFile, workspaceRecord{Name: name, Device: uint64(st.Dev), Inode: st.Ino})
}

// Remove only recorded underlying mountpoints, never mounts from another
// namespace and never recursive trees or a loose name prefix. An acquisition
// crash before recording an inode intentionally leaves an unowned empty directory
// requiring administrator inspection rather than guessing cleanup authority.
func removeRuntime(directory *os.File, id string, owner *ownerRecord) error {
	var workspace workspaceRecord
	err := readRecord(directory, workspaceFile, &workspace)
	hasWorkspace := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if hasWorkspace && (filepath.Base(workspace.Name) != workspace.Name || !strings.HasPrefix(workspace.Name, "workspace-") || workspace.Inode == 0) {
		return errors.New("invalid exact workspace ownership record")
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if owner != nil && entry.Name() == ownerFile || hasWorkspace && (entry.Name() == workspaceFile || entry.Name() == workspace.Name) {
			continue
		}
		return fmt.Errorf("refusing cleanup of unrecorded runtime entry %q", entry.Name())
	}
	if hasWorkspace {
		var st unix.Stat_t
		statErr := unix.Fstatat(int(directory.Fd()), workspace.Name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if statErr == nil {
			if st.Dev != workspace.Device || st.Ino != workspace.Inode || st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != 0o700 {
				return errors.New("refusing cleanup of replaced workspace mountpoint")
			}
			if err := unix.Unlinkat(int(directory.Fd()), workspace.Name, unix.AT_REMOVEDIR); err != nil {
				return fmt.Errorf("remove recorded empty mountpoint (no lazy unmount): %w", err)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		if err := unix.Unlinkat(int(directory.Fd()), workspaceFile, 0); err != nil {
			return err
		}
	}
	if owner != nil {
		if err := unix.Unlinkat(int(directory.Fd()), ownerFile, 0); err != nil {
			return err
		}
	}
	var original, actual unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &original); err != nil {
		return err
	}
	parent, err := openRootDirectory("/run", false)
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(runtimePath(id))
	if err := unix.Fstatat(int(parent.Fd()), name, &actual, unix.AT_SYMLINK_NOFOLLOW); err != nil || actual.Dev != original.Dev || actual.Ino != original.Ino {
		return errors.New("runtime directory changed before removal")
	}
	return unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
}

func readCgroupNumber(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}
