// Package filesystem owns writable state in an already-private mount namespace.
// Mount must only be called by the root worker born with CLONE_NEWNS, after it
// has made mount propagation private. It never enters a namespace itself.
package filesystem

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var runtimePattern = regexp.MustCompile(`^/run/soteria-[0-9a-f]{32}$`)

// Workspace contains only private tmpfs-backed state. The exported paths are
// bind sources for the worker, not permission to expose the containing host tree.
// Configuration is root-owned and readable, but not writable, by the workload.
type Workspace struct {
	Root     string
	Home     string
	Work     string
	Temp     string
	Run      string
	Var      string
	Etc      string
	Noswap   bool
	Warnings []string

	mu        sync.Mutex
	ops       mountOperations
	root      string
	created   *unix.Stat_t
	mountedID *unix.Stat_t
	mounted   bool
	closed    bool
}

// These seams are only the mount, kernel mount inspection, and unmount
// boundaries. Tests still use real private directories and configuration files.
type mountOperations struct {
	mount   func(source, target, fstype string, flags uintptr, data string) error
	inspect func(string) (bool, error)
	unmount func(string, int) error
}

func systemMountOperations() mountOperations {
	return mountOperations{mount: unix.Mount, inspect: inspectTmpfs, unmount: unix.Unmount}
}

// Mount creates its own new child beneath the systemd-owned runtime directory.
// uid and gid must both be nonzero authenticated workload credentials. Failure
// to mount or verify tmpfs is fatal; disk-backed state is never substituted.
func Mount(runtimeDirectory string, workspaceBytes uint64, uid, gid uint32) (*Workspace, error) {
	if err := validateArguments(runtimeDirectory, workspaceBytes, uid, gid); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("mount workspace requires the namespace-isolated root worker")
	}
	runtime, err := openRuntimeDirectory(runtimeDirectory)
	if err != nil {
		return nil, err
	}
	w, mountErr := mountWorkspace(runtimeDirectory, workspaceBytes, uid, gid, systemMountOperations())
	closeErr := runtime.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf("close runtime directory: %w", closeErr)
		if w != nil {
			closeErr = errors.Join(closeErr, w.Close())
		}
		return nil, errors.Join(mountErr, closeErr)
	}
	return w, mountErr
}

func validateArguments(runtimeDirectory string, workspaceBytes uint64, uid, gid uint32) error {
	if !filepath.IsAbs(runtimeDirectory) || filepath.Clean(runtimeDirectory) != runtimeDirectory || !runtimePattern.MatchString(runtimeDirectory) {
		return errors.New("runtime directory must be exactly /run/soteria-<32 lowercase hexadecimal characters>")
	}
	if workspaceBytes == 0 || workspaceBytes > math.MaxInt64 {
		return errors.New("workspace size must be between 1 and 9223372036854775807 bytes")
	}
	if uid == 0 || gid == 0 || uid == math.MaxUint32 || gid == math.MaxUint32 {
		return errors.New("workload uid and gid must be nonzero, valid numeric identities")
	}
	return nil
}

func openRuntimeDirectory(name string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(fd)
		if openErr != nil || closeErr != nil {
			if openErr == nil {
				closeErr = errors.Join(closeErr, unix.Close(next))
			}
			return nil, fmt.Errorf("open runtime directory without symlinks: %w", errors.Join(openErr, closeErr))
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, errors.Join(fmt.Errorf("stat runtime directory: %w", err), unix.Close(fd))
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != 0o700 {
		return nil, errors.Join(fmt.Errorf("runtime directory must be root:root owned with mode 0700 (got %d:%d mode %#o)", st.Uid, st.Gid, st.Mode&0o7777), unix.Close(fd))
	}
	return os.NewFile(uintptr(fd), name), nil
}

func mountWorkspace(runtimeDirectory string, workspaceBytes uint64, uid, gid uint32, ops mountOperations) (_ *Workspace, err error) {
	root, err := os.MkdirTemp(runtimeDirectory, "workspace-")
	if err != nil {
		return nil, fmt.Errorf("create owned workspace mountpoint: %w", err)
	}
	w := &Workspace{
		Root: root, Home: filepath.Join(root, "home", "workspace"),
		Work: filepath.Join(root, "work"), Temp: filepath.Join(root, "tmp"),
		Run: filepath.Join(root, "run"), Var: filepath.Join(root, "var"), Etc: filepath.Join(root, "etc"),
		root: root, ops: ops,
	}
	w.created, err = directoryIdentity(root)
	if err != nil {
		// Without a recorded identity it is not safe to remove this pathname.
		return nil, fmt.Errorf("record owned workspace directory: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, w.Close())
		}
	}()

	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV)
	options := fmt.Sprintf("size=%d,mode=0700,uid=0,gid=0", workspaceBytes)
	if mountErr := ops.mount("tmpfs", root, "tmpfs", flags, options+",noswap"); mountErr != nil {
		if !errors.Is(mountErr, unix.EINVAL) && !errors.Is(mountErr, unix.EOPNOTSUPP) {
			return nil, fmt.Errorf("mount bounded tmpfs with noswap: %w", mountErr)
		}
		if fallbackErr := ops.mount("tmpfs", root, "tmpfs", flags, options); fallbackErr != nil {
			return nil, errors.Join(fmt.Errorf("tmpfs noswap unsupported: %w", mountErr), fmt.Errorf("mount ordinary bounded tmpfs: %w", fallbackErr))
		}
		w.Warnings = append(w.Warnings, fmt.Sprintf("tmpfs noswap control is unsupported (%v); using ordinary tmpfs, so workspace files may be swapped to host storage", mountErr))
	}
	w.mounted = true
	w.mountedID, err = directoryIdentity(root)
	if err != nil {
		return nil, fmt.Errorf("record mounted workspace identity: %w", err)
	}
	w.Noswap, err = ops.inspect(root)
	if err != nil {
		return nil, fmt.Errorf("verify private tmpfs mount: %w", err)
	}
	if !w.Noswap && len(w.Warnings) == 0 {
		w.Warnings = append(w.Warnings, "tmpfs noswap was requested but is not effective in /proc/self/mountinfo; workspace files may be swapped to host storage")
	}
	if err = w.prepare(uid, gid); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Workspace) prepare(uid, gid uint32) error {
	rootUID, rootGID := int(w.mountedID.Uid), int(w.mountedID.Gid)
	homeParent := filepath.Join(w.root, "home")
	if err := os.Mkdir(homeParent, 0o700); err != nil {
		return fmt.Errorf("create private home parent: %w", err)
	}
	if err := os.Chown(homeParent, rootUID, rootGID); err != nil {
		return fmt.Errorf("own private home parent: %w", err)
	}
	if err := os.Chmod(homeParent, 0o755); err != nil {
		return fmt.Errorf("set private home parent permissions: %w", err)
	}
	for _, dir := range []struct {
		path string
		mode os.FileMode
	}{
		{w.Home, 0o700}, {w.Work, 0o700}, {filepath.Join(w.Work, "in"), 0o700}, {filepath.Join(w.Work, "out"), 0o700},
		{w.Temp, 0o777 | os.ModeSticky}, {w.Run, 0o700}, {w.Var, 0o700},
		{filepath.Join(w.Var, "tmp"), 0o777 | os.ModeSticky}, {filepath.Join(w.Var, "cache"), 0o700},
		{filepath.Join(w.Var, "lib"), 0o700}, {filepath.Join(w.Var, "log"), 0o700},
	} {
		if err := os.Mkdir(dir.path, 0o700); err != nil {
			return fmt.Errorf("create private writable directory %s: %w", filepath.Base(dir.path), err)
		}
		if err := os.Chown(dir.path, int(uid), int(gid)); err != nil {
			return fmt.Errorf("own private writable directory: %w", err)
		}
		if err := os.Chmod(dir.path, dir.mode); err != nil {
			return fmt.Errorf("set private directory permissions: %w", err)
		}
	}
	if err := os.Mkdir(w.Etc, 0o700); err != nil {
		return fmt.Errorf("create private configuration directory: %w", err)
	}
	if err := os.Chown(w.Etc, rootUID, rootGID); err != nil {
		return fmt.Errorf("own private configuration directory: %w", err)
	}
	if err := os.Chmod(w.Etc, 0o755); err != nil {
		return fmt.Errorf("set private configuration directory permissions: %w", err)
	}
	configs := []struct{ name, text string }{
		{"passwd", fmt.Sprintf("workspace:x:%d:%d:Workspace:/home/workspace:/bin/bash\n", uid, gid)},
		{"group", fmt.Sprintf("workspace:x:%d:\n", gid)},
		{"nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\n"},
		{"hosts", "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 workspace\n"},
		{"resolv.conf", ""},
	}
	for _, config := range configs {
		name := filepath.Join(w.Etc, config.name)
		if err := os.WriteFile(name, []byte(config.text), 0o600); err != nil {
			return fmt.Errorf("generate private %s: %w", config.name, err)
		}
		if err := os.Chown(name, rootUID, rootGID); err != nil {
			return fmt.Errorf("own private %s: %w", config.name, err)
		}
		if err := os.Chmod(name, 0o444); err != nil {
			return fmt.Errorf("set private %s permissions: %w", config.name, err)
		}
	}
	return nil
}

// SetResolver atomically replaces only the private resolver configuration.
// No names, IPv6, search domains, or arbitrary resolver directives are accepted.
// Passing no servers restores the empty offline configuration.
func (w *Workspace) SetResolver(servers []string) (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || !w.mounted {
		return os.ErrClosed
	}
	if len(servers) > 3 {
		return errors.New("resolver accepts at most three literal IPv4 addresses")
	}
	var text strings.Builder
	for _, server := range servers {
		address, parseErr := netip.ParseAddr(server)
		if parseErr != nil || !address.Is4() {
			return errors.New("resolver requires literal IPv4 addresses")
		}
		fmt.Fprintf(&text, "nameserver %s\n", address.String())
	}
	// Do not use the exported path: callers cannot redirect cleanup/config writes
	// by mutating the informational Workspace fields.
	etc := filepath.Join(w.root, "etc")
	f, err := os.CreateTemp(etc, ".resolv-")
	if err != nil {
		return fmt.Errorf("create private resolver replacement: %w", err)
	}
	name := f.Name()
	defer func() {
		if removeErr := os.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove resolver replacement: %w", removeErr))
		}
	}()
	_, writeErr := io.WriteString(f, text.String())
	ownerErr := f.Chown(int(w.mountedID.Uid), int(w.mountedID.Gid))
	modeErr := f.Chmod(0o444)
	closeErr := f.Close()
	if err := errors.Join(writeErr, ownerErr, modeErr, closeErr); err != nil {
		return fmt.Errorf("write private resolver: %w", err)
	}
	if err := os.Rename(name, filepath.Join(etc, "resolv.conf")); err != nil {
		return fmt.Errorf("publish private resolver: %w", err)
	}
	return nil
}

// OpenImport opens /work/in without following a workload-supplied symlink.
// The caller owns the returned descriptor and must close it before Close.
func (w *Workspace) OpenImport() (*os.File, error) { return w.openTransferDirectory("in") }

// OpenExport opens /work/out after the worker has stopped and reaped writers.
// The caller owns the returned descriptor and must close it before Close.
func (w *Workspace) OpenExport() (*os.File, error) { return w.openTransferDirectory("out") }

func (w *Workspace) openTransferDirectory(name string) (*os.File, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || !w.mounted {
		return nil, os.ErrClosed
	}
	fd, err := unix.Open(filepath.Join(w.root, "work"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open private work directory: %w", err)
	}
	child, openErr := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	closeErr := unix.Close(fd)
	if openErr != nil || closeErr != nil {
		if openErr == nil {
			closeErr = errors.Join(closeErr, unix.Close(child))
		}
		return nil, fmt.Errorf("open private transfer directory: %w", errors.Join(openErr, closeErr))
	}
	return os.NewFile(uintptr(child), filepath.Join(w.root, "work", name)), nil
}

// Close normally unmounts only this workspace, then removes only the directory
// it created. The lifecycle owner must first stop/reap writers and close transfer
// descriptors. EBUSY is reported, never bypassed with lazy detach. A failed Close
// can be retried; no new operations are accepted after the first close attempt.
func (w *Workspace) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if w.created == nil {
		return nil
	}
	if w.mounted {
		if err := requireIdentity(w.root, w.mountedID); err != nil {
			return fmt.Errorf("refuse to unmount changed workspace: %w", err)
		}
		if err := w.ops.unmount(w.root, 0); err != nil {
			return fmt.Errorf("unmount private workspace: %w", err)
		}
		w.mounted = false
	}
	if err := requireIdentity(w.root, w.created); err != nil {
		return fmt.Errorf("refuse to remove changed workspace directory: %w", err)
	}
	if err := os.Remove(w.root); err != nil {
		return fmt.Errorf("remove owned workspace directory: %w", err)
	}
	w.created = nil
	return nil
}

func directoryIdentity(name string) (*unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Lstat(name, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New("not a directory")
	}
	return &st, nil
}

func requireIdentity(name string, expected *unix.Stat_t) error {
	if expected == nil {
		return errors.New("directory ownership identity was not recorded")
	}
	actual, err := directoryIdentity(name)
	if err != nil {
		return err
	}
	if actual.Dev != expected.Dev || actual.Ino != expected.Ino {
		return errors.New("directory device/inode no longer matches acquired resource")
	}
	return nil
}

func inspectTmpfs(root string) (noswap bool, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		return false, fmt.Errorf("statfs: %w", err)
	}
	if st.Type != unix.TMPFS_MAGIC || st.Flags&int64(unix.MS_NOSUID|unix.MS_NODEV) != int64(unix.MS_NOSUID|unix.MS_NODEV) {
		return false, errors.New("workspace is not tmpfs with nosuid,nodev effective")
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, fmt.Errorf("open mountinfo: %w", err)
	}
	noswap, err = inspectMountInfo(f, root)
	return noswap, errors.Join(err, f.Close())
}

func inspectMountInfo(r io.Reader, root string) (bool, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	found, noswap := false, false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return false, errors.New("malformed /proc/self/mountinfo entry")
		}
		mountpoint := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(fields[4])
		if mountpoint != root {
			continue
		}
		separator := 6
		for separator < len(fields) && fields[separator] != "-" {
			separator++
		}
		if separator+3 >= len(fields) || fields[separator+1] != "tmpfs" {
			return false, errors.New("owned workspace mount is not recorded as tmpfs")
		}
		if found {
			return false, errors.New("multiple mounts cover the owned workspace mountpoint")
		}
		if !hasOption(fields[5], "nosuid") || !hasOption(fields[5], "nodev") {
			return false, errors.New("mountinfo does not confirm nosuid,nodev")
		}
		found = true
		noswap = hasOption(fields[5], "noswap") || hasOption(fields[separator+3], "noswap")
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read mountinfo: %w", err)
	}
	if !found {
		return false, errors.New("owned workspace mountpoint is absent from /proc/self/mountinfo")
	}
	return noswap, nil
}

func hasOption(options, wanted string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == wanted {
			return true
		}
	}
	return false
}
