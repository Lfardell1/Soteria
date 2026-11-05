package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Imports validates explicit host paths and rejects top-level basename
// collisions. Relative inputs are made absolute; nothing is opened as root on
// behalf of another user. Send checks the paths again when copying.
func Imports(paths []string) ([]Source, error) {
	if len(paths) > maxEntries {
		return nil, ErrLimit
	}
	sources := make([]Source, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, input := range paths {
		if err := validHostPath(input); err != nil {
			return nil, err
		}
		name := filepath.Base(input)
		if err := validBase(name); err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("%w: duplicate import basename %q", ErrUnsafe, name)
		}
		seen[name] = true
		absolute, err := filepath.Abs(input)
		if err != nil {
			return nil, err
		}
		f, st, err := openHost(absolute, false)
		if err != nil {
			return nil, err
		}
		err = errors.Join(safeSource(st), f.Close())
		if err != nil {
			return nil, fmt.Errorf("import %q: %w", input, err)
		}
		sources = append(sources, Source{Path: absolute, Name: name})
	}
	return sources, nil
}

// Outputs selects the immediate children of an existing, nonsymlink output
// directory or an explicit /proc/self/fd/N directory root. Keep that descriptor
// open through Send. The workload must already have stopped. Recursion and
// quotas are enforced by Send, which also rejects observed source mutations.
func Outputs(directory string) (_ []Source, err error) {
	if err := validHostPath(directory); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	root, before, err := openHost(absolute, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if before.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, fmt.Errorf("%w: output root is not a directory", ErrUnsafe)
	}
	if err := safeSource(before); err != nil {
		return nil, err
	}
	names, err := sourceNames(context.Background(), root, maxEntries)
	if err != nil {
		return nil, err
	}
	sources := make([]Source, 0, len(names))
	for _, name := range names {
		child, st, openErr := openBeneath(root, name)
		if openErr != nil {
			return nil, openErr
		}
		if err := errors.Join(safeSource(st), child.Close()); err != nil {
			return nil, fmt.Errorf("output %q: %w", name, err)
		}
		sources = append(sources, Source{Path: filepath.Join(absolute, name), Name: name})
	}
	after, err := statFile(root)
	if err != nil {
		return nil, err
	}
	if !sameStat(before, after) {
		return nil, ErrChanged
	}
	return sources, nil
}

// openHost starts at an os.Root anchor and resolves every untrusted component
// with openat2. O_PATH inspects types without opening devices or blocking on a
// FIFO. allowFD deliberately follows only an exact authorized proc-fd root.
func openHost(name string, allowFD bool) (_ *os.File, st unix.Stat_t, err error) {
	if err := validHostPath(name); err != nil {
		return nil, st, err
	}
	anchorName, relative := ".", name
	if strings.HasPrefix(name, "/") {
		anchorName, relative = "/", strings.TrimPrefix(name, "/")
		if relative == "" {
			relative = "."
		}
	}
	if allowFD && authorizedFDPath(name) {
		// Pin and inspect the authority without opening it for I/O first.
		// OpenRoot itself opens for reading, which would be unsafe if the
		// caller accidentally supplied a FIFO or device descriptor.
		fd, err := unix.Open(name, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, st, err
		}
		pinned := os.NewFile(uintptr(fd), name)
		defer pinned.Close()
		target, err := statFile(pinned)
		if err != nil {
			return nil, st, err
		}
		if target.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, st, fmt.Errorf("%w: authorized descriptor root is not a directory", ErrUnsafe)
		}
		anchorName, relative = "/proc/self/fd/"+strconv.Itoa(fd), "."
	}
	anchor, err := os.OpenRoot(anchorName)
	if err != nil {
		return nil, st, err
	}
	defer anchor.Close()
	parent, err := anchor.OpenFile(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, st, err
	}
	defer parent.Close()
	fd, err := unix.Openat2(int(parent.Fd()), relative, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, st, fmt.Errorf("open transfer path %q without symlinks: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	st, err = statFile(f)
	if err != nil {
		return nil, st, errors.Join(err, f.Close())
	}
	return f, st, nil
}

func authorizedFDPath(name string) bool {
	const prefix = "/proc/self/fd/"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	component := strings.TrimPrefix(name, prefix)
	n, err := strconv.ParseUint(component, 10, 31)
	return err == nil && strconv.FormatUint(n, 10) == component
}

// A helper may inherit an explicitly authorized output directory descriptor
// without permission to traverse its runtime-directory ancestors. Only this
// exact proc-fd prefix is an authority; every suffix is still resolved beneath
// that pinned directory without following symlinks or crossing mounts.
func openSource(name string) (_ *os.File, st unix.Stat_t, err error) {
	if err := validHostPath(name); err != nil {
		return nil, st, err
	}
	const prefix = "/proc/self/fd/"
	if !strings.HasPrefix(name, prefix) {
		return openHost(name, false)
	}
	component, relative, suffix := strings.Cut(strings.TrimPrefix(name, prefix), "/")
	rootPath := prefix + component
	if !authorizedFDPath(rootPath) {
		return openHost(name, false)
	}
	root, st, err := openHost(rootPath, true)
	if err != nil || !suffix {
		return root, st, err
	}
	defer root.Close()
	return openBeneath(root, relative)
}

func openBeneath(root *os.File, name string) (*os.File, unix.Stat_t, error) {
	fd, err := unix.Openat2(int(root.Fd()), name, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	runtime.KeepAlive(root)
	if err != nil {
		return nil, unix.Stat_t{}, fmt.Errorf("open tree entry %q without symlinks or mount crossings: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	st, err := statFile(f)
	if err != nil {
		return nil, st, errors.Join(err, f.Close())
	}
	return f, st, nil
}

func statFile(f *os.File) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstat(int(f.Fd()), &st)
	runtime.KeepAlive(f)
	return st, err
}

func safeSource(st unix.Stat_t) error {
	if st.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
		return fmt.Errorf("%w: setuid, setgid, or sticky metadata", ErrUnsafe)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if st.Nlink != 1 || st.Size < 0 {
			return fmt.Errorf("%w: hard-linked or invalid regular file", ErrUnsafe)
		}
	case unix.S_IFDIR:
		if st.Nlink == 0 {
			return ErrChanged
		}
	default:
		return fmt.Errorf("%w: only regular files and directories are transferable", ErrUnsafe)
	}
	return nil
}

func sameStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Reopening our own pinned O_PATH descriptor intentionally follows this one
// proc-fd link, never a caller-controlled filesystem link. Type checks precede
// this operation, so a special file is never opened for I/O.
func openPinned(f *os.File, directory bool) (*os.File, error) {
	name := "/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)
	if directory {
		root, err := os.OpenRoot(name)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		return root.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	runtime.KeepAlive(f)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), f.Name()), nil
}

func sourceNames(ctx context.Context, directory *os.File, remaining uint64) (_ []string, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := openPinned(directory, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	var names []string
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, readErr := f.ReadDir(128)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if uint64(len(names)) >= remaining || len(names) >= maxEntries {
				return nil, ErrLimit
			}
			if err := validBase(entry.Name()); err != nil {
				return nil, err
			}
			names = append(names, entry.Name())
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	slices.Sort(names)
	for i := 1; i < len(names); i++ {
		if names[i-1] == names[i] {
			return nil, ErrChanged
		}
	}
	return names, nil
}

type nodeSnapshot struct {
	path string
	stat unix.Stat_t
}

type sourceSnapshot struct {
	path  string
	nodes []nodeSnapshot
}

type sender struct {
	ctx    context.Context
	w      io.Writer
	budget budget
	buffer []byte
}

// Send streams sorted, normalized snapshots of explicit sources. Observed
// metadata, identity, hardlink, size, and directory changes fail the transfer.
// This is mutation detection, not a filesystem-level atomic snapshot.
func Send(ctx context.Context, w io.Writer, sources []Source, limits Limits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(sources) > maxEntries || uint64(len(sources)) > limits.MaxFiles {
		return ErrLimit
	}
	sources = slices.Clone(sources)
	slices.SortFunc(sources, func(a, b Source) int { return strings.Compare(a.Name, b.Name) })
	for i, source := range sources {
		if err := validBase(source.Name); err != nil {
			return err
		}
		if err := validHostPath(source.Path); err != nil {
			return err
		}
		if i > 0 && sources[i-1].Name == source.Name {
			return fmt.Errorf("%w: duplicate source %q", ErrUnsafe, source.Name)
		}
	}
	if err := writeBytes(ctx, w, []byte(streamMagic)); err != nil {
		return err
	}
	s := sender{ctx: ctx, w: w, budget: budget{limits: limits}, buffer: make([]byte, bufferBytes)}
	snapshots := make([]sourceSnapshot, 0, len(sources))
	for _, source := range sources {
		snapshot := sourceSnapshot{path: source.Path}
		if err := s.sendSource(source, &snapshot); err != nil {
			return fmt.Errorf("send %q: %w", source.Name, err)
		}
		snapshots = append(snapshots, snapshot)
	}
	// A final pass also catches changes to entries already sent while another
	// file was being copied. At most MaxFiles bounded metadata records are kept.
	for _, snapshot := range snapshots {
		if err := verifySnapshot(ctx, snapshot); err != nil {
			return err
		}
	}
	return writeFrame(ctx, w, frame{kind: endStream})
}

func (s *sender) sendSource(source Source, snapshot *sourceSnapshot) (err error) {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	root, _, err := openSource(source.Path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return s.walk(root, "", source.Name, snapshot)
}

func (s *sender) walk(root *os.File, relative, name string, snapshot *sourceSnapshot) (err error) {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if err := validName(name); err != nil {
		return err
	}
	f, before := root, unix.Stat_t{}
	if relative == "" {
		before, err = statFile(root)
	} else {
		f, before, err = openBeneath(root, relative)
		if err == nil {
			defer func() { err = errors.Join(err, f.Close()) }()
		}
	}
	if err != nil {
		return err
	}
	if err := safeSource(before); err != nil {
		return err
	}
	size := uint64(0)
	if before.Mode&unix.S_IFMT == unix.S_IFREG {
		size = uint64(before.Size)
	}
	if err := s.budget.add(size); err != nil {
		return err
	}
	snapshot.nodes = append(snapshot.nodes, nodeSnapshot{path: relative, stat: before})
	if before.Mode&unix.S_IFMT == unix.S_IFREG {
		return s.sendFile(f, name, before)
	}
	names, err := sourceNames(s.ctx, f, min(s.budget.limits.MaxFiles-s.budget.files, uint64(maxEntries)-s.budget.files))
	if err != nil {
		return err
	}
	if err := unchanged(f, before); err != nil {
		return err
	}
	if err := writeFrame(s.ctx, s.w, frame{kind: directoryEntry, name: name}); err != nil {
		return err
	}
	for _, child := range names {
		if err := unchanged(f, before); err != nil {
			return err
		}
		childPath := child
		if relative != "" {
			childPath = relative + "/" + child
		}
		if err := s.walk(root, childPath, name+"/"+child, snapshot); err != nil {
			return err
		}
	}
	if err := unchanged(f, before); err != nil {
		return err
	}
	return writeFrame(s.ctx, s.w, frame{kind: endDirectory})
}

func (s *sender) sendFile(pinned *os.File, name string, before unix.Stat_t) (err error) {
	f, err := openPinned(pinned, false)
	if err != nil {
		return err
	}
	defer func() {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	if err := unchanged(f, before); err != nil {
		return err
	}
	if err := writeFrame(s.ctx, s.w, frame{kind: fileEntry, name: name, size: uint64(before.Size)}); err != nil {
		return err
	}
	r := streamReader{ctx: s.ctx, r: f}
	if err := copySized(r, s.w, uint64(before.Size), s.buffer); err != nil {
		return errors.Join(err, unchanged(f, before))
	}
	if err := r.eof(); err != nil {
		return fmt.Errorf("%w: file grew or read failed: %w", ErrChanged, err)
	}
	if err := unchanged(f, before); err != nil {
		return err
	}
	closeErr := f.Close()
	f = nil
	if closeErr != nil {
		return closeErr
	}
	// Receive must see this marker before publishing, so a failed size or
	// metadata check cannot publish the in-progress file.
	return writeFrame(s.ctx, s.w, frame{kind: endFile})
}

func unchanged(f *os.File, before unix.Stat_t) error {
	after, err := statFile(f)
	if err != nil {
		return err
	}
	if !sameStat(before, after) {
		return ErrChanged
	}
	return safeSource(after)
}

func verifySnapshot(ctx context.Context, snapshot sourceSnapshot) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, before, err := openSource(snapshot.path)
	if err != nil {
		return fmt.Errorf("%w: reopen source: %w", ErrChanged, err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if !sameStat(before, snapshot.nodes[0].stat) {
		return ErrChanged
	}
	for _, node := range snapshot.nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if node.path == "" {
			continue
		}
		f, after, err := openBeneath(root, node.path)
		if err != nil {
			return fmt.Errorf("%w: reopen entry %q: %w", ErrChanged, node.path, err)
		}
		closeErr := f.Close()
		if !sameStat(node.stat, after) {
			return errors.Join(ErrChanged, closeErr)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err := unchanged(root, before); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	check, after, err := openSource(snapshot.path)
	if err != nil {
		return fmt.Errorf("%w: source path was replaced: %w", ErrChanged, err)
	}
	closeErr := check.Close()
	if !sameStat(before, after) {
		return errors.Join(ErrChanged, closeErr)
	}
	return closeErr
}
