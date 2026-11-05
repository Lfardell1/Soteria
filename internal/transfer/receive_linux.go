package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

type receiveDirectory struct {
	order treeOrder
	file  *os.File
	stat  unix.Stat_t
}

// Receive writes one complete stream into an existing, explicitly authorized
// destination. The exact path /proc/self/fd/N may be used as an authorized root;
// all other symlinks, including destination-root symlinks, are rejected.
//
// Files are 0600, directories are created with 0700 (subject to umask), and no
// ownership, timestamps, executable bits, links, or other metadata are copied.
// Existing entries are never overwritten or merged. Anonymous same-directory
// temporary files require O_TMPFILE and proc-fd linkat support; unsupported
// filesystems fail closed. No durability/fsync promise is made.
func Receive(ctx context.Context, r io.Reader, destination string, limits Limits) (err error) {
	result := &ReceiveError{}
	defer func() {
		if err != nil {
			result.Err = err
			err = result
		}
	}()
	if err := limits.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, st, err := openHost(destination, true)
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.Join(fmt.Errorf("%w: destination must already be a directory", ErrUnsafe), root.Close())
	}
	stack := []receiveDirectory{{file: root, stat: st}}
	defer func() {
		for i := len(stack) - 1; i >= 0; i-- {
			err = errors.Join(err, stack[i].file.Close())
		}
	}()
	input := streamReader{ctx: ctx, r: r}
	var magic [len(streamMagic)]byte
	if err := input.full(magic[:]); err != nil {
		return err
	}
	if string(magic[:]) != streamMagic {
		return fmt.Errorf("%w: unsupported magic/version", ErrProtocol)
	}
	quota := budget{limits: limits}
	buffer := make([]byte, bufferBytes)
	for {
		entry, err := input.next()
		if err != nil {
			return err
		}
		current := &stack[len(stack)-1]
		switch entry.kind {
		case endStream:
			if len(stack) != 1 {
				return fmt.Errorf("%w: unclosed directory", ErrProtocol)
			}
			return input.eof()
		case endDirectory:
			if len(stack) == 1 {
				return fmt.Errorf("%w: unexpected directory end", ErrProtocol)
			}
			if err := checkDestination(root, *current); err != nil {
				return err
			}
			closeErr := current.file.Close()
			stack = stack[:len(stack)-1]
			if closeErr != nil {
				return closeErr
			}
		case directoryEntry, fileEntry:
			if err := quota.add(entry.size); err != nil {
				return err
			}
			base, err := current.order.accept(entry.name)
			if err != nil {
				return err
			}
			if err := checkDestination(root, *current); err != nil {
				return err
			}
			if entry.kind == directoryEntry {
				if err := unix.Mkdirat(int(current.file.Fd()), base, 0o700); err != nil {
					return fmt.Errorf("create output directory %q without overwrite: %w", entry.name, err)
				}
				result.CreatedDirectories++
				child, childStat, err := openBeneath(root, entry.name)
				if err != nil {
					return err
				}
				if err := safeDestinationDirectory(childStat); err != nil {
					return errors.Join(err, child.Close())
				}
				stack = append(stack, receiveDirectory{order: treeOrder{path: entry.name}, file: child, stat: childStat})
				continue
			}
			if err := receiveFile(input, root, *current, base, entry.size, buffer, result); err != nil {
				return fmt.Errorf("receive file %q: %w", entry.name, err)
			}
		default:
			return fmt.Errorf("%w: unexpected file-completion frame", ErrProtocol)
		}
	}
}

func safeDestinationDirectory(st unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7077 != 0 || st.Nlink == 0 {
		return fmt.Errorf("%w: output directory was replaced or has unsafe metadata", ErrUnsafe)
	}
	return nil
}

func checkDestination(root *os.File, directory receiveDirectory) error {
	if directory.order.path == "" {
		return nil // the explicitly authorized root is an anchored descriptor
	}
	f, st, err := openBeneath(root, directory.order.path)
	if err != nil {
		return err
	}
	closeErr := f.Close()
	if st.Dev != directory.stat.Dev || st.Ino != directory.stat.Ino {
		return errors.Join(fmt.Errorf("%w: output directory was renamed or replaced", ErrUnsafe), closeErr)
	}
	return errors.Join(safeDestinationDirectory(st), closeErr)
}

func receiveFile(input streamReader, root *os.File, parent receiveDirectory, name string, size uint64, buffer []byte, result *ReceiveError) (err error) {
	// There is no temporary pathname for an attacker to replace, hard-link, or
	// trick cleanup into removing. Closing an unpublished inode discards it.
	fd, err := unix.Openat(int(parent.file.Fd()), ".", unix.O_WRONLY|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create anonymous atomic output (O_TMPFILE required): %w", err)
	}
	f := os.NewFile(uintptr(fd), "anonymous transfer output")
	defer func() { err = errors.Join(err, f.Close()) }()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if err := copySized(input, f, size, buffer); err != nil {
		return err
	}
	commit, err := input.next()
	if err != nil {
		return err
	}
	if commit.kind != endFile {
		return fmt.Errorf("%w: missing file-completion frame", ErrProtocol)
	}
	st, err := statFile(f)
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 || st.Nlink != 0 || st.Size < 0 || uint64(st.Size) != size {
		return fmt.Errorf("%w: temporary output changed", ErrUnsafe)
	}
	if err := checkDestination(root, parent); err != nil {
		return err
	}
	if err := input.ctx.Err(); err != nil {
		return err
	}
	// AT_EMPTY_PATH would require a capability for an ordinary process. The
	// documented proc-fd form links this pinned anonymous inode without that
	// privilege. linkat is atomic and fails if any target entry already exists.
	procFD := "/proc/self/fd/" + strconv.Itoa(fd)
	if err := unix.Linkat(unix.AT_FDCWD, procFD, int(parent.file.Fd()), name, unix.AT_SYMLINK_FOLLOW); err != nil {
		return fmt.Errorf("publish without overwrite: %w", err)
	}
	runtime.KeepAlive(f)
	result.PublishedFiles++
	return input.ctx.Err()
}
