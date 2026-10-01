package filesystem

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/Lfardell1/Soteria/internal/config"
	"golang.org/x/sys/unix"
)

func lookPath(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		candidate := filepath.Join(dir, name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s not found", name)
}

// Manager owns the ephemeral tmpfs workspace.
type Manager struct {
	cfg         config.FilesystemConfig
	createdDir  bool
	mounted     bool
	populated   bool
}

// New creates a filesystem manager from config.
func New(cfg config.FilesystemConfig) *Manager {
	return &Manager{cfg: cfg}
}

// Mount creates the mount point if needed and mounts a tmpfs.
func (m *Manager) Mount() error {
	if m.mounted {
		return nil
	}

	if err := os.MkdirAll(m.cfg.MountPoint, 0o700); err != nil {
		return fmt.Errorf("create mount point: %w", err)
	}
	// Track whether we created an empty directory we should remove on teardown.
	if empty, _ := dirEmpty(m.cfg.MountPoint); empty {
		m.createdDir = true
	}

	sizeBytes, err := config.ParseSize(m.cfg.TmpfsSize)
	if err != nil {
		return err
	}

	opts := fmt.Sprintf("size=%d,mode=0700", sizeBytes)
	if err := unix.Mount("tmpfs", m.cfg.MountPoint, "tmpfs", 0, opts); err != nil {
		return fmt.Errorf("mount tmpfs at %s: %w", m.cfg.MountPoint, err)
	}
	m.mounted = true
	return nil
}

// Populate copies host tool paths into the tmpfs workspace via rsync.
func (m *Manager) Populate() error {
	if !m.mounted {
		return fmt.Errorf("tmpfs not mounted")
	}

	rsyncBin, err := lookPath("rsync")
	if err != nil {
		return err
	}

	paths := m.cfg.PopulatePaths
	if len(paths) == 0 && m.cfg.ToolsDir != "" {
		paths = []string{m.cfg.ToolsDir}
	}
	if len(paths) == 0 {
		return fmt.Errorf("no populate paths configured")
	}

	for _, src := range paths {
		info, err := os.Stat(src)
		if err != nil {
			// Skip missing optional paths (e.g. /lib64 on some systems).
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat %s: %w", src, err)
		}

		dst := filepath.Join(m.cfg.MountPoint, src)
		if info.IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", dst, err)
			}
			cmd := exec.Command(rsyncBin, "-a", src+"/", dst+"/")
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("rsync %s -> %s: %w (%s)", src, dst, err, string(out))
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			cmd := exec.Command(rsyncBin, "-a", src, dst)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("rsync file %s: %w (%s)", src, err, string(out))
			}
		}
	}

	// Ensure a workspace home directory exists inside the ephemeral env.
	home := filepath.Join(m.cfg.MountPoint, "home", "soteria")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fmt.Errorf("create workspace home: %w", err)
	}

	m.populated = true
	return nil
}

// Usage reports tmpfs capacity statistics.
type Usage struct {
	Total uint64
	Used  uint64
	Free  uint64
}

// Stats returns filesystem usage for the mount point.
func (m *Manager) Stats() (Usage, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(m.cfg.MountPoint, &st); err != nil {
		return Usage{}, fmt.Errorf("statfs: %w", err)
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	return Usage{
		Total: total,
		Free:  free,
		Used:  total - free,
	}, nil
}

// MountPoint returns the configured mount path.
func (m *Manager) MountPoint() string {
	return m.cfg.MountPoint
}

// IsMounted reports whether the tmpfs is currently mounted by this manager.
func (m *Manager) IsMounted() bool {
	return m.mounted
}

// Teardown syncs, best-effort zeroes sensitive paths, unmounts, and cleans up.
func (m *Manager) Teardown() error {
	var firstErr error
	capture := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if m.mounted {
		syscall.Sync()
		capture(zeroTree(m.cfg.MountPoint))
		if err := unix.Unmount(m.cfg.MountPoint, unix.MNT_DETACH); err != nil {
			capture(fmt.Errorf("unmount %s: %w", m.cfg.MountPoint, err))
		} else {
			m.mounted = false
			m.populated = false
		}
	}

	if m.createdDir && !m.mounted {
		if err := os.Remove(m.cfg.MountPoint); err != nil && !os.IsNotExist(err) {
			// Directory may not be empty if unmount failed; ignore non-fatal.
			capture(err)
		}
		m.createdDir = false
	}

	return firstErr
}

func dirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return len(names) == 0, nil
}

func zeroTree(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		// Skip very large files for teardown latency; overwrite small files.
		if info.Size() > 16<<20 {
			return nil
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil
		}
		defer f.Close()
		buf := make([]byte, 4096)
		remaining := info.Size()
		for remaining > 0 {
			n := int64(len(buf))
			if remaining < n {
				n = remaining
			}
			if _, err := f.Write(buf[:n]); err != nil {
				return nil
			}
			remaining -= n
		}
		_ = f.Sync()
		return nil
	})
}
