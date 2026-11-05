//go:build linux

package toolkit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Generate seals a dedicated, single-writer build tree and writes the exact v1
// manifest consumed by Verify. It does not install files or change ownership.
// Package archives must already have been authenticated by the distro builder.
// Installation/archive creation must independently set root:root ownership.
func Generate(root string, build BuildMetadata) (inventory Inventory, err error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return Inventory{}, errors.New("build root must be a clean absolute non-root path")
	}
	if resolved, err := filepath.EvalSymlinks(root); err != nil || resolved != root {
		return Inventory{}, errors.Join(errors.New("build root and its ancestors must not be symlinks"), err)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return Inventory{}, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	if _, err := r.Lstat(ManifestName); !errors.Is(err, os.ErrNotExist) {
		return Inventory{}, errors.New("refusing to replace an existing runtime manifest; use a fresh build tree")
	}
	rootFile, err := r.Open(".")
	if err != nil {
		return Inventory{}, err
	}
	defer func() { err = errors.Join(err, rootFile.Close()) }()
	var rootStat unix.Stat_t
	if err := unix.Fstat(int(rootFile.Fd()), &rootStat); err != nil {
		return Inventory{}, err
	}
	if err := (verifier{capability: unix.Fgetxattr}).noCapabilities(int(rootFile.Fd())); err != nil {
		return Inventory{}, err
	}
	inventory = Inventory{Version: 1, Build: build}
	var directories []string
	err = fs.WalkDir(r.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		if !safePath(name) || secretPath(name) || strings.Count(name, "/") > 64 {
			return fmt.Errorf("unsafe or secret build path: %q", name)
		}
		if len(inventory.Files) >= maxEntries {
			return errors.New("build tree exceeds the inventory entry limit")
		}
		entry := Entry{Path: name}
		if d.Type()&os.ModeSymlink != 0 {
			target, err := r.Readlink(name)
			if err != nil {
				return err
			}
			if path.IsAbs(target) {
				// Absolute package links refer to the guest root, never the host.
				target, err = filepath.Rel(path.Dir(name), strings.TrimPrefix(path.Clean(target), "/"))
				if err != nil || !safeTarget(target) {
					return fmt.Errorf("cannot normalize package symlink %s", name)
				}
				if err := r.Remove(name); err != nil {
					return err
				}
				if err := r.Symlink(target, name); err != nil {
					return err
				}
			}
			entry.Type, entry.Mode, entry.Target = "symlink", "0777", target
		} else {
			flags := os.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK
			if d.IsDir() {
				flags |= unix.O_DIRECTORY
			} else if !d.Type().IsRegular() {
				return fmt.Errorf("special object in build tree: %s", name)
			}
			f, err := r.OpenFile(name, flags, 0)
			if err != nil {
				return err
			}
			var st unix.Stat_t
			statErr := unix.Fstat(int(f.Fd()), &st)
			if statErr == nil && st.Dev != rootStat.Dev {
				statErr = fmt.Errorf("build tree crosses a filesystem boundary: %s", name)
			}
			if statErr == nil {
				statErr = (verifier{capability: unix.Fgetxattr}).noCapabilities(int(f.Fd()))
			}
			if statErr != nil {
				return errors.Join(statErr, f.Close())
			}
			if d.IsDir() {
				entry.Type, entry.Mode = "directory", "0555"
				directories = append(directories, name)
			} else {
				if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
					return errors.Join(fmt.Errorf("build file must be a private regular file, not a hard link: %s", name), f.Close())
				}
				entry.Type, entry.Mode = "file", "0444"
				mode := os.FileMode(0o444)
				if st.Mode&0o111 != 0 {
					entry.Mode, mode = "0555", 0o555
				}
				hash := sha256.New()
				_, readErr := io.Copy(io.MultiWriter(hash, &keyGuard{}), f)
				if readErr != nil {
					return errors.Join(fmt.Errorf("read build file %s: %w", name, readErr), f.Close())
				}
				entry.SHA256 = hex.EncodeToString(hash.Sum(nil))
				if err := f.Chmod(mode); err != nil {
					return errors.Join(err, f.Close())
				}
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
		inventory.Files = append(inventory.Files, entry)
		return nil
	})
	if err != nil {
		return Inventory{}, err
	}
	inventory = canonical(inventory)
	if _, err := validateInventory(inventory); err != nil {
		return Inventory{}, err
	}
	inventory.Digest, err = Digest(inventory)
	if err != nil {
		return Inventory{}, err
	}
	data, err := json.Marshal(inventory)
	if err != nil || len(data)+1 > maxManifestBytes {
		return Inventory{}, errors.Join(errors.New("cannot encode runtime manifest within its size limit"), err)
	}
	manifest, err := r.OpenFile(ManifestName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return Inventory{}, err
	}
	_, writeErr := manifest.Write(append(data, '\n'))
	modeErr := manifest.Chmod(0o444)
	if err := errors.Join(writeErr, modeErr, manifest.Close()); err != nil {
		return Inventory{}, err
	}
	for i := len(directories) - 1; i >= 0; i-- {
		f, err := r.OpenFile(directories[i], os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return Inventory{}, err
		}
		if err := errors.Join(f.Chmod(0o555), f.Close()); err != nil {
			return Inventory{}, err
		}
	}
	if err := rootFile.Chmod(0o555); err != nil {
		return Inventory{}, err
	}
	return VerifyStaging(root)
}

// VerifyStaging performs every content/mode/secret/symlink check used by Verify,
// but allows the current builder's ownership. This is only an archive-building
// check, not proof of installed root ownership or trusted runtime provenance.
func VerifyStaging(root string) (inventory Inventory, err error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return Inventory{}, errors.New("staging root must be a clean absolute non-root path")
	}
	if resolved, err := filepath.EvalSymlinks(root); err != nil || resolved != root {
		return Inventory{}, errors.Join(errors.New("staging root and its ancestors must not be symlinks"), err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	r, err := os.OpenRoot(root)
	if err != nil {
		return Inventory{}, err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	// A disposable container's ancestors need not be owned by its mapped root.
	// Check ownership of the archive tree separately; production Verify still
	// requires actual root ownership of the installed tree AND its ancestors.
	if err := fs.WalkDir(r.FS(), ".", func(name string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := r.Lstat(name)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != uid && st.Uid != 0) || (st.Gid != gid && st.Gid != 0) {
			return fmt.Errorf("staging object %s must belong to builder %d:%d or root", name, uid, gid)
		}
		return nil
	}); err != nil {
		return Inventory{}, err
	}
	v := verifier{capability: unix.Fgetxattr, stat: func(fd int, name string, st *unix.Stat_t, flags int) error {
		if err := unix.Fstatat(fd, name, st, flags); err != nil {
			return err
		}
		st.Uid, st.Gid = 0, 0
		return nil
	}}
	return v.verify(root)
}
