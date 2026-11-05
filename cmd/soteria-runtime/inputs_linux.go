//go:build linux

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Lfardell1/Soteria/internal/toolkit"
	"golang.org/x/sys/unix"
)

const (
	entryPath = "usr/libexec/soteria-entry"
	packageLockPath = "usr/share/soteria/packages.lock"
	snapshotPath = "usr/share/soteria/snapshot.sources"
)

type lockedPackage struct {
	Name, Version, Architecture, SHA256 string
}

var lockName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
var lockVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.+:~_-]*$`)
var lockHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var snapshotTime = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

func readBounded(name string, limit int64) (data []byte, err error) {
	f, err := os.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil { return nil, err }
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() { return nil, errors.Join(errors.New("input must be a regular file, not a symlink or special object"), err) }
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) { return nil, errors.New("build input exceeds its size bound") }
	return data, err
}

// Every authenticated archive is recorded, not only the requested tools. The
// canonical lock is also inventoried INSIDE the runtime to bind its archive hashes.
func readLock(name string) ([]lockedPackage, error) {
	data, err := readBounded(name, 1<<20)
	if err != nil { return nil, fmt.Errorf("read package lock: %w", err) }
	return parseLock(data)
}

func parseLock(data []byte) ([]lockedPackage, error) {
	var packages []lockedPackage
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 4 || !lockName.MatchString(fields[0]) || !lockVersion.MatchString(fields[1]) ||
			(fields[2] != "amd64" && fields[2] != "all") || !lockHash.MatchString(fields[3]) || seen[fields[0]] {
			return nil, errors.New("invalid, duplicate, unpinned, or non-amd64 package lock row")
		}
		seen[fields[0]] = true
		packages = append(packages, lockedPackage{fields[0], fields[1], fields[2], fields[3]})
		if len(packages) > 4096 { return nil, errors.New("package lock exceeds 4096 packages") }
	}
	if err := scanner.Err(); err != nil { return nil, err }
	if len(packages) == 0 { return nil, errors.New("package lock is empty") }
	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })
	return packages, nil
}

func canonicalLock(packages []lockedPackage) []byte {
	var data bytes.Buffer
	for _, p := range packages { fmt.Fprintf(&data, "%s\t%s\t%s\t%s\n", p.Name, p.Version, p.Architecture, p.SHA256) }
	return data.Bytes()
}

func inventoryPackages(packages []lockedPackage) []toolkit.Package {
	result := make([]toolkit.Package, len(packages))
	for i, p := range packages { result[i] = toolkit.Package{Name:p.Name, Version:p.Version} }
	return result
}

func readSources(name string, build toolkit.BuildMetadata) ([]byte, error) {
	data, err := readBounded(name, 64<<10)
	if err != nil { return nil, fmt.Errorf("read snapshot sources: %w", err) }
	if err := validateSources(data, build); err != nil { return nil, err }
	return data, nil
}

func validateSources(data []byte, build toolkit.BuildMetadata) error {
	var expected []map[string]string
	switch {
	case build.Distro == "debian" && build.Release == "13":
		expected = []map[string]string{
			{"URIs":"https://snapshot.debian.org/archive/debian/", "Suites":"trixie trixie-updates", "Components":"main", "Signed-By":"/usr/share/keyrings/debian-archive-keyring.gpg"},
			{"URIs":"https://snapshot.debian.org/archive/debian-security/", "Suites":"trixie-security", "Components":"main", "Signed-By":"/usr/share/keyrings/debian-archive-keyring.gpg"},
		}
	case build.Distro == "ubuntu" && build.Release == "24.04":
		expected = []map[string]string{{"URIs":"https://snapshot.ubuntu.com/ubuntu/", "Suites":"noble noble-updates noble-security", "Components":"main universe", "Signed-By":"/usr/share/keyrings/ubuntu-archive-keyring.gpg"}}
	default:
		return errors.New("only Debian 13 and Ubuntu 24.04 snapshots are supported")
	}
	stanzas := strings.Split(strings.TrimSpace(string(data)), "\n\n")
	if len(stanzas) != len(expected) { return errors.New("snapshot sources have an unexpected number of repositories") }
	var selectedTime string
	for i, stanza := range stanzas {
		fields := make(map[string]string)
		for _, line := range strings.Split(stanza, "\n") {
			key, value, ok := strings.Cut(line, ": ")
			if !ok || fields[key] != "" { return errors.New("invalid or duplicate Deb822 source field") }
			fields[key] = value
		}
		if len(fields) != 7 || fields["Types"] != "deb" || fields["Architectures"] != "amd64" || fields["Check-Valid-Until"] != "no" {
			return errors.New("snapshot must require signed amd64 binary repositories; unreviewed source options are forbidden")
		}
		prefix := expected[i]["URIs"]
		stamp := strings.TrimSuffix(strings.TrimPrefix(fields["URIs"], prefix), "/")
		if fields["URIs"] != prefix+stamp+"/" || !snapshotTime.MatchString(stamp) { return errors.New("snapshot URL must pin an exact supported HTTPS archive timestamp") }
		if _, err := time.Parse("20060102T150405Z", stamp); err != nil { return errors.New("snapshot timestamp is invalid") }
		if selectedTime != "" && selectedTime != stamp { return errors.New("snapshot repositories must use the same timestamp") }
		selectedTime = stamp
		for key, value := range expected[i] {
			if key != "URIs" && fields[key] != value { return fmt.Errorf("snapshot source %s does not match the selected target", key) }
		}
	}
	return nil
}

func copyEntry(name string, destination *os.Root) (err error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name { return errors.New("--entry must select a clean absolute separately built soteria-entry path") }
	in, err := os.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil { return fmt.Errorf("open separately built entry: %w", err) }
	defer func() { err = errors.Join(err, in.Close()) }()
	var st unix.Stat_t
	if err := unix.Fstat(int(in.Fd()), &st); err != nil { return err }
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o111 == 0 || st.Mode&0o7000 != 0 || st.Nlink != 1 || st.Size <= 0 || st.Size > 64<<20 {
		return errors.New("entry must be a nonempty regular executable with no privileged bits/hard links, within 64 MiB")
	}
	_, capErr := unix.Fgetxattr(int(in.Fd()), "security.capability", nil)
	if !errors.Is(capErr, unix.ENODATA) && !errors.Is(capErr, unix.EOPNOTSUPP) { return errors.New("entry must have no file capabilities") }
	out, err := destination.OpenFile(entryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o555)
	if err != nil { return fmt.Errorf("create runtime entry (package collisions are forbidden): %w", err) }
	_, copyErr := io.CopyN(out, in, st.Size)
	var after unix.Stat_t
	statErr := unix.Fstat(int(in.Fd()), &after)
	if statErr == nil && (st.Dev != after.Dev || st.Ino != after.Ino || st.Mode != after.Mode || st.Size != after.Size ||
		st.Uid != after.Uid || st.Gid != after.Gid || st.Nlink != after.Nlink || st.Mtim != after.Mtim || st.Ctim != after.Ctim) {
		statErr = errors.New("entry changed while it was copied")
	}
	return errors.Join(copyErr, statErr, out.Close())
}

func writeBuildInputs(root string, packages []lockedPackage, sources []byte) (err error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" { return errors.New("build root must be a clean absolute non-root path") }
	if resolved, err := filepath.EvalSymlinks(root); err != nil || resolved != root { return errors.Join(errors.New("build root and its ancestors must not be symlinks"),err) }
	r, err := os.OpenRoot(root)
	if err != nil { return err }
	defer func() { err = errors.Join(err, r.Close()) }()
	if _, err := r.Lstat(toolkit.ManifestName); !errors.Is(err, os.ErrNotExist) { return errors.New("refusing to add build inputs to an already sealed runtime") }
	if err := r.MkdirAll("usr/share/soteria", 0o755); err != nil { return err }
	for _, name := range []string{"usr","usr/share","usr/share/soteria"} {
		info, err := r.Lstat(name)
		if err != nil || !info.IsDir() { return errors.Join(errors.New("build-input parents must be real directories"),err) }
	}
	for name, data := range map[string][]byte{packageLockPath:canonicalLock(packages), snapshotPath:sources} {
		f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o444)
		if err != nil { return err }
		_, writeErr := f.Write(data)
		if err := errors.Join(writeErr, f.Close()); err != nil { return err }
	}
	return nil
}

func verifyBuildInputs(root string, inventory toolkit.Inventory, lock, sources, entry string) error {
	embedded, err := readLock(filepath.Join(root, packageLockPath))
	if err != nil { return fmt.Errorf("runtime must contain its exact archive lock: %w", err) }
	if !slices.Equal(inventoryPackages(embedded), inventory.Build.Packages) { return errors.New("runtime package lock and inventory identities differ") }
	if lock != "" {
		selected, err := readLock(lock)
		if err != nil { return err }
		if !slices.Equal(embedded, selected) { return errors.New("runtime does not match the selected exact package/archive lock") }
	}
	data, err := readSources(filepath.Join(root, snapshotPath), inventory.Build)
	if err != nil { return err }
	if sources != "" {
		selected, err := readSources(sources, inventory.Build)
		if err != nil { return err }
		if !bytes.Equal(data, selected) { return errors.New("runtime snapshot sources differ from the selected target inputs") }
	}
	if entry != "" {
		data, err := readBounded(entry, 64<<20)
		if err != nil { return err }
		sum := sha256.Sum256(data)
		found := false
		for _, file := range inventory.Files {
			if file.Path == entryPath && file.Type == "file" && file.Mode == "0555" && file.SHA256 == hex.EncodeToString(sum[:]) { found = true }
		}
		if !found { return errors.New("runtime trusted entry does not match this separately built soteria-entry") }
	}
	return nil
}
