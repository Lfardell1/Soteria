// Package toolkit verifies the admin-installed, immutable runtime. Verification
// never discovers host tools, copies files, installs packages, or mounts anything.
package toolkit

import (
	"bytes"
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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const Root = "/usr/lib/soteria/runtime"
const ManifestName = ".soteria-manifest.json"

const maxManifestBytes = 16 << 20
const maxEntries = 100000

// Inventory is also the version-1 manifest format. Files contains every real
// tree entry except the root directory and ManifestName. Paths are clean relative
// slash paths. Modes are four-digit octal strings. Only regular files have
// sha256; only symlinks have target. The manifest itself must be root:root 0444.
type Inventory struct {
	Version int           `json:"version"`
	Build   BuildMetadata `json:"build"`
	Files   []Entry       `json:"files"`
	Digest  string        `json:"digest"`
}

type BuildMetadata struct {
	Distro       string    `json:"distro"`
	Release      string    `json:"release"`
	Architecture string    `json:"architecture"`
	Packages     []Package `json:"packages"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Entry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

var requiredDirectories = []string{"proc", "dev", "home", "home/workspace", "work", "tmp", "run", "var", "etc"}
var requiredExecutables = []string{
	"bin/bash", "usr/bin/setpriv", "usr/bin/setsid", "usr/bin/env", "usr/bin/ls", "usr/bin/cat",
	"usr/bin/cp", "usr/bin/mv", "usr/bin/rm", "usr/bin/mkdir", "usr/bin/find", "usr/bin/grep",
	"usr/bin/sed", "usr/bin/nano", "usr/bin/curl", "usr/bin/jq", "usr/bin/git", "usr/bin/python3",
	"usr/bin/openssl", "usr/bin/tar", "usr/bin/gzip", "usr/libexec/soteria-entry",
}
var requiredPackages = []string{
	"bash", "coreutils", "findutils", "grep", "sed", "nano", "curl", "jq", "git", "python3",
	"openssl", "ca-certificates", "tar", "gzip", "util-linux",
}
var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
var packageVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.+:~_-]*$`)
var privateKey = regexp.MustCompile(`(?m)(^|\n)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\r?\n(?:Proc-Type: [^\r\n]*\r?\n|DEK-Info: [^\r\n]*\r?\n|\r?\n)*[A-Za-z0-9+/]{16}`)

// Digest returns sha256:<lowercase hex> for the compact encoding/json encoding
// of {version,build,files}, in that field order, with packages sorted by name and
// files sorted by path. Empty sha256/target fields are omitted. Digest is not a
// signature and does not authenticate a build against a malicious administrator.
func Digest(inventory Inventory) (string, error) {
	inventory = canonical(inventory)
	payload := struct {
		Version int           `json:"version"`
		Build   BuildMetadata `json:"build"`
		Files   []Entry       `json:"files"`
	}{inventory.Version, inventory.Build, inventory.Files}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonical(inventory Inventory) Inventory {
	inventory.Files = append([]Entry(nil), inventory.Files...)
	inventory.Build.Packages = append([]Package(nil), inventory.Build.Packages...)
	sort.Slice(inventory.Files, func(i, j int) bool { return inventory.Files[i].Path < inventory.Files[j].Path })
	sort.Slice(inventory.Build.Packages, func(i, j int) bool { return inventory.Build.Packages[i].Name < inventory.Build.Packages[j].Name })
	return inventory
}

// Verify is read-only and works both for an unprivileged doctor and the root
// service. It requires root-owned immutable files/directories, safe ancestors,
// complete inventory coverage, pinned build metadata, and the useful baseline.
func Verify(root string) (Inventory, error) {
	return (verifier{stat: unix.Fstatat, capability: unix.Fgetxattr}).verify(root)
}

// Only real stat/xattr boundaries are replaceable in tests; no broad bypass of
// path, hash, mode, symlink, inventory, or build validation is provided.
type verifier struct {
	stat       func(int, string, *unix.Stat_t, int) error
	capability func(int, string, []byte) (int, error)
}

func (v verifier) verify(root string) (inventory Inventory, err error) {
	fd, rootStat, err := v.openRoot(root)
	if err != nil {
		return Inventory{}, err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	data, err := v.readManifest(fd)
	if err != nil {
		return Inventory{}, err
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Inventory{}, fmt.Errorf("decode runtime manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		return Inventory{}, fmt.Errorf("decode runtime manifest: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Inventory{}, errors.New("runtime manifest contains trailing JSON")
	}
	inventory = canonical(inventory)
	entries, err := validateInventory(inventory)
	if err != nil {
		return Inventory{}, err
	}
	digest, err := Digest(inventory)
	if err != nil {
		return Inventory{}, err
	}
	if inventory.Digest != digest {
		return Inventory{}, errors.New("runtime manifest digest mismatch")
	}
	seen := make(map[string]bool, len(entries))
	if err := v.walk(fd, "", entries, seen, 0); err != nil {
		return Inventory{}, err
	}
	if len(seen) != len(entries) {
		for _, entry := range inventory.Files {
			if !seen[entry.Path] {
				return Inventory{}, fmt.Errorf("inventoried runtime entry is missing: %s", entry.Path)
			}
		}
	}
	var after unix.Stat_t
	if err := v.stat(fd, "", &after, unix.AT_EMPTY_PATH); err != nil || !unchanged(rootStat, after) {
		return Inventory{}, errors.Join(errors.New("runtime root changed during verification"), err)
	}
	// Reopening also detects replacement of the supplied root pathname while
	// descriptor-relative traversal was in progress.
	checkFD, checkStat, err := v.openRoot(root)
	if err != nil {
		return Inventory{}, err
	}
	closeErr := unix.Close(checkFD)
	if !unchanged(rootStat, checkStat) {
		return Inventory{}, errors.Join(errors.New("runtime root pathname changed during verification"), closeErr)
	}
	if closeErr != nil {
		return Inventory{}, closeErr
	}
	return inventory, nil
}

func (v verifier) openRoot(root string) (int, unix.Stat_t, error) {
	var st unix.Stat_t
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return -1, st, errors.New("runtime root must be a clean absolute non-root path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, st, err
	}
	parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
	for i, component := range parts {
		if err := v.stat(fd, "", &st, unix.AT_EMPTY_PATH); err != nil {
			return -1, st, errors.Join(err, unix.Close(fd))
		}
		// A root-owned sticky ancestor (e.g. /tmp in tests) cannot have its
		// root-owned child replaced by another user. Other writable ancestors fail.
		if st.Uid != 0 || st.Gid != 0 || (st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0) {
			ancestor := "/" + strings.Join(parts[:i], "/")
			return -1, st, errors.Join(fmt.Errorf("runtime ancestor %s is not safely root-owned (uid=%d gid=%d mode=%#o)", ancestor, st.Uid, st.Gid, st.Mode&0o7777), unix.Close(fd))
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(fd)
		if openErr != nil || closeErr != nil {
			if openErr == nil {
				closeErr = errors.Join(closeErr, unix.Close(next))
			}
			return -1, st, fmt.Errorf("open runtime path without symlinks: %w", errors.Join(openErr, closeErr))
		}
		fd = next
		if i == len(parts)-1 {
			if err := v.stat(fd, "", &st, unix.AT_EMPTY_PATH); err != nil {
				return -1, st, errors.Join(err, unix.Close(fd))
			}
			if err := validateStat("runtime root", st, "directory"); err != nil {
				return -1, st, errors.Join(err, unix.Close(fd))
			}
			if err := v.noCapabilities(fd); err != nil {
				return -1, st, errors.Join(err, unix.Close(fd))
			}
		}
	}
	return fd, st, nil
}

func (v verifier) readManifest(root int) ([]byte, error) {
	var before unix.Stat_t
	if err := v.stat(root, ManifestName, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, fmt.Errorf("stat runtime manifest: %w", err)
	}
	if err := validateStat(ManifestName, before, "file"); err != nil {
		return nil, err
	}
	if before.Mode&0o7777 != 0o444 {
		return nil, errors.New("runtime manifest must have mode 0444")
	}
	fd, err := unix.Openat(root, ManifestName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open runtime manifest: %w", err)
	}
	f := os.NewFile(uintptr(fd), ManifestName)
	var opened unix.Stat_t
	if err := v.stat(fd, "", &opened, unix.AT_EMPTY_PATH); err != nil || !unchanged(before, opened) {
		return nil, errors.Join(errors.New("runtime manifest changed before opening"), err, f.Close())
	}
	if err := v.noCapabilities(fd); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	var after unix.Stat_t
	statErr := v.stat(fd, "", &after, unix.AT_EMPTY_PATH)
	closeErr := f.Close()
	if err := errors.Join(readErr, statErr, closeErr); err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, errors.New("runtime manifest exceeds 16 MiB")
	}
	if !unchanged(before, after) {
		return nil, errors.New("runtime manifest changed while being read")
	}
	return data, nil
}

func validateInventory(inventory Inventory) (map[string]Entry, error) {
	if inventory.Version != 1 {
		return nil, errors.New("runtime manifest version must be 1")
	}
	build := inventory.Build
	if (build.Distro != "debian" || build.Release != "13") && (build.Distro != "ubuntu" || build.Release != "24.04") {
		return nil, errors.New("runtime build must pin Debian 13 or Ubuntu 24.04")
	}
	if build.Architecture != "amd64" {
		return nil, errors.New("runtime architecture must be amd64")
	}
	packages := make(map[string]bool, len(build.Packages))
	for _, pkg := range build.Packages {
		if !packageName.MatchString(pkg.Name) || !packageVersion.MatchString(pkg.Version) || packages[pkg.Name] {
			return nil, errors.New("runtime packages must have unique names and exact pinned versions")
		}
		packages[pkg.Name] = true
	}
	for _, name := range requiredPackages {
		if !packages[name] {
			return nil, fmt.Errorf("runtime build metadata lacks required package %s", name)
		}
	}
	if len(inventory.Files) == 0 || len(inventory.Files) > maxEntries {
		return nil, errors.New("runtime inventory must contain 1..100000 entries")
	}
	entries := make(map[string]Entry, len(inventory.Files))
	for _, entry := range inventory.Files {
		if !safePath(entry.Path) || entry.Path == ManifestName || secretPath(entry.Path) {
			return nil, fmt.Errorf("unsafe or secret runtime inventory path: %q", entry.Path)
		}
		if _, exists := entries[entry.Path]; exists {
			return nil, fmt.Errorf("duplicate runtime inventory path: %s", entry.Path)
		}
		mode, err := parseMode(entry.Mode)
		if err != nil {
			return nil, fmt.Errorf("runtime mode for %s: %w", entry.Path, err)
		}
		switch entry.Type {
		case "directory":
			if mode != 0o555 || entry.SHA256 != "" || entry.Target != "" {
				return nil, fmt.Errorf("invalid immutable directory metadata: %s", entry.Path)
			}
		case "file":
			if (mode != 0o444 && mode != 0o555) || !validHash(entry.SHA256) || entry.Target != "" {
				return nil, fmt.Errorf("invalid immutable file metadata: %s", entry.Path)
			}
		case "symlink":
			if mode != 0o777 || entry.SHA256 != "" || !safeTarget(entry.Target) {
				return nil, fmt.Errorf("unsafe runtime symlink metadata: %s", entry.Path)
			}
		default:
			return nil, fmt.Errorf("unsupported runtime entry type for %s", entry.Path)
		}
		entries[entry.Path] = entry
	}
	for _, entry := range inventory.Files {
		if parent := path.Dir(entry.Path); parent != "." && entries[parent].Type != "directory" {
			return nil, fmt.Errorf("runtime entry lacks an inventoried real parent directory: %s", entry.Path)
		}
		if entry.Type == "symlink" {
			if _, err := resolve(entries, entry.Path); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range requiredDirectories {
		if entries[name].Type != "directory" {
			return nil, fmt.Errorf("runtime lacks required real directory /%s", name)
		}
	}
	for _, name := range requiredExecutables {
		resolved, err := resolve(entries, name)
		if err != nil || entries[resolved].Type != "file" || entries[resolved].Mode != "0555" {
			return nil, fmt.Errorf("runtime lacks required immutable executable /%s", name)
		}
	}
	if entries["etc/ssl/certs/ca-certificates.crt"].Type != "file" {
		return nil, errors.New("runtime lacks the public CA certificate bundle /etc/ssl/certs/ca-certificates.crt")
	}
	return entries, nil
}

func (v verifier) walk(fd int, prefix string, entries map[string]Entry, seen map[string]bool, depth int) error {
	if depth > 64 {
		return errors.New("runtime directory depth exceeds 64")
	}
	var before unix.Stat_t
	if err := v.stat(fd, "", &before, unix.AT_EMPTY_PATH); err != nil {
		return err
	}
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dup), prefix)
	children, readErr := dir.ReadDir(maxEntries + 2)
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if err := errors.Join(readErr, dir.Close()); err != nil {
		return err
	}
	if len(children) > maxEntries+1 {
		return errors.New("runtime directory exceeds inventory entry limit")
	}
	for _, child := range children {
		name := path.Join(prefix, child.Name())
		if name == ManifestName {
			continue
		}
		entry, exists := entries[name]
		if !exists || len(seen) >= maxEntries {
			return fmt.Errorf("unlisted runtime entry: %s", name)
		}
		var st unix.Stat_t
		if err := v.stat(fd, child.Name(), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if err := validateStat(name, st, entry.Type); err != nil {
			return err
		}
		mode, _ := parseMode(entry.Mode)
		if st.Mode&0o7777 != mode {
			return fmt.Errorf("runtime mode mismatch: %s", name)
		}
		if st.Dev != before.Dev {
			return fmt.Errorf("runtime entry crosses a filesystem boundary: %s", name)
		}
		seen[name] = true
		if entry.Type == "symlink" {
			buffer := make([]byte, 4096)
			n, err := unix.Readlinkat(fd, child.Name(), buffer)
			if err != nil || n == len(buffer) || string(buffer[:n]) != entry.Target {
				return errors.Join(fmt.Errorf("runtime symlink target mismatch: %s", name), err)
			}
			continue
		}
		if err := v.verifyChild(fd, child.Name(), name, entry, st, entries, seen, depth); err != nil {
			return err
		}
	}
	var after unix.Stat_t
	if err := v.stat(fd, "", &after, unix.AT_EMPTY_PATH); err != nil || !unchanged(before, after) {
		return errors.Join(fmt.Errorf("runtime directory changed during verification: %s", prefix), err)
	}
	return nil
}

func (v verifier) verifyChild(parent int, base, name string, entry Entry, st unix.Stat_t, entries map[string]Entry, seen map[string]bool, depth int) (err error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if entry.Type == "directory" {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(parent, base, flags, 0)
	if err != nil {
		return fmt.Errorf("open immutable runtime entry %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { err = errors.Join(err, f.Close()) }()
	var before unix.Stat_t
	if err := v.stat(fd, "", &before, unix.AT_EMPTY_PATH); err != nil || !unchanged(st, before) {
		return errors.Join(fmt.Errorf("runtime entry changed before opening: %s", name), err)
	}
	if err := v.noCapabilities(fd); err != nil {
		return fmt.Errorf("runtime entry %s: %w", name, err)
	}
	if entry.Type == "directory" {
		return v.walk(fd, name, entries, seen, depth+1)
	}
	hash := sha256.New()
	guard := &keyGuard{}
	if _, err := io.Copy(io.MultiWriter(hash, guard), f); err != nil {
		return fmt.Errorf("read runtime file %s: %w", name, err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("runtime file digest mismatch: %s", name)
	}
	var after unix.Stat_t
	if err := v.stat(fd, "", &after, unix.AT_EMPTY_PATH); err != nil || !unchanged(before, after) {
		return errors.Join(fmt.Errorf("runtime file changed during verification: %s", name), err)
	}
	return nil
}

func validateStat(name string, st unix.Stat_t, kind string) error {
	if st.Uid != 0 || st.Gid != 0 {
		return fmt.Errorf("runtime entry is not root:root owned: %s", name)
	}
	want := uint32(unix.S_IFREG)
	if kind == "directory" {
		want = unix.S_IFDIR
	} else if kind == "symlink" {
		want = unix.S_IFLNK
	} else if kind != "file" {
		return fmt.Errorf("unsupported runtime object: %s", name)
	}
	if st.Mode&unix.S_IFMT != want {
		return fmt.Errorf("runtime type mismatch or special object: %s", name)
	}
	if st.Mode&0o7000 != 0 || (kind != "symlink" && st.Mode&0o222 != 0) {
		return fmt.Errorf("runtime entry is writable or has privileged mode bits: %s", name)
	}
	if kind == "directory" && st.Mode&0o777 != 0o555 {
		return fmt.Errorf("runtime directory is not universally readable/searchable: %s", name)
	}
	if kind == "file" && st.Mode&0o444 != 0o444 {
		return fmt.Errorf("runtime file is not unprivileged-readable: %s", name)
	}
	return nil
}

func (v verifier) noCapabilities(fd int) error {
	_, err := v.capability(fd, "security.capability", nil)
	if err == nil {
		return errors.New("runtime file has a security.capability attribute")
	}
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	return fmt.Errorf("inspect runtime capabilities: %w", err)
}

func unchanged(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Mode == b.Mode && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim && a.Nlink == b.Nlink
}

func parseMode(mode string) (uint32, error) {
	if len(mode) != 4 {
		return 0, errors.New("mode must be a four-digit octal string")
	}
	for _, digit := range mode {
		if digit < '0' || digit > '7' {
			return 0, errors.New("mode must be a four-digit octal string")
		}
	}
	value, err := strconv.ParseUint(mode, 8, 12)
	return uint32(value), err
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, digit := range value {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

func safePath(name string) bool {
	if !fs.ValidPath(name) || name == "." || len(name) > 4095 || strings.Contains(name, `\`) || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func safeTarget(target string) bool {
	if target == "" || path.IsAbs(target) || len(target) > 4095 || strings.Contains(target, `\`) || !utf8.ValidString(target) {
		return false
	}
	for _, r := range target {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// resolve uses the complete inventory, not host symlink evaluation. Each '..'
// is checked before normalizing, so an escape followed by re-entry still fails.
func resolve(entries map[string]Entry, name string) (string, error) {
	queue := strings.Split(name, "/")
	var stack []string
	links := 0
	for len(queue) > 0 {
		part := queue[0]
		queue = queue[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(stack) == 0 {
				return "", fmt.Errorf("runtime symlink escapes the runtime: %s", name)
			}
			stack = stack[:len(stack)-1]
			continue
		}
		stack = append(stack, part)
		current := strings.Join(stack, "/")
		entry, exists := entries[current]
		if !exists || secretPath(current) {
			return "", fmt.Errorf("runtime symlink is dangling or targets an unsafe path: %s", name)
		}
		if entry.Type == "symlink" {
			links++
			if links > 40 || !safeTarget(entry.Target) {
				return "", fmt.Errorf("runtime symlink is cyclic or unsafe: %s", name)
			}
			stack = stack[:len(stack)-1]
			queue = append(strings.Split(entry.Target, "/"), queue...)
		} else if len(queue) > 0 && entry.Type != "directory" {
			return "", fmt.Errorf("runtime symlink traverses a non-directory: %s", name)
		}
	}
	if len(stack) == 0 {
		return "", fmt.Errorf("runtime symlink targets the runtime root: %s", name)
	}
	return strings.Join(stack, "/"), nil
}

func secretPath(name string) bool {
	for _, prefix := range []string{"root", "etc/shadow", "etc/gshadow", "etc/security/opasswd", "etc/ssl/private", "etc/wireguard", "etc/NetworkManager/system-connections", "etc/soteria/profiles", "etc/machine-id", "var/lib/dbus/machine-id"} {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	// These are empty mount placeholders, never a source of host state.
	for _, prefix := range []string{"dev/", "proc/", "sys/", "tmp/", "run/", "work/", "home/workspace/"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	if strings.HasPrefix(name, "home/") && name != "home/workspace" {
		return true
	}
	for _, component := range strings.Split(name, "/") {
		switch component {
		case ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".env", ".bash_history", ".python_history", "credentials.json", "credentials.db", "access_tokens.db", "application_default_credentials.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
			return true
		}
	}
	base := path.Base(name)
	return strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx") ||
		(strings.HasPrefix(name, "etc/ssh/ssh_host_") && !strings.HasSuffix(name, ".pub"))
}

type keyGuard struct{ tail []byte }

func (g *keyGuard) Write(data []byte) (int, error) {
	window := append(g.tail, data...)
	if privateKey.Match(window) {
		return 0, errors.New("runtime contains a PEM private key")
	}
	if len(window) > 2048 {
		window = window[len(window)-2048:]
	}
	g.tail = append(g.tail[:0], window...)
	return len(data), nil
}

func rejectDuplicateKeys(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("runtime manifest is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value func(int, string) error
	value = func(depth int, scope string) error {
		if depth > 64 {
			return errors.New("manifest JSON nesting exceeds 64")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("null is not permitted in a runtime manifest")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			var allowed string
			switch scope {
			case "inventory":
				allowed = "|version|build|files|digest|"
			case "build":
				allowed = "|distro|release|architecture|packages|"
			case "package":
				allowed = "|name|version|"
			case "entry":
				allowed = "|path|type|mode|sha256|target|"
			default:
				return errors.New("unexpected object in runtime manifest")
			}
			keys := make(map[string]bool)
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || keys[key] {
					return errors.New("duplicate or invalid manifest JSON key")
				}
				if !strings.Contains(allowed, "|"+key+"|") {
					return errors.New("unknown or incorrectly cased runtime manifest key")
				}
				keys[key] = true
				nextScope := "scalar"
				if scope == "inventory" && key == "build" {
					nextScope = "build"
				} else if scope == "inventory" && key == "files" {
					nextScope = "files"
				} else if scope == "build" && key == "packages" {
					nextScope = "packages"
				}
				if err := value(depth+1, nextScope); err != nil {
					return err
				}
			}
		case '[':
			element := "entry"
			if scope == "packages" {
				element = "package"
			} else if scope != "files" {
				return errors.New("unexpected array in runtime manifest")
			}
			for decoder.More() {
				if err := value(depth+1, element); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected manifest JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(0, "inventory"); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing manifest JSON")
	}
	return nil
}
