package toolkit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fixture struct {
	root string
	inv  Inventory
	v    verifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{root: t.TempDir(), inv: Inventory{Version: 1, Build: BuildMetadata{Distro: "debian", Release: "13", Architecture: "amd64"}}}
	// Virtualize only ownership at the real stat boundary, so these exact tests
	// also run unprivileged. All path/mode/hash/xattr operations remain real.
	f.v = verifier{
		stat: func(fd int, name string, st *unix.Stat_t, flags int) error {
			if err := unix.Fstatat(fd, name, st, flags); err != nil {
				return err
			}
			st.Uid, st.Gid = 0, 0
			return nil
		},
		capability: unix.Fgetxattr,
	}
	t.Cleanup(func() {
		// Make only this test-owned immutable fixture removable by its creator.
		_ = filepath.WalkDir(f.root, func(name string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				return os.Chmod(name, 0o700)
			}
			return err
		})
	})
	for _, name := range requiredPackages {
		f.inv.Build.Packages = append(f.inv.Build.Packages, Package{Name: name, Version: "1.0-1"})
	}
	dirs := map[string]bool{}
	addDir := func(name string) {
		for name != "." {
			dirs[name] = true
			name = path.Dir(name)
		}
	}
	for _, name := range requiredDirectories {
		addDir(name)
	}
	addDir("usr/bin")
	addDir("usr/libexec")
	addDir("etc/ssl/certs")
	for name := range dirs {
		if err := os.MkdirAll(filepath.Join(f.root, name), 0o755); err != nil {
			t.Fatal(err)
		}
		f.inv.Files = append(f.inv.Files, Entry{Path: name, Type: "directory", Mode: "0555"})
	}
	if err := os.Symlink("usr/bin", filepath.Join(f.root, "bin")); err != nil {
		t.Fatal(err)
	}
	f.inv.Files = append(f.inv.Files, Entry{Path: "bin", Type: "symlink", Mode: "0777", Target: "usr/bin"})
	for _, name := range requiredExecutables {
		if name == "bin/bash" {
			name = "usr/bin/bash"
		}
		data := []byte("#!/bin/bash\n# deterministic runtime fixture: " + name + "\n")
		if err := os.WriteFile(filepath.Join(f.root, name), data, 0o555); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		f.inv.Files = append(f.inv.Files, Entry{Path: name, Type: "file", Mode: "0555", SHA256: hex.EncodeToString(sum[:])})
	}
	certificate := []byte("public certificate bundle fixture\n")
	if err := os.WriteFile(filepath.Join(f.root, "etc/ssl/certs/ca-certificates.crt"), certificate, 0o444); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(certificate)
	f.inv.Files = append(f.inv.Files, Entry{Path: "etc/ssl/certs/ca-certificates.crt", Type: "file", Mode: "0444", SHA256: hex.EncodeToString(sum[:])})
	for name := range dirs {
		if err := os.Chmod(filepath.Join(f.root, name), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	f.writeManifest(t)
	return f
}

func (f *fixture) writeManifest(t *testing.T) {
	t.Helper()
	var err error
	f.inv.Digest, err = Digest(f.inv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(f.inv)
	if err != nil {
		t.Fatal(err)
	}
	f.writeManifestBytes(t, data)
}

func (f *fixture) writeManifestBytes(t *testing.T, data []byte) {
	t.Helper()
	if err := os.Chmod(f.root, 0o755); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(f.root, ManifestName)
	if err := os.Chmod(name, 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.root, 0o555); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) rewriteFile(t *testing.T, relative string, data []byte, mode os.FileMode) {
	t.Helper()
	name := filepath.Join(f.root, relative)
	if err := os.Chmod(name, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyImmutableRuntime(t *testing.T) {
	f := newFixture(t)
	got, err := f.v.verify(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != f.inv.Digest || got.Version != 1 || len(got.Files) != len(f.inv.Files) {
		t.Fatalf("wrong verified inventory: %+v", got)
	}
	if !sort.SliceIsSorted(got.Files, func(i, j int) bool { return got.Files[i].Path < got.Files[j].Path }) {
		t.Fatal("returned inventory is not canonical")
	}
	var hostRoot unix.Stat_t
	if err := unix.Stat("/", &hostRoot); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 && os.Getgid() == 0 && hostRoot.Uid == 0 && hostRoot.Gid == 0 {
		if _, err := Verify(f.root); err != nil {
			t.Fatalf("real root-owned fixture: %v", err)
		}
	} else if _, err := Verify(f.root); err == nil {
		t.Fatal("production verifier accepted non-root ownership")
	}
}

func TestDigestDeterministicAndCoversMetadata(t *testing.T) {
	f := newFixture(t)
	reversed := canonical(f.inv)
	for i, j := 0, len(reversed.Files)-1; i < j; i, j = i+1, j-1 {
		reversed.Files[i], reversed.Files[j] = reversed.Files[j], reversed.Files[i]
	}
	for i, j := 0, len(reversed.Build.Packages)-1; i < j; i, j = i+1, j-1 {
		reversed.Build.Packages[i], reversed.Build.Packages[j] = reversed.Build.Packages[j], reversed.Build.Packages[i]
	}
	got, err := Digest(reversed)
	if err != nil || got != f.inv.Digest {
		t.Fatalf("ordering changed digest: %s %v", got, err)
	}
	reversed.Build.Packages[0].Version = "2.0-1"
	changed, err := Digest(reversed)
	if err != nil || changed == got {
		t.Fatalf("pinned package metadata not covered: %s %v", changed, err)
	}
	reversed = canonical(f.inv)
	reversed.Files[0].Mode = "0755"
	changed, _ = Digest(reversed)
	if changed == got {
		t.Fatal("file permissions not covered by digest")
	}
}

func TestDigestCanonicalEncoding(t *testing.T) {
	inventory := Inventory{
		Version: 1,
		Build:   BuildMetadata{Distro: "debian", Release: "13", Architecture: "amd64", Packages: []Package{{Name: "bash", Version: "1.0"}}},
		Files:   []Entry{{Path: "bin", Type: "symlink", Mode: "0777", Target: "usr/bin"}},
	}
	payload := `{"version":1,"build":{"distro":"debian","release":"13","architecture":"amd64","packages":[{"name":"bash","version":"1.0"}]},"files":[{"path":"bin","type":"symlink","mode":"0777","target":"usr/bin"}]}`
	sum := sha256.Sum256([]byte(payload))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got, err := Digest(inventory); err != nil || got != want {
		t.Fatalf("canonical v1 encoding changed: got %s, want %s, err %v", got, want, err)
	}
}

func TestVerifyDetectsFileAndManifestTampering(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		f := newFixture(t)
		f.rewriteFile(t, "usr/bin/bash", []byte("tampered runtime\n"), 0o555)
		if _, err := f.v.verify(f.root); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("missed file tampering: %v", err)
		}
	})
	t.Run("manifest", func(t *testing.T) {
		f := newFixture(t)
		f.inv.Digest = "sha256:" + strings.Repeat("0", 64)
		data, err := json.Marshal(f.inv)
		if err != nil {
			t.Fatal(err)
		}
		f.writeManifestBytes(t, data)
		if _, err := f.v.verify(f.root); err == nil || !strings.Contains(err.Error(), "manifest digest mismatch") {
			t.Fatalf("missed manifest tampering: %v", err)
		}
	})
}

func TestVerifyRejectsWritableAndPrivilegedModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o464, 0o446, os.ModeSetuid | 0o555, os.ModeSetgid | 0o555, 0o400} {
		t.Run(fmt.Sprintf("%#o", mode), func(t *testing.T) {
			f := newFixture(t)
			if err := os.Chmod(filepath.Join(f.root, "usr/bin/bash"), mode); err != nil {
				t.Fatal(err)
			}
			if _, err := f.v.verify(f.root); err == nil {
				t.Fatalf("accepted unsafe mode %#o", mode)
			}
		})
	}
	for _, relative := range []string{"", "usr", ManifestName} {
		t.Run("writable "+relative, func(t *testing.T) {
			f := newFixture(t)
			if err := os.Chmod(filepath.Join(f.root, relative), 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := f.v.verify(f.root); err == nil {
				t.Fatalf("accepted writable %q", relative)
			}
		})
	}
}

func TestVerifyRejectsWrongOwnerSpecialFilesAndCapabilities(t *testing.T) {
	for _, mutation := range []string{"uid", "gid", "device", "block device", "socket", "fifo"} {
		t.Run(mutation, func(t *testing.T) {
			f := newFixture(t)
			stat := f.v.stat
			f.v.stat = func(fd int, name string, st *unix.Stat_t, flags int) error {
				if err := stat(fd, name, st, flags); err != nil {
					return err
				}
				if name == "bash" {
					switch mutation {
					case "uid":
						st.Uid = 12345
					case "gid":
						st.Gid = 12345
					default:
						kinds := map[string]uint32{"device": unix.S_IFCHR, "block device": unix.S_IFBLK, "socket": unix.S_IFSOCK, "fifo": unix.S_IFIFO}
						st.Mode = st.Mode&0o7777 | kinds[mutation]
					}
				}
				return nil
			}
			if _, err := f.v.verify(f.root); err == nil {
				t.Fatalf("accepted %s", mutation)
			}
		})
	}
	for _, failure := range []error{nil, unix.EACCES, unix.EIO} {
		t.Run(fmt.Sprintf("capabilities %v", failure), func(t *testing.T) {
			f := newFixture(t)
			f.v.capability = func(int, string, []byte) (int, error) { return 1, failure }
			if _, err := f.v.verify(f.root); err == nil {
				t.Fatal("accepted capabilities or unverified capability state")
			}
		})
	}
}

func TestVerifyRequiresExactInventory(t *testing.T) {
	t.Run("unlisted file", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Chmod(f.root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.root, "unlisted"), []byte("extra"), 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f.root, 0o555); err != nil {
			t.Fatal(err)
		}
		if _, err := f.v.verify(f.root); err == nil || !strings.Contains(err.Error(), "unlisted") {
			t.Fatalf("missed unlisted file: %v", err)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		f := newFixture(t)
		f.inv.Files = append(f.inv.Files, Entry{Path: "usr/bin/missing", Type: "file", Mode: "0555", SHA256: strings.Repeat("0", 64)})
		f.writeManifest(t)
		if _, err := f.v.verify(f.root); err == nil || !strings.Contains(err.Error(), "missing") {
			t.Fatalf("missed missing entry: %v", err)
		}
	})
	t.Run("duplicate path", func(t *testing.T) {
		f := newFixture(t)
		f.inv.Files = append(f.inv.Files, f.inv.Files[0])
		f.writeManifest(t)
		if _, err := f.v.verify(f.root); err == nil {
			t.Fatal("accepted duplicate path")
		}
	})
}

func TestManifestRejectsUnsafePaths(t *testing.T) {
	for _, name := range []string{"../escape", "/etc/passwd", "usr/../escape", "usr//bin/x", "usr/./x", "usr/bin/", `usr\bin\x`, "usr/bin/evil\nname", ".", ManifestName, "home/workspace/.ssh/id_rsa", "etc/shadow", "etc/ssl/private/server.key", "etc/wireguard/session", "run/service.sock", "usr/share/token.p12", "etc/ssh/ssh_host_ed25519_key"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.inv.Files = append(f.inv.Files, Entry{Path: name, Type: "file", Mode: "0444", SHA256: strings.Repeat("0", 64)})
			f.writeManifest(t)
			if _, err := f.v.verify(f.root); err == nil {
				t.Fatalf("accepted unsafe path %q", name)
			}
		})
	}
}

func TestManifestRejectsUnsafeSymlinks(t *testing.T) {
	for _, target := range []string{"/usr/bin", "../usr/bin", "../../etc/passwd", "usr/../../usr/bin", "missing", "bin", "etc/shadow", "usr/bin/bash/child", "usr\\bin", "usr/bin\n"} {
		t.Run(target, func(t *testing.T) {
			f := newFixture(t)
			for i := range f.inv.Files {
				if f.inv.Files[i].Path == "bin" {
					f.inv.Files[i].Target = target
				}
			}
			f.writeManifest(t)
			if _, err := f.v.verify(f.root); err == nil {
				t.Fatalf("accepted unsafe symlink %q", target)
			}
		})
	}
	t.Run("target changed on disk", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Chmod(f.root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(f.root, "bin")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/usr/bin", filepath.Join(f.root, "bin")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f.root, 0o555); err != nil {
			t.Fatal(err)
		}
		if _, err := f.v.verify(f.root); err == nil || !strings.Contains(err.Error(), "symlink target mismatch") {
			t.Fatalf("missed changed symlink: %v", err)
		}
	})
}

func TestSafeInternalRelativeSymlink(t *testing.T) {
	f := newFixture(t)
	parent := filepath.Join(f.root, "usr/bin")
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../bin/bash", filepath.Join(parent, "sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	f.inv.Files = append(f.inv.Files, Entry{Path: "usr/bin/sh", Type: "symlink", Mode: "0777", Target: "../bin/bash"})
	f.writeManifest(t)
	if _, err := f.v.verify(f.root); err != nil {
		t.Fatalf("safe immutable internal link rejected: %v", err)
	}
}

func TestVerifierRejectsPrivateKeys(t *testing.T) {
	f := newFixture(t)
	data := []byte("-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n")
	f.rewriteFile(t, "usr/bin/bash", data, 0o555)
	sum := sha256.Sum256(data)
	for i := range f.inv.Files {
		if f.inv.Files[i].Path == "usr/bin/bash" {
			f.inv.Files[i].SHA256 = hex.EncodeToString(sum[:])
		}
	}
	f.writeManifest(t)
	if _, err := f.v.verify(f.root); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("accepted a private key with an otherwise valid digest: %v", err)
	}
	guard := &keyGuard{}
	for _, part := range [][]byte{data[:20], data[20:41], data[41:]} {
		_, err := guard.Write(part)
		if err != nil {
			return
		}
	}
	t.Fatal("split-write private key bypassed scanner")
}

func TestManifestRequiresPinnedUsefulRuntime(t *testing.T) {
	for _, mutation := range []string{"version", "distro", "release", "architecture", "package version", "package missing", "package duplicate", "executable missing", "directory missing", "ca bundle missing", "mode", "hash", "parent"} {
		t.Run(mutation, func(t *testing.T) {
			f := newFixture(t)
			switch mutation {
			case "version":
				f.inv.Version = 2
			case "distro":
				f.inv.Build.Distro = "unknown"
			case "release":
				f.inv.Build.Release = "latest"
			case "architecture":
				f.inv.Build.Architecture = "arm64"
			case "package version":
				f.inv.Build.Packages[0].Version = "latest"
			case "package missing":
				f.inv.Build.Packages = f.inv.Build.Packages[1:]
			case "package duplicate":
				f.inv.Build.Packages = append(f.inv.Build.Packages, f.inv.Build.Packages[0])
			case "executable missing", "directory missing", "ca bundle missing":
				remove := map[string]string{"executable missing": "usr/bin/setpriv", "directory missing": "proc", "ca bundle missing": "etc/ssl/certs/ca-certificates.crt"}[mutation]
				for i, entry := range f.inv.Files {
					if entry.Path == remove {
						f.inv.Files = append(f.inv.Files[:i], f.inv.Files[i+1:]...)
						break
					}
				}
			case "mode":
				f.inv.Files[0].Mode = "755"
			case "hash":
				for i := range f.inv.Files {
					if f.inv.Files[i].Type == "file" {
						f.inv.Files[i].SHA256 = "bad"
						break
					}
				}
			case "parent":
				f.inv.Files = append(f.inv.Files, Entry{Path: "absent/child", Type: "directory", Mode: "0555"})
			}
			f.writeManifest(t)
			if _, err := f.v.verify(f.root); err == nil {
				t.Fatalf("accepted invalid build: %s", mutation)
			}
		})
	}
}

func TestManifestStrictJSONAndRootPaths(t *testing.T) {
	for _, mutation := range []string{"unknown", "case alias", "duplicate", "escaped duplicate", "trailing", "null", "invalid UTF-8", "oversize"} {
		t.Run(mutation, func(t *testing.T) {
			f := newFixture(t)
			data, err := json.Marshal(f.inv)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "unknown":
				data = append([]byte(`{"unknown":1,`), data[1:]...)
			case "case alias":
				data = bytes.Replace(data, []byte(`"version"`), []byte(`"Version"`), 1)
			case "duplicate":
				data = append([]byte(`{"version":1,`), data[1:]...)
			case "escaped duplicate":
				data = append([]byte(`{"\u0076ersion":1,`), data[1:]...)
			case "trailing":
				data = append(data, []byte(" {}")...)
			case "null":
				data = []byte("null")
			case "invalid UTF-8":
				data = append([]byte{'"', 0xff, '"'}, data...)
			case "oversize":
				data = bytes.Repeat([]byte(" "), maxManifestBytes+1)
			}
			f.writeManifestBytes(t, data)
			if _, err := f.v.verify(f.root); err == nil {
				t.Fatalf("accepted malformed manifest: %s", mutation)
			}
		})
	}
	f := newFixture(t)
	for _, root := range []string{"", "/", "relative", f.root + "/", f.root + "/../" + filepath.Base(f.root)} {
		if _, err := f.v.verify(root); err == nil {
			t.Errorf("accepted unsafe root %q", root)
		}
	}
	link := filepath.Join(t.TempDir(), "runtime")
	if err := os.Symlink(f.root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.verify(link); err == nil {
		t.Fatal("accepted symlink root")
	}
}

func FuzzManifestJSON(f *testing.F) {
	f.Add([]byte(`{"version":1,"build":{},"files":[],"digest":""}`))
	f.Add([]byte(`{"version":1,"\u0076ersion":1}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		_ = rejectDuplicateKeys(data)
	})
}

func FuzzInternalSymlinkResolution(f *testing.F) {
	f.Add("usr/bin")
	f.Add("../usr/bin")
	f.Add("usr/../../usr/bin")
	f.Add("bin")
	f.Fuzz(func(t *testing.T, target string) {
		if len(target) > 4096 {
			return
		}
		entries := map[string]Entry{
			"bin":     {Path: "bin", Type: "symlink", Mode: "0777", Target: target},
			"usr":     {Path: "usr", Type: "directory", Mode: "0555"},
			"usr/bin": {Path: "usr/bin", Type: "directory", Mode: "0555"},
		}
		resolved, err := resolve(entries, "bin")
		if err == nil && (!safePath(resolved) || entries[resolved].Type != "directory") {
			t.Fatalf("resolution escaped verified immutable entries: %q", resolved)
		}
	})
}
