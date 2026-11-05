//go:build linux

package toolkit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func freshBuildFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	if err := os.Chmod(f.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.root, ManifestName)); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestGenerateExactVerifierManifest(t *testing.T) {
	f := freshBuildFixture(t)
	bin := filepath.Join(f.root, "usr/bin")
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/bash", filepath.Join(bin, "sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(bin, "bash"), os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Generate(f.root, f.inv.Build)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := Digest(got)
	if err != nil || got.Digest != wantDigest {
		t.Fatalf("generator did not use exact Digest: %q %v", got.Digest, err)
	}
	verified, err := f.v.verify(f.root)
	if err != nil || verified.Digest != got.Digest {
		t.Fatalf("production content verifier disagrees: %v", err)
	}
	link, err := os.Readlink(filepath.Join(bin, "sh"))
	if err != nil || link != "bash" {
		t.Fatalf("absolute link not normalized internally: %q %v", link, err)
	}
	if _, err := Generate(f.root, f.inv.Build); err == nil {
		t.Fatal("generation replaced an existing manifest")
	}
}

func TestGenerateRejectsUnsafeBuildContent(t *testing.T) {
	for _, mutation := range []string{"secret path", "private key", "escaping link", "dangling link", "hard link", "unpinned metadata"} {
		t.Run(mutation, func(t *testing.T) {
			f := freshBuildFixture(t)
			switch mutation {
			case "secret path":
				if err := os.WriteFile(filepath.Join(f.root, ".env"), []byte("TOKEN=not-a-real-secret"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "private key":
				if err := os.WriteFile(filepath.Join(f.root, "public-looking-file"), []byte("-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASC\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "escaping link", "dangling link":
				target := "../outside"
				if mutation == "dangling link" {
					target = "missing"
				}
				if err := os.Symlink(target, filepath.Join(f.root, "link")); err != nil {
					t.Fatal(err)
				}
			case "hard link":
				if err := os.Link(filepath.Join(f.root, "usr/bin/bash"), filepath.Join(f.root, "hardlink")); err != nil {
					t.Fatal(err)
				}
			case "unpinned metadata":
				f.inv.Build.Packages[0].Version = "latest"
			}
			if _, err := Generate(f.root, f.inv.Build); err == nil {
				t.Fatal("accepted " + mutation)
			}
			if _, err := os.Lstat(filepath.Join(f.root, ManifestName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failure published a manifest: %v", err)
			}
		})
	}
}

func TestGeneratedManifestDeterministic(t *testing.T) {
	a, b := freshBuildFixture(t), freshBuildFixture(t)
	first, err := Generate(a.root, a.inv.Build)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(b.root, b.inv.Build)
	if err != nil || first.Digest != second.Digest {
		t.Fatalf("same staged bytes changed digest: %v", err)
	}
	if _, err := Generate("/", a.inv.Build); err == nil || !strings.Contains(err.Error(), "non-root") {
		t.Fatalf("accepted unsafe build root: %v", err)
	}
}

func TestGenerateRejectsAliasedRootBeforeMutation(t *testing.T) {
	f := freshBuildFixture(t)
	name := filepath.Join(f.root, "usr/bin/bash")
	if err := os.Chmod(name, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "runtime-alias")
	if err := os.Symlink(f.root, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(alias, f.inv.Build); err == nil {
		t.Fatal("accepted an aliased build root")
	}
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("aliased build root was mutated before rejection: %v", err)
	}
}
