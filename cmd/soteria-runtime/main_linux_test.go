//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Lfardell1/Soteria/internal/toolkit"
)

func TestPackageLock(t *testing.T) {
	for _, line := range []string{
		"", "bash\tlatest\tamd64\t" + strings.Repeat("a", 64),
		"bash\t5.2-1\tarm64\t" + strings.Repeat("a", 64),
		"bash\t5.2-1\tamd64\tbad", "../bash\t5.2\tamd64\t" + strings.Repeat("a", 64),
		strings.Repeat("bash\t5.2-1\tamd64\t"+strings.Repeat("a", 64)+"\n", 2),
	} {
		name := filepath.Join(t.TempDir(), "packages.lock")
		if err := os.WriteFile(name, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readLock(name); err == nil {
			t.Fatalf("accepted invalid package lock %q", line)
		}
	}
	name := filepath.Join(t.TempDir(), "packages.lock")
	if err := os.WriteFile(name, []byte("coreutils\t9.7-1\tamd64\t"+strings.Repeat("a", 64)+"\nbash\t5.2.37-2+b1\tamd64\t"+strings.Repeat("b", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	packages, err := readLock(name)
	if err != nil || len(packages) != 2 || packages[0].Name != "bash" {
		t.Fatalf("exact package lock rejected: %+v %v", packages, err)
	}
}

func TestRuntimeSBOMContainsExactPackageIdentities(t *testing.T) {
	inventory := toolkit.Inventory{Digest: "sha256:" + strings.Repeat("a", 64), Build: toolkit.BuildMetadata{
		Distro: "debian", Release: "13", Architecture: "amd64", Packages: []toolkit.Package{{Name: "bash", Version: "5.2.37-2+b1"}},
	}}
	var output bytes.Buffer
	if err := runtimeSBOM(inventory, &output); err != nil {
		t.Fatal(err)
	}
	var got bom
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Format != "CycloneDX" || got.Spec != "1.6" || len(got.Components) != 2 ||
		got.Components[1].PURL != "pkg:deb/debian/bash@5.2.37-2+b1?distro=debian-13" {
		t.Fatalf("incorrect runtime package SBOM: %s", output.String())
	}
}

func TestBuilderRequiresExplicitUnprivilegedOptIn(t *testing.T) {
	t.Setenv("SOTERIA_DISPOSABLE_BUILD", "")
	if err := run([]string{"prepare", "--source", "/", "--root", "/"}, &bytes.Buffer{}); err == nil {
		t.Fatal("prepare accepted missing build opt-in")
	}
}

func TestGoSBOMDoesNotRelabelUnrelatedGoBinaryAsSoteria(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := goSBOM(self, "0.0.0-dev", &bytes.Buffer{}); err == nil {
		t.Fatal("misrepresented the test/helper executable as a Soteria CLI artifact")
	}
}

func TestPrepareUsesOnlyPublicPackageInputs(t *testing.T) {
	source := t.TempDir()
	destination := filepath.Join(t.TempDir(), "runtime")
	write := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(source, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, name), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	build := toolkit.BuildMetadata{Distro: "debian", Release: "13", Architecture: "amd64"}
	for _, name := range []string{"bash", "coreutils", "findutils", "grep", "sed", "nano", "curl", "jq", "git", "python3", "openssl", "ca-certificates", "tar", "gzip", "util-linux"} {
		build.Packages = append(build.Packages, toolkit.Package{Name: name, Version: "1.0-1"})
	}
	for _, name := range []string{"bash", "setpriv", "setsid", "env", "ls", "cat", "cp", "mv", "rm", "mkdir", "find", "grep", "sed", "nano", "curl", "jq", "git", "python3", "openssl", "tar", "gzip"} {
		write("usr/bin/"+name, []byte("synthetic package executable fixture\n"), 0o755)
	}
	write("etc/ssl/openssl.cnf", []byte("# public package configuration fixture\n"), 0o644)
	write("etc/shadow", []byte("never copied\n"), 0o600)
	write("etc/resolv.conf", []byte("host resolver must not be copied\n"), 0o644)
	write("home/builder/.ssh/id_ed25519", []byte("never copied\n"), 0o600)
	if err := os.MkdirAll(filepath.Join(source, "usr/lib/ssl"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/ssl/private", filepath.Join(source, "usr/lib/ssl/private")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/ssl/certs", filepath.Join(source, "usr/lib/ssl/certs")); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic test CA, not runtime trust"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	write("usr/share/ca-certificates/test.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	entry := filepath.Join(t.TempDir(), "soteria-entry")
	entryData := []byte("synthetic entry fixture, not a runnable program or release artifact\n")
	if err := os.WriteFile(entry, entryData, 0o755); err != nil { t.Fatal(err) }
	if err := prepare(source, destination, entry, build); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(destination, func(name string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				return os.Chmod(name, 0o700)
			}
			return err
		})
	})
	packages := fixtureLock(build.Packages)
	if err := writeBuildInputs(destination, packages, []byte(debianSources)); err != nil { t.Fatal(err) }
	inventory, err := toolkit.Generate(destination, build)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := toolkit.VerifyStaging(destination); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etc/shadow", "home/builder", "usr/lib/ssl/private"} {
		if _, err := os.Lstat(filepath.Join(destination, name)); !os.IsNotExist(err) {
			t.Fatalf("copied private/host input %s: %v", name, err)
		}
	}
	if err := verifyBuildInputs(destination, inventory, "", "", entry); err != nil { t.Fatal(err) }
	gotEntry, err := os.ReadFile(filepath.Join(destination, entryPath))
	if err != nil || !bytes.Equal(gotEntry, entryData) { t.Fatalf("separate trusted entry not copied exactly: %q %v",gotEntry,err) }
	bundle, err := os.ReadFile(filepath.Join(destination, "etc/ssl/certs/ca-certificates.crt"))
	if err != nil || len(bundle) == 0 { t.Fatalf("public CA bundle lost: %v",err) }
	resolver, err := os.ReadFile(filepath.Join(destination, "etc/resolv.conf"))
	if err != nil || len(resolver) != 0 {
		t.Fatalf("copied host resolver into runtime: %q %v", resolver, err)
	}
}

func fixtureLock(packages []toolkit.Package) []lockedPackage {
	var result []lockedPackage
	for _, p := range packages {
		sum := sha256.Sum256([]byte("synthetic archive fixture: " + p.Name))
		result = append(result, lockedPackage{Name:p.Name, Version:p.Version, Architecture:"amd64", SHA256:fmt.Sprintf("%x",sum)})
	}
	sort.Slice(result,func(i,j int)bool{return result[i].Name<result[j].Name})
	return result
}

func TestPrepareRejectsAliasedSourceBeforeCreatingOutput(t *testing.T) {
	source := t.TempDir()
	alias := filepath.Join(t.TempDir(), "package-alias")
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "runtime")
	if err := prepare(alias, destination, "", toolkit.BuildMetadata{Distro: "debian", Release: "13"}); err == nil {
		t.Fatal("accepted aliased package source")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("created output before checking package source: %v", err)
	}
}
