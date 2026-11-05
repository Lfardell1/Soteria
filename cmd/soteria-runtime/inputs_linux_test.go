//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lfardell1/Soteria/internal/toolkit"
	"golang.org/x/sys/unix"
)

// These are syntax fixtures only, not authenticated archive or VM evidence.
const debianSources = `Types: deb
URIs: https://snapshot.debian.org/archive/debian/20200101T000000Z/
Suites: trixie trixie-updates
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no

Types: deb
URIs: https://snapshot.debian.org/archive/debian-security/20200101T000000Z/
Suites: trixie-security
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
`

func TestSnapshotSourcePolicy(t *testing.T) {
	build := toolkit.BuildMetadata{Distro:"debian",Release:"13"}
	if err := validateSources([]byte(debianSources), build); err != nil { t.Fatal(err) }
	for _, data := range []string{
		strings.Replace(debianSources,"https://snapshot.debian.org/archive/debian/20200101T000000Z/","http://deb.debian.org/debian/",1),
		strings.Replace(debianSources,"20200101T000000Z/","current/",1),
		strings.Replace(debianSources,"20200101T000000Z/","20200230T000000Z/",1),
		strings.Replace(debianSources,"20200101T000000Z/","20200102T000000Z/",1),
		strings.Replace(debianSources,"Signed-By:","Trusted:",1),
		strings.Replace(debianSources,"Types: deb","Types: deb\nTrusted: yes",1),
		strings.Replace(debianSources,"Types: deb","Types: deb\nTypes: deb",1),
		strings.Replace(debianSources,"Architectures: amd64","Architectures: amd64 arm64",1),
		strings.Replace(debianSources,"Suites: trixie trixie-updates","Suites: stable",1),
	} {
		if err := validateSources([]byte(data),build); err == nil { t.Fatalf("accepted unpinned/untrusted source:\n%s",data) }
	}
	if err := validateSources([]byte(debianSources),toolkit.BuildMetadata{Distro:"ubuntu",Release:"24.04"}); err == nil { t.Fatal("accepted mismatched snapshot target") }
}

func TestExactLockAndEntryBinding(t *testing.T) {
	root := t.TempDir()
	packages := fixtureLock([]toolkit.Package{{Name:"bash",Version:"1.0-1"}})
	if err := writeBuildInputs(root,packages,[]byte(debianSources)); err != nil { t.Fatal(err) }
	entry := filepath.Join(t.TempDir(),"entry")
	entryData := []byte("synthetic entry bytes\n")
	if err := os.WriteFile(entry,entryData,0o755); err != nil { t.Fatal(err) }
	hash := sha256.Sum256(entryData)
	inventory := toolkit.Inventory{Build:toolkit.BuildMetadata{Distro:"debian",Release:"13",Packages:inventoryPackages(packages)}, Files:[]toolkit.Entry{{Path:entryPath,Type:"file",Mode:"0555",SHA256:hex.EncodeToString(hash[:])}}}
	lock := filepath.Join(t.TempDir(),"packages.lock")
	if err := os.WriteFile(lock,canonicalLock(packages),0o600); err != nil { t.Fatal(err) }
	sources := filepath.Join(t.TempDir(),"snapshot.sources")
	if err := os.WriteFile(sources,[]byte(debianSources),0o600); err != nil { t.Fatal(err) }
	if err := verifyBuildInputs(root,inventory,lock,sources,entry); err != nil { t.Fatal(err) }
	changed := append([]lockedPackage(nil),packages...)
	changed[0].SHA256 = strings.Repeat("f",64)
	if err := os.WriteFile(lock,canonicalLock(changed),0o600); err != nil { t.Fatal(err) }
	if err := verifyBuildInputs(root,inventory,lock,"",""); err == nil { t.Fatal("accepted a different archive hash") }
	changed[0] = packages[0]
	changed[0].Architecture = "all"
	if err := os.WriteFile(lock,canonicalLock(changed),0o600); err != nil { t.Fatal(err) }
	if err := verifyBuildInputs(root,inventory,lock,"",""); err == nil { t.Fatal("accepted a different package architecture") }
	if err := os.WriteFile(sources,[]byte(strings.ReplaceAll(debianSources,"20200101","20200102")),0o600); err != nil { t.Fatal(err) }
	if err := verifyBuildInputs(root,inventory,"",sources,""); err == nil { t.Fatal("accepted different snapshot inputs") }
	if err := os.WriteFile(entry,[]byte("different source build\n"),0o755); err != nil { t.Fatal(err) }
	if err := verifyBuildInputs(root,inventory,"","",entry); err == nil { t.Fatal("accepted different trusted entry binary") }
	inventory.Build.Packages[0].Version = "2.0-1"
	if err := verifyBuildInputs(root,inventory,"","",""); err == nil { t.Fatal("accepted manifest/embedded-lock mismatch") }
}

func TestBuildInputSafety(t *testing.T) {
	if err := writeBuildInputs("/",nil,nil); err == nil { t.Fatal("accepted host root") }
	root := t.TempDir()
	alias := filepath.Join(t.TempDir(),"alias")
	if err := os.Symlink(root,alias); err != nil { t.Fatal(err) }
	if err := writeBuildInputs(alias,nil,nil); err == nil { t.Fatal("modified an aliased runtime before generation") }
	if _,err := os.Lstat(filepath.Join(root,"usr")); !os.IsNotExist(err) { t.Fatal("created files through an aliased build root") }
	file := filepath.Join(root,"lock")
	if err := os.WriteFile(file,bytes.Repeat([]byte("x"),100),0o600); err != nil { t.Fatal(err) }
	if _,err := readBounded(file,10); err == nil { t.Fatal("accepted oversized input") }
	link := filepath.Join(root,"symlink")
	if err := os.Symlink(file,link); err != nil { t.Fatal(err) }
	if _,err := readLock(link); err == nil { t.Fatal("accepted symlink lock") }
	fifo := filepath.Join(root,"fifo")
	if err := unix.Mkfifo(fifo,0o600); err != nil { t.Fatal(err) }
	if _,err := readBounded(fifo,10); err == nil { t.Fatal("accepted special file") }
}

func TestCopyEntryRejectsUnsafeObjectsAndCollisions(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root,"usr/libexec"),0o755); err != nil { t.Fatal(err) }
	d,err := os.OpenRoot(root)
	if err != nil { t.Fatal(err) }
	defer d.Close()
	entry := filepath.Join(t.TempDir(),"entry")
	if err := os.WriteFile(entry,[]byte("synthetic fixture\n"),0o644); err != nil { t.Fatal(err) }
	if err := copyEntry(entry,d); err == nil { t.Fatal("accepted nonexecutable entry") }
	if err := os.Chmod(entry,0o755); err != nil { t.Fatal(err) }
	link := entry+"-link"
	if err := os.Link(entry,link); err != nil { t.Fatal(err) }
	if err := copyEntry(entry,d); err == nil { t.Fatal("accepted hard-linked entry") }
	if err := os.Remove(link); err != nil { t.Fatal(err) }
	if err := os.Symlink(entry,link); err != nil { t.Fatal(err) }
	if err := copyEntry(link,d); err == nil { t.Fatal("accepted symlink entry") }
	if err := copyEntry(entry,d); err != nil { t.Fatal(err) }
	if err := copyEntry(entry,d); err == nil { t.Fatal("replaced an existing runtime entry") }
}
