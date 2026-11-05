//go:build linux

// soteria-runtime is a build-time utility, not a privileged session helper.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Lfardell1/Soteria/internal/toolkit"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "soteria-runtime:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected prepare, generate, verify, verify-staging, check-sources, sbom-runtime, sbom-go, licenses-runtime, or licenses-go")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	root := flags.String("root", "", "absolute runtime build tree")
	source := flags.String("source", "", "absolute, freshly extracted signed package tree (prepare only)")
	distro := flags.String("distro", "", "debian or ubuntu")
	release := flags.String("release", "", "13 or 24.04")
	lock := flags.String("packages", "", "exact package/archive SHA256 TSV lock")
	sources := flags.String("sources", "", "pinned, signature-required Deb822 snapshot sources")
	entry := flags.String("entry", "", "separately built static soteria-entry executable")
	binary := flags.String("binary", "", "compiled Go executable (sbom-go only)")
	version := flags.String("version", "", "build version (sbom-go only)")
	moduleCache := flags.String("module-cache", "", "Go module cache for license-file inventory")
	goRoot := flags.String("goroot", "", "selected Go toolchain for its actual license files")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	var inventory toolkit.Inventory
	var err error
	switch args[0] {
	case "prepare", "generate":
		if os.Geteuid() == 0 || os.Getenv("SOTERIA_DISPOSABLE_BUILD") != "1" {
			return errors.New("sealing requires a non-root builder and SOTERIA_DISPOSABLE_BUILD=1 in a disposable build environment")
		}
		packages, err := readLock(*lock)
		if err != nil {
			return err
		}
		build := toolkit.BuildMetadata{Distro: *distro, Release: *release, Architecture: "amd64", Packages: inventoryPackages(packages)}
		snapshot, err := readSources(*sources, build)
		if err != nil {
			return err
		}
		if args[0] == "prepare" {
			if err := prepare(*source, *root, *entry, build); err != nil {
				return err
			}
		} else if *entry != "" {
			return errors.New("generate inventories an existing entry; --entry is only accepted by prepare or verification")
		}
		if err := writeBuildInputs(*root, packages, snapshot); err != nil {
			return err
		}
		inventory, err = toolkit.Generate(*root, build)
	case "verify":
		inventory, err = toolkit.Verify(*root)
	case "verify-staging", "sbom-runtime", "licenses-runtime":
		inventory, err = toolkit.VerifyStaging(*root)
	case "check-sources":
		data, err := readSources(*sources, toolkit.BuildMetadata{Distro: *distro, Release: *release})
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		_, err = fmt.Fprintf(out, "sha256:%x\n", sum)
		return err
	case "sbom-go":
		return goSBOM(*binary, *version, out)
	case "licenses-go":
		return goLicenses(*binary, *source, *moduleCache, *goRoot, out)
	default:
		return fmt.Errorf("unknown operation %q", args[0])
	}
	if err != nil {
		return err
	}
	if (*distro != "" && inventory.Build.Distro != *distro) || (*release != "" && inventory.Build.Release != *release) {
		return errors.New("runtime distro/release does not match the requested package target")
	}
	if err := verifyBuildInputs(*root, inventory, *lock, *sources, *entry); err != nil {
		return err
	}
	if args[0] == "sbom-runtime" {
		return runtimeSBOM(inventory, out)
	}
	if args[0] == "licenses-runtime" {
		return runtimeLicenses(*root, inventory, out)
	}
	_, err = fmt.Fprintln(out, inventory.Digest)
	return err
}

func prepare(source, destination, entry string, build toolkit.BuildMetadata) (err error) {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || source == "/" ||
		!filepath.IsAbs(destination) || filepath.Clean(destination) != destination || destination == "/" ||
		destination == source || strings.HasPrefix(destination, source+"/") || strings.HasPrefix(source, destination+"/") {
		return errors.New("source and destination must be separate clean absolute build paths, not host root")
	}
	if (build.Distro != "debian" || build.Release != "13") && (build.Distro != "ubuntu" || build.Release != "24.04") {
		return errors.New("only Debian 13 and Ubuntu 24.04 runtime inputs are supported")
	}
	if resolved, err := filepath.EvalSymlinks(source); err != nil || resolved != source {
		return errors.Join(errors.New("package source and its ancestors must not be symlinks"), err)
	}
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(destination)); err != nil || resolved != filepath.Dir(destination) {
		return errors.Join(errors.New("fresh runtime parent must exist and have no symlink ancestors"), err)
	}
	if err := os.Mkdir(destination, 0o755); err != nil {
		return fmt.Errorf("create fresh runtime destination: %w", err)
	}
	s, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	d, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, d.Close()) }()
	for _, name := range []string{"usr", "usr/bin", "usr/sbin", "usr/lib", "usr/lib64", "usr/libexec", "etc", "etc/ssl/certs", "dev", "proc", "sys", "home/workspace", "work", "tmp", "run", "var"} {
		if err := d.MkdirAll(name, 0o755); err != nil {
			return err
		}
	}
	// Copy only package-supplied public userland, never builder /etc, /home,
	// /root, credentials, package-manager state, devices, or service sockets.
	if err := copyTree(s, d, "usr", "usr"); err != nil {
		return err
	}
	for _, name := range []string{"bin", "sbin", "lib", "lib64"} {
		info, err := s.Lstat(name)
		if err == nil && info.IsDir() {
			if err := copyTree(s, d, name, "usr/"+name); err != nil {
				return err
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		} else if err == nil && info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("unexpected top-level package object: %s", name)
		}
		if err := d.Symlink("usr/"+name, name); err != nil {
			return err
		}
	}
	if err := copyTree(s, d, "etc/ssl/openssl.cnf", "etc/ssl/openssl.cnf"); err != nil {
		return fmt.Errorf("copy distro public OpenSSL configuration: %w", err)
	}
	if _, err := d.Lstat("usr/bin/sh"); errors.Is(err, os.ErrNotExist) {
		shell := "bash"
		if _, err := d.Lstat("usr/bin/dash"); err == nil {
			shell = "dash"
		}
		if err := d.Symlink(shell, "usr/bin/sh"); err != nil {
			return err
		}
	}
	files := map[string]string{
		"etc/nsswitch.conf": "passwd: files\ngroup: files\nhosts: files dns\nnetworks: files\n",
		"etc/passwd":        "", "etc/group": "", "etc/resolv.conf": "",
		"etc/hosts": "127.0.0.1 localhost\n::1 localhost\n", "etc/hostname": "soteria\n",
		"etc/os-release": fmt.Sprintf("ID=%s\nVERSION_ID=\"%s\"\n", build.Distro, build.Release),
	}
	for name, content := range files {
		if err := d.WriteFile(name, []byte(content), 0o644); err != nil {
			return err
		}
	}
	if err := copyEntry(entry, d); err != nil {
		return err
	}
	var bundle []byte
	err = fs.WalkDir(s.FS(), "usr/share/ca-certificates", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".crt") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("public CA input is not a regular file: %s", name)
		}
		data, err := s.ReadFile(name)
		if err != nil {
			return err
		}
		for len(strings.TrimSpace(string(data))) > 0 {
			block, rest := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return fmt.Errorf("non-certificate PEM in distro CA input: %s", name)
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return fmt.Errorf("parse public CA %s: %w", name, err)
			}
			bundle = append(bundle, pem.EncodeToMemory(block)...)
			data = rest
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(bundle) == 0 {
		return errors.New("signed ca-certificates package supplied no public CA certificates")
	}
	return d.WriteFile("etc/ssl/certs/ca-certificates.crt", bundle, 0o644)
}

func copyTree(source, destination *os.Root, from, to string) error {
	return fs.WalkDir(source.FS(), from, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "usr/lib/ssl/private" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil // OpenSSL's empty private-key-directory alias is not runtime input.
		}
		relative := to + strings.TrimPrefix(name, from)
		if entry.IsDir() {
			return destination.MkdirAll(relative, 0o755)
		}
		if err := destination.MkdirAll(path.Dir(relative), 0o755); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := source.Readlink(name)
			if err != nil {
				return err
			}
			return destination.Symlink(target, relative)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("package input has a special object: %s", name)
		}
		in, err := source.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		info, err := in.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return errors.Join(errors.New("package file changed type"), err, in.Close())
		}
		out, err := destination.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o644|info.Mode().Perm()&0o111)
		if err != nil {
			return errors.Join(fmt.Errorf("copy package file %s (duplicate paths are rejected): %w", name, err), in.Close())
		}
		_, copyErr := io.Copy(out, in)
		return errors.Join(copyErr, in.Close(), out.Close())
	})
}

type component struct {
	Type       string      `json:"type"`
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	PURL       string      `json:"purl,omitempty"`
	Hashes     []hashValue `json:"hashes,omitempty"`
	Properties []property  `json:"properties,omitempty"`
}
type hashValue struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}
type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type bom struct {
	Format     string      `json:"bomFormat"`
	Spec       string      `json:"specVersion"`
	Version    int         `json:"version"`
	Components []component `json:"components"`
}

func runtimeSBOM(inventory toolkit.Inventory, out io.Writer) error {
	components := []component{{Type: "application", Name: "soteria-runtime", Version: inventory.Digest,
		Hashes: []hashValue{{"SHA-256", strings.TrimPrefix(inventory.Digest, "sha256:")}},
		Properties: []property{
			{"soteria:evidence", "package inventory and verified staging contents; not an installed-ownership or security attestation"},
			{"soteria:runtime-architecture", inventory.Build.Architecture},
		},
	}}
	for _, entry := range inventory.Files {
		if entry.Path == entryPath {
			components = append(components, component{Type: "application", Name: "soteria-entry", Version: "sha256:" + entry.SHA256,
				Hashes: []hashValue{{"SHA-256", entry.SHA256}}, Properties: []property{{"soteria:runtime-path", "/" + entryPath}}})
		}
	}
	for _, pkg := range inventory.Build.Packages {
		// v1 Inventory has no per-package architecture. In particular, do not
		// mislabel Architecture:all archives as amd64; retain that in the lock.
		query := url.Values{"distro": {inventory.Build.Distro + "-" + inventory.Build.Release}}
		components = append(components, component{Type: "library", Name: pkg.Name, Version: pkg.Version,
			PURL: "pkg:deb/" + inventory.Build.Distro + "/" + pkg.Name + "@" + url.PathEscape(pkg.Version) + "?" + query.Encode()})
	}
	return json.NewEncoder(out).Encode(bom{"CycloneDX", "1.6", 1, components})
}

func goSBOM(binary, version string, out io.Writer) error {
	if version == "" {
		return errors.New("a non-empty build version is required")
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return err
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if info.Path != "github.com/Lfardell1/Soteria/cmd/soteria" || info.GoVersion != "go1.27.3" ||
		settings["GOOS"] != "linux" || settings["GOARCH"] != "amd64" || settings["CGO_ENABLED"] != "0" {
		return errors.New("evidence requires the actual Go 1.27.3 Linux amd64 CGO-disabled Soteria CLI; rebuild with scripts/build.sh")
	}
	f, err := os.Open(binary)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, f)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return err
	}
	components := []component{
		{Type: "application", Name: filepath.Base(binary), Version: version, Hashes: []hashValue{{"SHA-256", hex.EncodeToString(hash.Sum(nil))}},
			Properties: []property{{"soteria:go-main-path", info.Path}, {"soteria:go-toolchain", info.GoVersion}}},
		{Type: "library", Name: "stdlib", Version: strings.TrimPrefix(info.GoVersion, "go"), PURL: "pkg:golang/stdlib@" + strings.TrimPrefix(info.GoVersion, "go")},
	}
	for _, module := range info.Deps {
		if module.Replace != nil {
			module = module.Replace
		}
		if module.Version == "" || module.Version == "(devel)" {
			return fmt.Errorf("cannot inventory unversioned/local Go module %s", module.Path)
		}
		components = append(components, component{Type: "library", Name: module.Path, Version: module.Version,
			PURL: "pkg:golang/" + module.Path + "@" + url.PathEscape(module.Version), Properties: []property{{"soteria:go-module-sum", module.Sum}}})
	}
	return json.NewEncoder(out).Encode(bom{"CycloneDX", "1.6", 1, components})
}
