//go:build linux

package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lfardell1/Soteria/internal/toolkit"
)

type licenseFile struct {
	Path string `json:"path"`
	SHA256 string `json:"sha256"`
}

type licenseComponent struct {
	Name string `json:"name"`
	Version string `json:"version"`
	ModuleSum string `json:"module_sum,omitempty"`
	Files []licenseFile `json:"files"`
	Status string `json:"status"`
}

type licenseInventory struct {
	Kind string `json:"kind"`
	Subject string `json:"subject"`
	Assessment string `json:"license_and_source_obligation_review"`
	Components []licenseComponent `json:"components"`
}

func runtimeLicenses(root string, inventory toolkit.Inventory, out io.Writer) (err error) {
	r, err := os.OpenRoot(root)
	if err != nil { return err }
	defer func() { err = errors.Join(err, r.Close()) }()
	record := licenseInventory{Kind:"actual-license-file-inventory-v1", Subject:inventory.Digest, Assessment:"pending-human-review"}
	for _, pkg := range inventory.Build.Packages {
		component := licenseComponent{Name:pkg.Name, Version:pkg.Version, Files:[]licenseFile{}, Status:"copyright-file-not-found; review required"}
		name := "usr/share/doc/" + pkg.Name + "/copyright"
		f, openErr := r.Open(name)
		if openErr == nil {
			data, readErr := io.ReadAll(io.LimitReader(f, (16<<20)+1))
			if err := errors.Join(readErr, f.Close()); err != nil { return err }
			if len(data) > 16<<20 { return fmt.Errorf("copyright file exceeds 16 MiB: %s", name) }
			sum := sha256.Sum256(data)
			component.Files = append(component.Files, licenseFile{Path:name, SHA256:hex.EncodeToString(sum[:])})
			component.Status = "file-inventoried; terms and source obligations not classified"
		} else if !errors.Is(openErr, os.ErrNotExist) { return openErr }
		record.Components = append(record.Components, component)
	}
	return json.NewEncoder(out).Encode(record)
}

func goLicenses(binary, source, moduleCache, goRoot string, out io.Writer) error {
	info, err := buildinfo.ReadFile(binary)
	if err != nil { return err }
	record := licenseInventory{Kind:"actual-license-file-inventory-v1", Subject:filepath.Base(binary), Assessment:"pending-human-review"}
	app, err := collectLicenses(source, filepath.Base(binary), info.Main.Version, "")
	if err != nil { return err }
	record.Components = append(record.Components, app)
	stdlib, err := collectLicenses(goRoot, "stdlib", strings.TrimPrefix(info.GoVersion, "go"), "")
	if err != nil { return err }
	record.Components = append(record.Components, stdlib)
	for _, module := range info.Deps {
		if module.Replace != nil { module = module.Replace }
		if module.Version == "" || module.Version == "(devel)" { return fmt.Errorf("cannot inventory license files for local/unversioned module %s", module.Path) }
		var directory string
		if moduleCache != "" {
			path, err := escapeModule(module.Path)
			if err != nil { return err }
			version, err := escapeModule(module.Version)
			if err != nil { return err }
			directory = filepath.Join(moduleCache, path+"@"+version)
		}
		component, err := collectLicenses(directory, module.Path, module.Version, module.Sum)
		if err != nil { return err }
		record.Components = append(record.Components, component)
	}
	return json.NewEncoder(out).Encode(record)
}

func escapeModule(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "!\\\x00") || filepath.IsAbs(value) || filepath.Clean(value) != value || strings.HasPrefix(value, "../") || value == ".." {
		return "", errors.New("unsafe module cache identity")
	}
	var result strings.Builder
	for _, c := range value {
		if c >= 'A' && c <= 'Z' { result.WriteByte('!'); c += 'a'-'A' }
		result.WriteRune(c)
	}
	return result.String(), nil
}

func collectLicenses(directory, name, version, sum string) (licenseComponent, error) {
	component := licenseComponent{Name:name, Version:version, ModuleSum:sum, Files:[]licenseFile{}, Status:"license-files-unavailable; review required"}
	if directory == "" { return component, nil }
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" { return component, errors.New("license source/cache paths must be clean absolute non-root directories") }
	files, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) { return component, nil }
	if err != nil { return component, err }
	for _, file := range files {
		base := strings.ToUpper(file.Name())
		if !strings.HasPrefix(base, "LICENSE") && !strings.HasPrefix(base, "COPYING") && !strings.HasPrefix(base, "COPYRIGHT") && !strings.HasPrefix(base, "NOTICE") && base != "PATENTS" { continue }
		if !file.Type().IsRegular() { continue }
		data, err := readBounded(filepath.Join(directory,file.Name()), 16<<20)
		if err != nil { return component, err }
		hash := sha256.Sum256(data)
		component.Files = append(component.Files, licenseFile{Path:file.Name(), SHA256:hex.EncodeToString(hash[:])})
	}
	if len(component.Files) != 0 { component.Status = "files-inventoried; terms and source obligations not classified" }
	return component, nil
}
