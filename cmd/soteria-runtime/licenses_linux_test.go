//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lfardell1/Soteria/internal/toolkit"
)

func TestActualLicenseFileInventory(t *testing.T) {
	root := t.TempDir()
	data := []byte("synthetic license file fixture, not an approved license classification\n")
	if err := os.WriteFile(filepath.Join(root,"LICENSE"),data,0o600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(root,"not-a-license"),[]byte("not scanned"),0o600); err != nil { t.Fatal(err) }
	got,err := collectLicenses(root,"fixture","v1.0.0","h1:fixture")
	if err != nil { t.Fatal(err) }
	sum := sha256.Sum256(data)
	if len(got.Files)!=1 || got.Files[0].Path!="LICENSE" || got.Files[0].SHA256!=fmt.Sprintf("%x",sum) || !strings.Contains(got.Status,"not classified") { t.Fatalf("incorrect license evidence: %+v",got) }
	missing,err := collectLicenses(filepath.Join(root,"missing"),"fixture","v1","")
	if err != nil || len(missing.Files)!=0 || !strings.Contains(missing.Status,"unavailable") { t.Fatalf("missing file became a pass: %+v %v",missing,err) }
	if _,err := collectLicenses("/","fixture","v1",""); err==nil { t.Fatal("accepted broad host root for license collection") }
}

func TestRuntimeCopyrightInventory(t *testing.T) {
	root:=t.TempDir()
	directory:=filepath.Join(root,"usr/share/doc/bash")
	if err:=os.MkdirAll(directory,0o755);err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(filepath.Join(directory,"copyright"),[]byte("synthetic copyright fixture\n"),0o644);err!=nil{t.Fatal(err)}
	inventory:=toolkit.Inventory{Digest:"sha256:"+strings.Repeat("a",64),Build:toolkit.BuildMetadata{Packages:[]toolkit.Package{{Name:"bash",Version:"1.0-1"},{Name:"missing",Version:"1.0-1"}}}}
	var output bytes.Buffer
	if err:=runtimeLicenses(root,inventory,&output);err!=nil{t.Fatal(err)}
	var got licenseInventory
	if err:=json.Unmarshal(output.Bytes(),&got);err!=nil{t.Fatal(err)}
	if got.Assessment!="pending-human-review" || len(got.Components)!=2 || len(got.Components[0].Files)!=1 || len(got.Components[1].Files)!=0 || !strings.Contains(got.Components[1].Status,"not-found") {t.Fatalf("incorrect copyright evidence: %s",output.String())}
}

func TestModuleCacheEscaping(t *testing.T) {
	got,err:=escapeModule("github.com/Example/Module")
	if err!=nil || got!="github.com/!example/!module" {t.Fatalf("incorrect Go module cache identity: %q %v",got,err)}
	for _,name:=range []string{"", "/host", "../host", "a/../b", "a\\b", "a!b"} {
		if _,err:=escapeModule(name);err==nil{t.Fatalf("accepted unsafe module cache identity %q",name)}
	}
}

func TestGoSBOMUsesActualBinaryIdentity(t *testing.T) {
	binary,err:=os.Executable()
	if err!=nil{t.Fatal(err)}
	var output bytes.Buffer
	if err:=goSBOM(binary,"0.0.0-test-fixture",&output);err!=nil{t.Fatal(err)}
	var got bom
	if err:=json.Unmarshal(output.Bytes(),&got);err!=nil{t.Fatal(err)}
	if len(got.Components)<2 || got.Components[0].Name!=filepath.Base(binary) || len(got.Components[0].Hashes)!=1 || got.Components[1].Name!="stdlib" {t.Fatalf("incorrect linked-binary inventory: %s",output.String())}
	if err:=goSBOM(binary,"",&bytes.Buffer{});err==nil{t.Fatal("accepted unversioned declared build")}
}
