//go:build linux && amd64

package session

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bus "github.com/godbus/dbus/v5"
)

func TestCleanupRefusesActiveStoppingAndUnverifiableUnits(t *testing.T) {
	invocation, err := hex.DecodeString(testID)
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]any{"ActiveState": "inactive", "SubState": "dead", "MainPID": uint32(0), "ControlPID": uint32(0), "InvocationID": invocation, "Job": []any{uint32(0), bus.ObjectPath("/")}}
	if err := requireInactiveInvocation(state, testID); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		field string
		value any
	}{
		{"ActiveState", "active"}, {"SubState", "stop-post"}, {"MainPID", uint32(30)}, {"ControlPID", uint32(31)},
		{"MainPID", nil}, {"InvocationID", []byte{1}},
		{"Job", []any{uint32(1), bus.ObjectPath("/job/1")}}, {"Job", nil},
	} {
		old := state[item.field]
		state[item.field] = item.value
		if err := requireInactiveInvocation(state, testID); err == nil {
			t.Errorf("unsafe cleanup authority accepted: %s=%v", item.field, item.value)
		}
		state[item.field] = old
	}
}

func TestOwnershipRecordsAreBoundedNoFollowAndSingleLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned metadata assertion; only test-temp files are written")
	}
	name := t.TempDir()
	directory, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	owner := ownerRecord{Version: 1, ID: testID, Invocation: testID, Caller: identity{UID: 1000, GID: 1000}}
	if err := createRecord(directory, ownerFile, owner); err != nil {
		t.Fatal(err)
	}
	if observed, err := readOwner(directory, testID); err != nil || observed != owner {
		t.Fatalf("exact owner not recovered: %+v %v", observed, err)
	}
	if _, err := readOwner(directory, strings.Repeat("f", 32)); err == nil {
		t.Fatal("record accepted for another session")
	}
	if err := os.Symlink(ownerFile, filepath.Join(name, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := readRecord(directory, "alias", new(ownerRecord)); err == nil {
		t.Fatal("ownership symlink followed")
	}
	if err := os.Link(filepath.Join(name, ownerFile), filepath.Join(name, "duplicate")); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwner(directory, testID); err == nil {
		t.Fatal("multiply linked authority record accepted")
	}
}

func TestCleanupRefusesAReplacedRecordedMountpoint(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned metadata assertion; no mounts or /run changes")
	}
	root, saved := t.TempDir(), t.TempDir()
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	owner := ownerRecord{Version: 1, ID: testID, Invocation: testID, Caller: identity{UID: 1000, GID: 1000}}
	if err := createRecord(directory, ownerFile, owner); err != nil {
		t.Fatal(err)
	}
	const basename = "workspace-test"
	if err := os.Mkdir(filepath.Join(root, basename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := recordWorkspace(directory, basename); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, basename), filepath.Join(saved, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, basename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeRuntime(directory, testID, &owner); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("replaced mountpoint was not refused before any /run operation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ownerFile)); err != nil {
		t.Fatalf("authority destroyed on refused cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, basename)); err != nil {
		t.Fatalf("replacement deleted on refused cleanup: %v", err)
	}
}

func TestRootExecutableCannotUseAWritableLookupAncestor(t *testing.T) {
	if _, err := openRootDirectory("/tmp", false); err == nil {
		t.Skip("/tmp is private in this host; no writable-ancestor fixture available")
	}
	if err := verifyRootExecutable(filepath.Join(t.TempDir(), "does-not-exist"), true); err == nil || !strings.Contains(err.Error(), "lookup") {
		t.Fatalf("unsafe lexical lookup ancestor not rejected before alias resolution: %v", err)
	}
}
