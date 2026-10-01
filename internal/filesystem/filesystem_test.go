package filesystem

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/Lfardell1/Soteria/internal/config"
)

func rootAvailable(t *testing.T) bool {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		return false
	}
	return u.Uid == "0"
}

func TestManagerLifecycleRoot(t *testing.T) {
	if !rootAvailable(t) {
		t.Skip("requires root for tmpfs mount")
	}

	mount := filepath.Join(t.TempDir(), "secure")
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "hello"), []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := New(config.FilesystemConfig{
		TmpfsSize:     "64M",
		MountPoint:    mount,
		PopulatePaths: []string{src},
	})

	if err := m.Mount(); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	defer func() { _ = m.Teardown() }()

	if err := m.Populate(); err != nil {
		t.Fatalf("Populate: %v", err)
	}

	copied := filepath.Join(mount, src, "hello")
	data, err := os.ReadFile(copied)
	if err != nil {
		t.Fatalf("read populated file: %v", err)
	}
	if string(data) != "world" {
		t.Fatalf("got %q", data)
	}

	usage, err := m.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if usage.Total == 0 {
		t.Fatal("expected non-zero total")
	}

	if err := m.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if m.IsMounted() {
		t.Fatal("expected unmounted")
	}
}

func TestPopulateRequiresMount(t *testing.T) {
	m := New(config.FilesystemConfig{MountPoint: "/mnt/secure", PopulatePaths: []string{"/bin"}})
	if err := m.Populate(); err == nil {
		t.Fatal("expected error when not mounted")
	}
}
