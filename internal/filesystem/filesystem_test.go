package filesystem

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// No test calls the real mount/unmount functions, including when tests run as
// root. The fake unmount only removes files in a test-owned temporary directory.
func testOperations(t *testing.T) mountOperations {
	t.Helper()
	return mountOperations{
		mount: func(source, target, fstype string, flags uintptr, options string) error {
			if source != "tmpfs" || fstype != "tmpfs" || flags != unix.MS_NOSUID|unix.MS_NODEV {
				t.Fatalf("unsafe mount parameters: %q %q %#x", source, fstype, flags)
			}
			if !strings.Contains(options, "size=1048576,mode=0700,uid=0,gid=0") {
				t.Fatalf("unbounded or incorrectly owned tmpfs: %q", options)
			}
			return nil
		},
		inspect: func(string) (bool, error) { return true, nil },
		unmount: func(root string, flags int) error {
			if flags != 0 {
				t.Fatalf("unmount must not detach: %#x", flags)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func testCredentials() (uint32, uint32) {
	// Preparation tests keep the fixture creator's identity, requiring no
	// CAP_CHOWN even under root. Public Mount's nonzero-identity gate is tested
	// separately and cannot be bypassed by callers outside this package.
	return uint32(os.Getuid()), uint32(os.Getgid())
}

func newTestWorkspace(t *testing.T) (*Workspace, string) {
	t.Helper()
	runtime := t.TempDir()
	uid, gid := testCredentials()
	w, err := mountWorkspace(runtime, 1<<20, uid, gid, testOperations(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("close test workspace: %v", err)
		}
	})
	return w, runtime
}

func TestValidateArguments(t *testing.T) {
	valid := "/run/soteria-0123456789abcdef0123456789abcdef"
	if err := validateArguments(valid, 1<<20, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "/", "run/soteria-0123456789abcdef0123456789abcdef", valid + "/", valid + "/child", valid + "/../x", strings.ToUpper(valid), "/tmp/" + filepath.Base(valid), "/run/soteria-0123"} {
		if _, err := Mount(name, 1<<20, 1000, 1000); err == nil {
			t.Errorf("accepted unsafe runtime %q", name)
		}
	}
	for _, size := range []uint64{0, math.MaxUint64} {
		if _, err := Mount(valid, size, 1000, 1000); err == nil {
			t.Errorf("accepted size %d", size)
		}
	}
	for _, ids := range [][2]uint32{{0, 1000}, {1000, 0}, {math.MaxUint32, 1000}, {1000, math.MaxUint32}} {
		if _, err := Mount(valid, 1<<20, ids[0], ids[1]); err == nil {
			t.Errorf("accepted credentials %v", ids)
		}
	}
}

func TestRuntimeDirectoryOwnershipAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := openRuntimeDirectory(dir)
	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	} else if err == nil {
		f.Close()
		t.Fatal("accepted non-root runtime ownership")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if f, err := openRuntimeDirectory(dir); err == nil {
		f.Close()
		t.Fatal("accepted runtime mode 0755")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openRuntimeDirectory(link); err == nil {
		f.Close()
		t.Fatal("accepted symlink runtime")
	}
}

func TestWorkspaceLayoutAndOwnedCleanup(t *testing.T) {
	w, runtime := newTestWorkspace(t)
	preexisting := filepath.Join(runtime, "workspace-preexisting")
	if err := os.Mkdir(preexisting, 0o700); err != nil {
		t.Fatal(err)
	}
	uid, gid := testCredentials()
	for _, name := range []string{w.Home, w.Work, w.Temp, w.Run, w.Var, filepath.Join(w.Work, "in"), filepath.Join(w.Work, "out")} {
		st, err := directoryIdentity(name)
		if err != nil {
			t.Fatal(err)
		}
		if st.Uid != uid || st.Gid != gid {
			t.Fatalf("%s owned by %d:%d, want %d:%d", name, st.Uid, st.Gid, uid, gid)
		}
	}
	if w.Home != filepath.Join(w.Root, "home", "workspace") || !w.Noswap || len(w.Warnings) != 0 {
		t.Fatalf("unexpected workspace: %+v", w)
	}
	for name, mode := range map[string]os.FileMode{
		w.Root: 0o700, w.Home: 0o700, w.Work: 0o700, w.Run: 0o700, w.Var: 0o700, w.Etc: 0o755,
		w.Temp: 0o777 | os.ModeSticky, filepath.Join(w.Var, "tmp"): 0o777 | os.ModeSticky,
	} {
		st, err := os.Stat(name)
		if err != nil || st.Mode()&(os.ModePerm|os.ModeSticky) != mode {
			t.Fatalf("incorrect private directory mode for %s: %v", name, err)
		}
	}
	passwd, err := os.ReadFile(filepath.Join(w.Etc, "passwd"))
	if err != nil || string(passwd) != fmt.Sprintf("workspace:x:%d:%d:Workspace:/home/workspace:/bin/bash\n", uid, gid) {
		t.Fatalf("passwd: %q, %v", passwd, err)
	}
	resolver, err := os.ReadFile(filepath.Join(w.Etc, "resolv.conf"))
	if err != nil || len(resolver) != 0 {
		t.Fatalf("offline resolver must be empty: %q, %v", resolver, err)
	}
	for _, name := range []string{"passwd", "group", "nsswitch.conf", "hosts", "resolv.conf"} {
		st, err := os.Stat(filepath.Join(w.Etc, name))
		if err != nil || st.Mode().Perm() != 0o444 {
			t.Fatalf("configuration is writable: %s, %v", name, err)
		}
	}
	root := w.Root
	w.Root, w.Work, w.Etc = preexisting, preexisting, preexisting
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned mountpoint remains: %v", err)
	}
	if _, err := os.Stat(preexisting); err != nil {
		t.Fatalf("preexisting directory was removed: %v", err)
	}
	if _, err := os.Stat(runtime); err != nil {
		t.Fatalf("systemd runtime directory was removed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNoswapFallbackOnlyForUnsupportedControl(t *testing.T) {
	for _, unsupported := range []error{unix.EINVAL, unix.EOPNOTSUPP} {
		t.Run(unsupported.Error(), func(t *testing.T) {
			ops := testOperations(t)
			mount := ops.mount
			calls := 0
			ops.mount = func(source, target, kind string, flags uintptr, options string) error {
				calls++
				if calls == 1 {
					if !strings.HasSuffix(options, ",noswap") {
						t.Fatal("noswap not attempted first")
					}
					return unsupported
				}
				if strings.Contains(options, "noswap") {
					t.Fatal("fallback still contains unsupported option")
				}
				return mount(source, target, kind, flags, options)
			}
			ops.inspect = func(string) (bool, error) { return false, nil }
			uid, gid := testCredentials()
			w, err := mountWorkspace(t.TempDir(), 1<<20, uid, gid, ops)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 2 || w.Noswap || len(w.Warnings) != 1 || !strings.Contains(w.Warnings[0], "swapped to host storage") {
				t.Fatalf("incorrect fallback evidence: calls=%d, %+v", calls, w)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, failure := range []error{unix.EPERM, unix.ENOSPC, unix.ENOMEM, unix.EIO, unix.ENOSYS, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			ops := testOperations(t)
			calls := 0
			ops.mount = func(string, string, string, uintptr, string) error { calls++; return failure }
			ops.unmount = func(string, int) error { t.Fatal("unmount after failed mount"); return nil }
			uid, gid := testCredentials()
			runtime := t.TempDir()
			if w, err := mountWorkspace(runtime, 1<<20, uid, gid, ops); w != nil || !errors.Is(err, failure) || calls != 1 {
				t.Fatalf("mount failure not fatal: w=%v err=%v calls=%d", w, err, calls)
			}
			entries, err := os.ReadDir(runtime)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed setup left a disk substitute: %v %v", entries, err)
			}
		})
	}
}

func TestMountVerificationAndPreparationFailuresCleanUp(t *testing.T) {
	for _, stage := range []string{"inspection", "preparation", "fallback"} {
		t.Run(stage, func(t *testing.T) {
			ops := testOperations(t)
			failure := errors.New("injected " + stage)
			switch stage {
			case "inspection":
				ops.inspect = func(string) (bool, error) { return false, failure }
			case "preparation":
				ops.inspect = func(root string) (bool, error) {
					return true, os.WriteFile(filepath.Join(root, "home"), nil, 0o600)
				}
			case "fallback":
				calls := 0
				ops.mount = func(string, string, string, uintptr, string) error {
					calls++
					if calls == 1 {
						return unix.EINVAL
					}
					return failure
				}
			}
			uid, gid := testCredentials()
			runtime := t.TempDir()
			if w, err := mountWorkspace(runtime, 1<<20, uid, gid, ops); w != nil || err == nil {
				t.Fatalf("accepted failed setup: %v, %v", w, err)
			}
			entries, err := os.ReadDir(runtime)
			if err != nil || len(entries) != 0 {
				t.Fatalf("setup cleanup left files: %v %v", entries, err)
			}
		})
	}
}

func TestRequestedNoswapMustBeVerified(t *testing.T) {
	ops := testOperations(t)
	ops.inspect = func(string) (bool, error) { return false, nil }
	uid, gid := testCredentials()
	w, err := mountWorkspace(t.TempDir(), 1<<20, uid, gid, ops)
	if err != nil {
		t.Fatal(err)
	}
	if w.Noswap || len(w.Warnings) != 1 || !strings.Contains(w.Warnings[0], "not effective") {
		t.Fatalf("unverified noswap reported effective: %+v", w)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquisitionDoesNotOwnPreexistingEmptyDirectory(t *testing.T) {
	runtime := t.TempDir()
	preexisting := filepath.Join(runtime, "workspace-existing")
	if err := os.Mkdir(preexisting, 0o700); err != nil {
		t.Fatal(err)
	}
	ops := testOperations(t)
	ops.mount = func(_, target, _ string, _ uintptr, _ string) error {
		if target == preexisting {
			t.Fatal("reused preexisting empty directory")
		}
		return unix.EPERM
	}
	ops.unmount = func(string, int) error { t.Fatal("unmounted a failed acquisition"); return nil }
	uid, gid := testCredentials()
	if _, err := mountWorkspace(runtime, 1<<20, uid, gid, ops); !errors.Is(err, unix.EPERM) {
		t.Fatalf("mount failure: %v", err)
	}
	entries, err := os.ReadDir(runtime)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(preexisting) {
		t.Fatalf("preexisting empty directory not preserved: %v %v", entries, err)
	}
}

func TestCloseReportsRemovalFailureWithoutRecursiveDeletion(t *testing.T) {
	w, _ := newTestWorkspace(t)
	w.ops.unmount = func(_ string, flags int) error {
		if flags != 0 {
			t.Fatal("lazy unmount")
		}
		return nil
	}
	if err := w.Close(); err == nil || !strings.Contains(err.Error(), "remove owned workspace") {
		t.Fatalf("discarded nonempty-directory removal failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w.root, "home", "workspace")); err != nil {
		t.Fatalf("recursively deleted state: %v", err)
	}
	entries, err := os.ReadDir(w.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(w.root, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
}

func TestCloseBusyNeverDetachesOrRemovesUnderWriter(t *testing.T) {
	w, _ := newTestWorkspace(t)
	unmount := w.ops.unmount
	w.ops.unmount = func(string, int) error { return unix.EBUSY }
	if err := w.Close(); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("busy error discarded: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w.root, "work", "out")); err != nil {
		t.Fatalf("state removed under a writer: %v", err)
	}
	if _, err := w.OpenExport(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("new operations accepted during stopping: %v", err)
	}
	w.ops.unmount = unmount
	if err := w.Close(); err != nil {
		t.Fatalf("retry after writers stop: %v", err)
	}
}

func TestConcurrentCloseUnmountsOnlyOnce(t *testing.T) {
	w, _ := newTestWorkspace(t)
	unmount, calls := w.ops.unmount, 0
	w.ops.unmount = func(root string, flags int) error {
		calls++
		return unmount(root, flags)
	}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := w.Close(); err != nil {
				t.Errorf("concurrent close: %v", err)
			}
		}()
	}
	group.Wait()
	if calls != 1 {
		t.Fatalf("unmounted %d times", calls)
	}
}

func TestFailedSetupReportsCleanupFailure(t *testing.T) {
	ops := testOperations(t)
	failure := errors.New("verification failed")
	ops.inspect = func(string) (bool, error) { return false, failure }
	ops.unmount = func(_ string, flags int) error {
		if flags != 0 {
			t.Fatal("lazy detach")
		}
		return unix.EBUSY
	}
	uid, gid := testCredentials()
	_, err := mountWorkspace(t.TempDir(), 1<<20, uid, gid, ops)
	if !errors.Is(err, failure) || !errors.Is(err, unix.EBUSY) {
		t.Fatalf("setup/cleanup errors not both reported: %v", err)
	}
}

func TestCloseRejectsReplacedDirectory(t *testing.T) {
	w, _ := newTestWorkspace(t)
	saved := w.root + "-saved"
	if err := os.Rename(w.root, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(w.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err == nil {
		t.Fatal("unmounted/removed a replacement directory")
	}
	if err := os.Remove(w.root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, w.root); err != nil {
		t.Fatal(err)
	}
}

func TestResolverAndTransferDescriptors(t *testing.T) {
	w, _ := newTestWorkspace(t)
	if err := w.SetResolver([]string{"192.0.2.1", "198.51.100.2"}); err != nil {
		t.Fatal(err)
	}
	want := "nameserver 192.0.2.1\nnameserver 198.51.100.2\n"
	for _, servers := range [][]string{{"example.com"}, {"::1"}, {"::ffff:192.0.2.1"}, {"192.0.2.1\nsearch evil"}, {" 192.0.2.1"}, {"192.0.2.01"}, {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}} {
		if err := w.SetResolver(servers); err == nil {
			t.Errorf("accepted unsafe resolver: %q", servers)
		}
		got, err := os.ReadFile(filepath.Join(w.Etc, "resolv.conf"))
		if err != nil || string(got) != want {
			t.Fatalf("invalid resolver changed prior configuration: %q %v", got, err)
		}
	}
	for _, open := range []func() (*os.File, error){w.OpenImport, w.OpenExport} {
		f, err := open()
		if err != nil {
			t.Fatal(err)
		}
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("transfer descriptor may leak to exec: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(w.Work, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(w.Work, "out")); err != nil {
		t.Fatal(err)
	}
	if f, err := w.OpenExport(); err == nil {
		f.Close()
		t.Fatal("followed workload symlink")
	}
	if err := w.SetResolver(nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(w.Etc, "resolv.conf"))
	if err != nil || len(data) != 0 {
		t.Fatalf("offline reset: %q %v", data, err)
	}
}

func TestInspectMountInfo(t *testing.T) {
	root := "/run/soteria-test/workspace with space"
	line := "42 20 0:33 / /run/soteria-test/workspace\\040with\\040space rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=1024k,mode=700,noswap\n"
	if noswap, err := inspectMountInfo(strings.NewReader(line), root); err != nil || !noswap {
		t.Fatalf("valid mount evidence: %v %v", noswap, err)
	}
	if noswap, err := inspectMountInfo(strings.NewReader(strings.ReplaceAll(line, ",noswap", "")), root); err != nil || noswap {
		t.Fatalf("ordinary tmpfs evidence: %v %v", noswap, err)
	}
	for _, bad := range []string{"", "malformed\n", strings.ReplaceAll(line, " - tmpfs ", " - ext4 "), strings.ReplaceAll(line, ",nodev", ""), line + line, strings.ReplaceAll(line, "workspace\\040with", "other\\040with")} {
		if _, err := inspectMountInfo(strings.NewReader(bad), root); err == nil {
			t.Errorf("accepted invalid mount evidence %q", bad)
		}
	}
}

func FuzzInspectMountInfo(f *testing.F) {
	f.Add("42 20 0:33 / /run/soteria-test/workspace rw,nosuid,nodev - tmpfs tmpfs rw,noswap\n")
	f.Add("malformed")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 64<<10 {
			return
		}
		_, _ = inspectMountInfo(strings.NewReader(data), "/run/soteria-test/workspace")
	})
}
