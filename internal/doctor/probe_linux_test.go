//go:build linux && amd64

package doctor

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/network"
	"github.com/Lfardell1/Soteria/internal/protocol"
	"github.com/Lfardell1/Soteria/internal/toolkit"
	"golang.org/x/sys/unix"
)

type fakeInfo struct {
	mode  os.FileMode
	uid   uint32
	gid   uint32
	size  int64
	links uint64
}

func (f fakeInfo) Name() string       { return "fixture" }
func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid, Gid: f.gid, Nlink: f.links} }

type hostFixture struct {
	files       map[string]string
	info        map[string]fakeInfo
	readPaths   []string
	statPaths   []string
	xattrs      map[string]error
	cfg         config.Config
	inventory   toolkit.Inventory
	verifyCalls int
	verifyErr   error
	fsType      int64
	procType    int64
}

func newHostFixture() *hostFixture {
	f := &hostFixture{
		files: map[string]string{
			"/etc/os-release":                             "ID=debian\nVERSION_ID=\"13\"\nPRETTY_NAME=\"Ignored human text\"\n",
			"/proc/sys/kernel/osrelease":                  "6.12.0-fixture\n",
			"/proc/1/comm":                                "systemd\n",
			"/sys/fs/cgroup/cgroup.controllers":           "cpu memory pids\n",
			"/sys/fs/cgroup/system.slice/memory.swap.max": "max\n",
			"/proc/filesystems":                           "nodev\tsysfs\nnodev\ttmpfs\n",
			"/proc/meminfo":                               "MemTotal: 4194304 kB\nMemAvailable: 2097152 kB\n",
			"/proc/swaps":                                 "Filename\t\tType\tSize\tUsed\tPriority\n",
			"/proc/sys/kernel/core_pattern":               "|/private/collector --argument-not-for-output\n",
		},
		info:   make(map[string]fakeInfo),
		xattrs: make(map[string]error),
		cfg:    config.Default(),
		inventory: toolkit.Inventory{
			Build:  toolkit.BuildMetadata{Distro: "debian", Release: "13", Architecture: "amd64"},
			Digest: "sha256:" + strings.Repeat("a", 64),
		},
		fsType:   unix.CGROUP2_SUPER_MAGIC,
		procType: unix.PROC_SUPER_MAGIC,
	}
	for _, name := range []string{"/", "/usr", "/usr/bin", "/usr/libexec", "/usr/libexec/soteria", "/run", "/run/systemd", "/run/systemd/system", "/run/dbus"} {
		f.info[name] = fakeInfo{mode: os.ModeDir | 0o755}
	}
	for _, name := range []string{protocol.StarterPath, protocol.EnginePath, protocol.BubblewrapPath, "/usr/bin/sudo"} {
		f.info[name] = fakeInfo{mode: 0o755}
	}
	for _, name := range []string{"mnt", "pid", "ipc", "uts", "net"} {
		f.info["/proc/self/ns/"+name] = fakeInfo{mode: os.ModeSymlink | 0o777}
	}
	f.info["/usr/bin/sudo"] = fakeInfo{mode: os.ModeSetuid | 0o755}
	f.info["/run/dbus/system_bus_socket"] = fakeInfo{mode: os.ModeSocket | 0o777}
	return f
}

func (f *hostFixture) probes(t *testing.T) probes {
	t.Helper()
	return probes{
		readFile: func(path string, limit int64) ([]byte, error) {
			f.readPaths = append(f.readPaths, path)
			value, ok := f.files[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			if int64(len(value)) > limit {
				return nil, errors.New("fixture exceeds read limit")
			}
			return []byte(value), nil
		},
		lstat: func(path string) (fs.FileInfo, error) {
			f.statPaths = append(f.statPaths, path)
			info, ok := f.info[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return info, nil
		},
		statfs: func(path string) (int64, error) {
			switch path {
			case "/sys/fs/cgroup":
				return f.fsType, nil
			case "/proc":
				return f.procType, nil
			default:
				t.Fatalf("unexpected filesystem inspection: %s", path)
				return 0, os.ErrNotExist
			}
		},
		xattr: func(path, attribute string, buffer []byte) (int, error) {
			if attribute != "security.capability" || buffer != nil {
				t.Fatal("doctor attempted non-metadata xattr access")
			}
			if err, ok := f.xattrs[path]; ok {
				return 0, err
			}
			return 0, unix.ENODATA
		},
		verify: func(path string) (toolkit.Inventory, error) {
			f.verifyCalls++
			if path != toolkit.Root {
				t.Fatalf("discovered arbitrary runtime: %s", path)
			}
			return f.inventory, f.verifyErr
		},
	}
}

func (f *hostFixture) report(t *testing.T) Report {
	t.Helper()
	r := Report{Checks: []CheckResult{}, Config: &f.cfg}
	probeLinux(context.Background(), f.cfg, &r, f.probes(t))
	return r
}

func findCheck(t *testing.T, r Report, name string) CheckResult {
	t.Helper()
	for _, check := range r.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("missing diagnostic check %q", name)
	return CheckResult{}
}

func TestSupportedHostReadOnlyFacts(t *testing.T) {
	f := newHostFixture()
	t.Setenv("PATH", t.TempDir())
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "tcp:host=must-not-connect,port=1")
	r := f.report(t)
	if !r.OK() || f.verifyCalls != 1 || !strings.Contains(findCheck(t, r, "toolkit").Detail, f.inventory.Digest) {
		t.Fatalf("unexpected supported host report: %+v", r)
	}
	for _, id := range []string{"distribution", "systemd_pid1", "runtime_directory", "systemd_runtime", "system_bus", "cgroup_v2", "cgroup_controllers", "swap_controller", "namespaces", "tmpfs", "installed_starter", "installed_engine", "bubblewrap", "authorization_tool", "toolkit", "toolkit_target"} {
		if check := findCheck(t, r, id); check.Status != Verified {
			t.Fatalf("required fact %s: %+v", id, check)
		}
	}
	for _, id := range []string{"authorized_startup", "service_cgroup", "tmpfs_noswap", "frontend_heap", "network_startup", "hibernation_snapshots"} {
		if check := findCheck(t, r, id); check.Status != Warning {
			t.Fatalf("unverified behavior mislabeled: %+v", check)
		}
	}
	if check := findCheck(t, r, "memory_dumps"); check.Status != Warning || !strings.Contains(check.Detail, "piped") || !strings.Contains(check.Detail, "metadata are unknown") || strings.Contains(check.Detail, "/private/collector") {
		t.Fatalf("dump risk missing or collector command leaked: %+v", check)
	}
	for _, path := range append(f.readPaths, f.statPaths...) {
		if strings.HasPrefix(path, "/etc/soteria") || strings.Contains(path, ".key") {
			t.Fatalf("doctor read a profile or credential: %s", path)
		}
	}
	for _, check := range r.Checks {
		if check.Status != Verified && check.Status != Warning && check.Status != Required && check.Status != Unsupported {
			t.Fatalf("obsolete or invented diagnostic status: %+v", check)
		}
	}
}

func TestRequiredPrerequisiteFailures(t *testing.T) {
	for _, test := range []struct {
		name, id string
		change   func(*hostFixture)
	}{
		{"missing distro", "distribution", func(f *hostFixture) { delete(f.files, "/etc/os-release") }},
		{"invalid distro", "distribution", func(f *hostFixture) { f.files["/etc/os-release"] = "ID=debian\nID=ubuntu\nVERSION_ID=13\n" }},
		{"not systemd", "systemd_pid1", func(f *hostFixture) { f.files["/proc/1/comm"] = "init\n" }},
		{"missing pid1", "systemd_pid1", func(f *hostFixture) { delete(f.files, "/proc/1/comm") }},
		{"writable runtime", "runtime_directory", func(f *hostFixture) { f.info["/run"] = fakeInfo{mode: os.ModeDir | 0o777} }},
		{"missing systemd runtime", "systemd_runtime", func(f *hostFixture) { delete(f.info, "/run/systemd/system") }},
		{"missing bus", "system_bus", func(f *hostFixture) { delete(f.info, "/run/dbus/system_bus_socket") }},
		{"not a bus socket", "system_bus", func(f *hostFixture) { f.info["/run/dbus/system_bus_socket"] = fakeInfo{mode: 0o644} }},
		{"unowned bus socket", "system_bus", func(f *hostFixture) {
			f.info["/run/dbus/system_bus_socket"] = fakeInfo{mode: os.ModeSocket | 0o777, uid: 1000}
		}},
		{"unsafe bus directory", "system_bus", func(f *hostFixture) { f.info["/run/dbus"] = fakeInfo{mode: os.ModeSymlink | 0o777} }},
		{"legacy cgroups", "cgroup_v2", func(f *hostFixture) { f.fsType = unix.TMPFS_MAGIC }},
		{"missing memory controller", "cgroup_controllers", func(f *hostFixture) { f.files["/sys/fs/cgroup/cgroup.controllers"] = "cpu pids\n" }},
		{"missing pids controller", "cgroup_controllers", func(f *hostFixture) { f.files["/sys/fs/cgroup/cgroup.controllers"] = "cpu memory\n" }},
		{"missing controller file", "cgroup_controllers", func(f *hostFixture) { delete(f.files, "/sys/fs/cgroup/cgroup.controllers") }},
		{"not procfs", "namespaces", func(f *hostFixture) { f.procType = unix.TMPFS_MAGIC }},
		{"missing network namespace", "namespaces", func(f *hostFixture) { delete(f.info, "/proc/self/ns/net") }},
		{"not a namespace entry", "namespaces", func(f *hostFixture) { f.info["/proc/self/ns/mnt"] = fakeInfo{mode: 0o444} }},
		{"no tmpfs", "tmpfs", func(f *hostFixture) { f.files["/proc/filesystems"] = "nodev sysfs\n" }},
		{"missing starter", "installed_starter", func(f *hostFixture) { delete(f.info, protocol.StarterPath) }},
		{"symlink starter", "installed_starter", func(f *hostFixture) { f.info[protocol.StarterPath] = fakeInfo{mode: os.ModeSymlink | 0o777} }},
		{"missing engine", "installed_engine", func(f *hostFixture) { delete(f.info, protocol.EnginePath) }},
		{"writable engine", "installed_engine", func(f *hostFixture) { f.info[protocol.EnginePath] = fakeInfo{mode: 0o777} }},
		{"missing bubblewrap", "bubblewrap", func(f *hostFixture) { delete(f.info, "/usr/bin/bwrap") }},
		{"setuid bubblewrap", "bubblewrap", func(f *hostFixture) { f.info[protocol.BubblewrapPath] = fakeInfo{mode: os.ModeSetuid | 0o755} }},
		{"capability bubblewrap", "bubblewrap", func(f *hostFixture) { f.xattrs[protocol.BubblewrapPath] = nil }},
		{"missing sudo", "authorization_tool", func(f *hostFixture) { delete(f.info, "/usr/bin/sudo") }},
		{"unverified runtime", "toolkit", func(f *hostFixture) { f.verifyErr = errors.New("digest mismatch") }},
		{"runtime wrong distro", "toolkit_target", func(f *hostFixture) { f.inventory.Build.Distro, f.inventory.Build.Release = "ubuntu", "24.04" }},
		{"runtime wrong release", "toolkit_target", func(f *hostFixture) { f.inventory.Build.Release = "12" }},
		{"runtime wrong architecture", "toolkit_target", func(f *hostFixture) { f.inventory.Build.Architecture = "arm64" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newHostFixture()
			test.change(f)
			r := f.report(t)
			if r.OK() || findCheck(t, r, test.id).Status != Required {
				t.Fatalf("required failure not reported: %+v", r)
			}
			if test.id == "toolkit" && strings.Contains(findCheck(t, r, "toolkit").Detail, f.inventory.Digest) {
				t.Fatal("unverified manifest digest was published")
			}
		})
	}
}

func TestMemoryRisksAreWarningsNotPrerequisites(t *testing.T) {
	f := newHostFixture()
	f.files["/proc/meminfo"] = "MemAvailable: 131072 kB\n"
	f.files["/proc/swaps"] += "/private/swap-secret file 524288 16 -2\n"
	r := f.report(t)
	if !r.OK() {
		t.Fatal("best-effort memory policy must not disable the runtime")
	}
	for _, id := range []string{"available_memory", "host_swap", "memory_dumps", "hibernation_snapshots", "frontend_heap", "tmpfs_noswap", "service_cgroup"} {
		check := findCheck(t, r, id)
		if check.Status != Warning || strings.Contains(check.Detail, "swap-secret") {
			t.Fatalf("memory policy or path disclosure error: %+v", check)
		}
	}
	delete(f.files, "/proc/swaps")
	delete(f.files, "/proc/sys/kernel/core_pattern")
	delete(f.files, "/proc/meminfo")
	r = f.report(t)
	if !r.OK() || findCheck(t, r, "host_swap").Status != Warning || findCheck(t, r, "memory_dumps").Status != Warning || findCheck(t, r, "available_memory").Status != Warning {
		t.Fatal("unknown memory policy must remain a visible nonfatal warning")
	}
}

func TestExecutablePathOwnershipAndNoSymlinkAncestors(t *testing.T) {
	for _, test := range []struct {
		name, path string
		info       fakeInfo
	}{
		{"wrong owner", protocol.StarterPath, fakeInfo{mode: 0o755, uid: 1000}},
		{"wrong group", protocol.StarterPath, fakeInfo{mode: 0o755, gid: 1000}},
		{"writable starter", protocol.StarterPath, fakeInfo{mode: 0o775}},
		{"nonexecutable starter", protocol.StarterPath, fakeInfo{mode: 0o644}},
		{"setuid starter", protocol.StarterPath, fakeInfo{mode: os.ModeSetuid | 0o755}},
		{"setgid starter", protocol.StarterPath, fakeInfo{mode: os.ModeSetgid | 0o755}},
		{"directory starter", protocol.StarterPath, fakeInfo{mode: os.ModeDir | 0o755}},
		{"symlink ancestor", "/usr/libexec", fakeInfo{mode: os.ModeSymlink | 0o755}},
		{"writable ancestor", "/usr", fakeInfo{mode: os.ModeDir | 0o777}},
		{"unowned root", "/", fakeInfo{mode: os.ModeDir | 0o755, uid: 1000}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newHostFixture()
			f.info[test.path] = test.info
			if err := executablePath(f.probes(t), protocol.StarterPath, false); err == nil {
				t.Fatal("unsafe executable path accepted")
			}
		})
	}
	f := newHostFixture()
	if err := executablePath(f.probes(t), "/usr/bin/sudo", true); err != nil {
		t.Fatalf("packaged sudo's expected setuid bit rejected: %v", err)
	}
}

func TestOSReleaseParsing(t *testing.T) {
	for _, test := range []struct {
		input, distro, release string
		valid                  bool
	}{
		{"ID=debian\nVERSION_ID=\"13\"\n", "debian", "13", true},
		{"# comment\nID='ubuntu'\nVERSION_ID='24.04'\nNAME=Ubuntu\n", "ubuntu", "24.04", true},
		{"ID=ubuntu\nVERSION_ID=24.10\n", "ubuntu", "24.10", true},
		{"ID=debian\nID=ubuntu\nVERSION_ID=13\n", "", "", false},
		{"ID=debian\n", "", "", false},
		{"ID=$(program)\nVERSION_ID=13\n", "", "", false},
		{"ID=\"debian\nVERSION_ID=13\n", "", "", false},
		{"ID=debian\nVERSION_ID=\"\"\n", "", "", false},
	} {
		distro, release, err := osRelease([]byte(test.input))
		if (err == nil) != test.valid || distro != test.distro || release != test.release {
			t.Fatalf("parse %q: %q %q %v", test.input, distro, release, err)
		}
	}
}

func TestReadLimitedDoesNotModifyInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("read-only fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readLimited(path, 64)
	if err != nil || string(data) != "read-only fixture" {
		t.Fatalf("read fixture: %q %v", data, err)
	}
	if _, err := readLimited(path, 4); err == nil {
		t.Fatal("oversized probe input accepted")
	}
	if _, err := readLimited(filepath.Dir(path), 64); err == nil {
		t.Fatal("directory accepted as probe input")
	}
	for _, limit := range []int64{0, -1} {
		if _, err := readLimited(path, limit); err == nil {
			t.Fatal("nonpositive diagnostic read bound accepted")
		}
	}
	if _, err := readLimited(path+"-missing", 64); err == nil {
		t.Fatal("missing diagnostic input accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != "read-only fixture" {
		t.Fatalf("probe changed input: %q %v", after, err)
	}
}

func TestReadLimitedRejectsFIFOWithoutOpeningIt(t *testing.T) {
	name := filepath.Join(t.TempDir(), "not-a-file")
	if err := unix.Mkfifo(name, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLimited(name, 64); err == nil {
		t.Fatal("FIFO accepted as diagnostic input")
	}
}

func TestCancellationAvoidsRuntimeVerification(t *testing.T) {
	f := newHostFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Report{}
	probeLinux(ctx, f.cfg, &r, f.probes(t))
	if f.verifyCalls != 0 || r.OK() || len(f.readPaths) != 0 || len(f.statPaths) != 0 {
		t.Fatal("canceled probe must not start any host reads or runtime verification")
	}
}

func TestCancellationAfterVerificationAvoidsProfileInspection(t *testing.T) {
	f := newHostFixture()
	f.useProfile("provider")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := f.probes(t)
	verify := p.verify
	p.verify = func(name string) (toolkit.Inventory, error) {
		inventory, err := verify(name)
		cancel()
		return inventory, err
	}
	r := Report{}
	probeLinux(ctx, f.cfg, &r, p)
	if r.OK() || f.verifyCalls != 1 || findCheck(t, r, "diagnostics").Status != Required {
		t.Fatal("cancellation after verification was ignored")
	}
	for _, name := range f.statPaths {
		if strings.HasPrefix(name, network.ProfileDirectory) {
			t.Fatal("profile inspection started after cancellation")
		}
	}
}

func TestExecutableCapabilitiesMustBeAbsent(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		ok   bool
	}{
		{"no attribute", unix.ENODATA, true},
		{"filesystem lacks xattrs", unix.EOPNOTSUPP, true},
		{"capabilities present", nil, false},
		{"capabilities unreadable", unix.EACCES, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newHostFixture()
			f.xattrs[protocol.EnginePath] = test.err
			err := executablePath(f.probes(t), protocol.EnginePath, false)
			if (err == nil) != test.ok {
				t.Fatalf("capability metadata result: %v", err)
			}
		})
	}
}

func TestDistributionSupportIsExact(t *testing.T) {
	for _, test := range []struct{ distro, release, status string }{
		{"debian", "13", Verified},
		{"ubuntu", "24.04", Verified},
		{"debian", "12", Unsupported},
		{"debian", "13.1", Unsupported},
		{"ubuntu", "24.10", Unsupported},
		{"linuxmint", "24.04", Unsupported},
	} {
		t.Run(test.distro+"/"+test.release, func(t *testing.T) {
			f := newHostFixture()
			f.files["/etc/os-release"] = "ID=" + test.distro + "\nVERSION_ID=" + test.release + "\nID_LIKE=ubuntu\n"
			if test.status == Verified {
				f.inventory.Build.Distro, f.inventory.Build.Release = test.distro, test.release
			}
			r := f.report(t)
			if findCheck(t, r, "distribution").Status != test.status || r.OK() != (test.status == Verified) {
				t.Fatalf("incorrect support scope: %+v", r)
			}
		})
	}
}

func TestMemoryCapacityUsesConfiguredBounds(t *testing.T) {
	for _, test := range []struct{ memory, workspace, transfer, available, status string }{
		{"4G", "2G", "256M", "2097152", Warning},
		{"128M", "16M", "16M", "262144", Verified},
		{"1G", "512M", "256M", "0", Warning},
	} {
		f := newHostFixture()
		f.cfg.Resources.MemoryMax, f.cfg.Resources.WorkspaceSize = test.memory, test.workspace
		f.cfg.Transfers.MaxBytes = test.transfer
		if err := f.cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		f.files["/proc/meminfo"] = "MemAvailable: " + test.available + " kB\n"
		r := f.report(t)
		check := findCheck(t, r, "available_memory")
		if !r.OK() || check.Status != test.status || !strings.Contains(check.Detail, "maximum "+test.memory) || !strings.Contains(check.Detail, "bound "+test.workspace) {
			t.Fatalf("capacity did not use configured limits: %+v", check)
		}
	}
}

func TestStartupProtectionIsNeverInferredFromKernelVersion(t *testing.T) {
	for _, kernel := range []string{"4.19.0", "6.12.0", "7.2.0"} {
		f := newHostFixture()
		f.files["/proc/sys/kernel/osrelease"] = kernel + "\n"
		f.files["/sys/fs/cgroup/system.slice/memory.swap.max"] = "0\n"
		r := f.report(t)
		for _, name := range []string{"service_cgroup", "tmpfs_noswap", "frontend_heap", "authorized_startup"} {
			if check := findCheck(t, r, name); check.Status != Warning {
				t.Fatalf("kernel %s incorrectly verified startup protection: %+v", kernel, check)
			}
		}
	}
}

func TestUnknownSwapAndDumpPoliciesRemainNonfatal(t *testing.T) {
	for _, swapLimit := range []string{"", "max\nextra", "-1", "18446744073709551616"} {
		f := newHostFixture()
		f.files["/sys/fs/cgroup/system.slice/memory.swap.max"] = swapLimit
		f.files["/proc/sys/kernel/core_pattern"] = "core.%p\n"
		r := f.report(t)
		if !r.OK() || findCheck(t, r, "swap_controller").Status != Warning || findCheck(t, r, "memory_dumps").Status != Warning {
			t.Fatal("unverified memory policies must warn and continue")
		}
	}
	f := newHostFixture()
	delete(f.files, "/sys/fs/cgroup/system.slice/memory.swap.max")
	delete(f.files, "/proc/sys/kernel/osrelease")
	f.files["/proc/meminfo"] = "MemAvailable: 18446744073709551615 kB\n"
	r := f.report(t)
	for _, name := range []string{"swap_controller", "kernel", "available_memory"} {
		if findCheck(t, r, name).Status != Warning || !r.OK() {
			t.Fatal("missing or overflowing optional observations must warn")
		}
	}
}

func (f *hostFixture) useProfile(name string) {
	f.cfg.Network = config.NetworkConfig{Mode: "wireguard", Profile: name}
	for _, path := range []string{"/etc", "/etc/soteria", network.ProfileDirectory} {
		f.info[path] = fakeInfo{mode: os.ModeDir | 0o755}
	}
	f.info[network.ProfileDirectory+"/"+name+".json"] = fakeInfo{mode: 0o644, size: 128, links: 1}
	f.info[network.ProfileDirectory+"/"+name+".key"] = fakeInfo{mode: 0o600, size: 45, links: 1}
}

func TestProfileInspectionNeverReadsCredentialsOrMetadataContents(t *testing.T) {
	for _, name := range []string{"provider_1-west", strings.Repeat("a", 48)} {
		f := newHostFixture()
		f.useProfile(name)
		r := f.report(t)
		if !r.OK() || findCheck(t, r, "network_profile").Status != Verified || findCheck(t, r, "network_startup").Status != Warning {
			t.Fatalf("safe profile metadata report: %+v", r)
		}
		keyStatted := false
		for _, path := range f.statPaths {
			keyStatted = keyStatted || path == network.ProfileDirectory+"/"+name+".key"
		}
		if !keyStatted {
			t.Fatal("credential permission metadata was not inspected")
		}
		for _, path := range f.readPaths {
			if strings.HasPrefix(path, network.ProfileDirectory) || strings.HasSuffix(path, ".key") {
				t.Fatalf("doctor attempted to read profile or credential content: %s", path)
			}
		}
	}
}

func TestUnsafeProfileMetadataIsRequired(t *testing.T) {
	metadata := network.ProfileDirectory + "/provider.json"
	key := network.ProfileDirectory + "/provider.key"
	for _, test := range []struct {
		name, path string
		info       fakeInfo
	}{
		{"symlink parent", network.ProfileDirectory, fakeInfo{mode: os.ModeSymlink | 0o777}},
		{"writable parent", "/etc/soteria", fakeInfo{mode: os.ModeDir | 0o777}},
		{"unowned parent", "/etc", fakeInfo{mode: os.ModeDir | 0o755, uid: 1000}},
		{"metadata symlink", metadata, fakeInfo{mode: os.ModeSymlink | 0o777, size: 128, links: 1}},
		{"metadata writable", metadata, fakeInfo{mode: 0o666, size: 128, links: 1}},
		{"metadata special bits", metadata, fakeInfo{mode: os.ModeSetuid | 0o644, size: 128, links: 1}},
		{"metadata unowned", metadata, fakeInfo{mode: 0o644, uid: 1000, size: 128, links: 1}},
		{"metadata empty", metadata, fakeInfo{mode: 0o644, size: 0, links: 1}},
		{"metadata oversized", metadata, fakeInfo{mode: 0o644, size: 16385, links: 1}},
		{"credential world readable", key, fakeInfo{mode: 0o644, size: 45, links: 1}},
		{"credential wrong group", key, fakeInfo{mode: 0o600, gid: 1000, size: 45, links: 1}},
		{"credential hardlink", key, fakeInfo{mode: 0o600, size: 45, links: 2}},
		{"credential symlink", key, fakeInfo{mode: os.ModeSymlink | 0o600, size: 45, links: 1}},
		{"credential fifo", key, fakeInfo{mode: os.ModeNamedPipe | 0o600, size: 45, links: 1}},
		{"credential short", key, fakeInfo{mode: 0o600, size: 43, links: 1}},
		{"credential long", key, fakeInfo{mode: 0o600, size: 46, links: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newHostFixture()
			f.useProfile("provider")
			f.info[test.path] = test.info
			r := f.report(t)
			if r.OK() || findCheck(t, r, "network_profile").Status != Required {
				t.Fatalf("unsafe requested profile allowed: %+v", r)
			}
		})
	}
	f := newHostFixture()
	f.useProfile("provider")
	delete(f.info, key)
	if r := f.report(t); r.OK() || findCheck(t, r, "network_profile").Status != Required {
		t.Fatal("missing credential must fail the requested profile metadata check")
	}
}

func TestProfileIDIsValidatedBeforeAnyPathInspection(t *testing.T) {
	for _, name := range []string{"", "../provider", "valid/../provider", "UPPER", "bad\x00key", strings.Repeat("a", 49)} {
		err := profilePermissions(func(string) (fs.FileInfo, error) {
			t.Fatal("invalid profile name reached filesystem")
			return nil, os.ErrNotExist
		}, name)
		if err == nil {
			t.Fatalf("unsafe profile ID accepted: %q", name)
		}
	}
}

func TestLimitAndFilesystemParsers(t *testing.T) {
	for _, value := range []string{"max", "0", "1", "18446744073709551615"} {
		if !validCgroupLimit(value) {
			t.Fatalf("valid cgroup limit rejected: %q", value)
		}
	}
	for _, value := range []string{"", "-1", "+1", "1k", "MAX", "18446744073709551616", "0\n1"} {
		if validCgroupLimit(value) {
			t.Fatalf("invalid cgroup limit accepted: %q", value)
		}
	}
	for _, test := range []struct {
		data string
		want bool
	}{
		{"nodev\ttmpfs\n", true}, {"tmpfs\n", true},
		{"nodev\txtmpfs\n", false}, {"tmpfs extra\n", false},
		{"nodev extra tmpfs\n", false}, {"", false},
	} {
		if got := filesystemAvailable([]byte(test.data), "tmpfs"); got != test.want {
			t.Fatalf("filesystem availability for %q = %v", test.data, got)
		}
	}
}

func TestAvailableMemoryParser(t *testing.T) {
	for _, test := range []struct {
		data  string
		bytes uint64
		valid bool
	}{
		{"MemTotal: 999 kB\nMemAvailable: 1024 kB\n", 1 << 20, true},
		{"MemAvailable:\t0 kB\n", 0, true},
		{"MemAvailable: 18014398509481983 kB\n", 18446744073709550592, true},
		{"", 0, false}, {"MemAvailable: 18014398509481984 kB\n", 0, false},
		{"MemAvailable: -1 kB\n", 0, false}, {"MemAvailable: 1 MB\n", 0, false},
		{"MemAvailable: max kB\n", 0, false}, {"MemAvailable: 1\n", 0, false},
		{"MemAvailable: 1 kB\nMemAvailable: 2 kB\n", 0, false},
	} {
		got, err := availableMemory([]byte(test.data))
		if (err == nil) != test.valid || got != test.bytes {
			t.Fatalf("parse %q = %d, %v", test.data, got, err)
		}
	}
}

func TestNoActiveSwapParser(t *testing.T) {
	header := "Filename\t\tType\tSize\tUsed\tPriority\n"
	if !noActiveSwap([]byte(header)) {
		t.Fatal("empty kernel swap listing rejected")
	}
	for _, data := range []string{"", "Filename bogus\n", header + "/private/swap file 123 0 -1\n", "Filename Type Size Used Priority extra\n"} {
		if noActiveSwap([]byte(data)) {
			t.Fatalf("active or unrecognized swap listing reported empty: %q", data)
		}
	}
}

func FuzzReadOnlyParsers(f *testing.F) {
	for _, input := range []string{"ID=debian\nVERSION_ID=13\n", "MemAvailable: 1048576 kB\n", "nodev\ttmpfs\n", "max", "Filename Type Size Used Priority\n", "\x00\xff"} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		_, _, _ = osRelease(data)
		_, _ = availableMemory(data)
		_ = validCgroupLimit(string(data))
		_ = filesystemAvailable(data, "tmpfs")
		_ = noActiveSwap(data)
	})
}
