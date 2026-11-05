//go:build linux && amd64

package doctor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/network"
	"github.com/Lfardell1/Soteria/internal/protocol"
	"github.com/Lfardell1/Soteria/internal/toolkit"
	"golang.org/x/sys/unix"
)

// These seams replace only real read-only OS boundaries and toolkit verification.
type probes struct {
	readFile func(string, int64) ([]byte, error)
	lstat    func(string) (fs.FileInfo, error)
	statfs   func(string) (int64, error)
	xattr    func(string, string, []byte) (int, error)
	verify   func(string) (toolkit.Inventory, error)
}

func probeHost(ctx context.Context, cfg config.Config, r *Report) {
	probeLinux(ctx, cfg, r, probes{
		readFile: readLimited,
		lstat:    os.Lstat,
		statfs: func(path string) (int64, error) {
			var st unix.Statfs_t
			err := unix.Statfs(path, &st)
			return st.Type, err
		},
		xattr:  unix.Lgetxattr,
		verify: toolkit.Verify,
	})
}

func probeLinux(ctx context.Context, cfg config.Config, r *Report, p probes) {
	if canceled(ctx, r) {
		return
	}
	var distro, release string
	data, err := p.readFile("/etc/os-release", 16<<10)
	if err != nil {
		r.add("distribution", Required, fmt.Sprintf("Cannot read /etc/os-release: %v", err))
	} else if distro, release, err = osRelease(data); err != nil {
		r.add("distribution", Required, fmt.Sprintf("Cannot identify supported distribution: %v", err))
	} else if distro == "debian" && release == "13" || distro == "ubuntu" && release == "24.04" {
		r.add("distribution", Verified, "Supported host release: "+distro+" "+release)
	} else {
		r.add("distribution", Unsupported, "Unsupported host release: "+distro+" "+release+"; only Debian 13 and Ubuntu 24.04 are in the Linux amd64 support scope")
	}
	if data, err := p.readFile("/proc/sys/kernel/osrelease", 256); err != nil {
		r.add("kernel", Warning, "Kernel release could not be read; namespace availability is checked separately")
	} else if kernel := strings.TrimSpace(string(data)); kernel == "" {
		r.add("kernel", Warning, "Kernel release is empty; no protection is inferred from a kernel version")
	} else {
		r.add("kernel", Verified, "Observed kernel release: "+kernel+"; no isolation or tmpfs noswap effectiveness is inferred from the version")
	}
	if data, err := p.readFile("/proc/1/comm", 256); err != nil {
		r.add("systemd_pid1", Required, fmt.Sprintf("Cannot identify PID 1: %v", err))
	} else if strings.TrimSpace(string(data)) != "systemd" {
		r.add("systemd_pid1", Required, "PID 1 is not systemd; a system systemd service manager is required")
	} else {
		r.add("systemd_pid1", Verified, "PID 1 reports systemd; no service was started")
	}
	for _, directory := range []struct{ name, path string }{
		{"runtime_directory", "/run"},
		{"systemd_runtime", "/run/systemd/system"},
	} {
		if err := trustedDirectory(p.lstat, directory.path); err != nil {
			r.add(directory.name, Required, fmt.Sprintf("Required runtime directory %s: %v", directory.path, err))
		} else {
			r.add(directory.name, Verified, "Observed root-owned runtime directory "+directory.path+"; no session directory was created")
		}
	}
	if err := trustedDirectory(p.lstat, "/run/dbus"); err != nil {
		r.add("system_bus", Required, fmt.Sprintf("System D-Bus directory is unavailable or untrusted: %v", err))
	} else if info, err := p.lstat("/run/dbus/system_bus_socket"); err != nil {
		r.add("system_bus", Required, fmt.Sprintf("System D-Bus socket is unavailable: %v", err))
	} else if info.Mode()&os.ModeSocket == 0 || !rootOwned(info) {
		r.add("system_bus", Required, "/run/dbus/system_bus_socket must be a real root-owned socket")
	} else {
		r.add("system_bus", Verified, "System D-Bus socket exists; no connection, activation, or authorization was attempted")
	}
	if kind, err := p.statfs("/sys/fs/cgroup"); err != nil {
		r.add("cgroup_v2", Required, fmt.Sprintf("Cannot inspect cgroup filesystem: %v", err))
	} else if kind != unix.CGROUP2_SUPER_MAGIC {
		r.add("cgroup_v2", Required, "/sys/fs/cgroup is not a cgroup v2 filesystem")
	} else {
		r.add("cgroup_v2", Verified, "Unified cgroup v2 filesystem is mounted at /sys/fs/cgroup")
	}
	if data, err := p.readFile("/sys/fs/cgroup/cgroup.controllers", 4<<10); err != nil {
		r.add("cgroup_controllers", Required, fmt.Sprintf("Cannot read available cgroup v2 controllers: %v", err))
	} else if !hasField(data, "memory") || !hasField(data, "pids") {
		r.add("cgroup_controllers", Required, "The memory and pids cgroup v2 controllers are both required")
	} else {
		r.add("cgroup_controllers", Verified, "memory and pids controllers are listed as available; per-service limits remain unverified")
	}
	if data, err := p.readFile("/sys/fs/cgroup/system.slice/memory.swap.max", 256); err != nil {
		r.add("swap_controller", Warning, "The system.slice memory.swap.max interface could not be read; swap control availability and MemorySwapMax=0 effectiveness require authorized startup")
	} else if value := strings.TrimSpace(string(data)); !validCgroupLimit(value) {
		r.add("swap_controller", Warning, "The system.slice swap limit is unrecognized; no service swap protection is established")
	} else {
		r.add("swap_controller", Verified, "The system.slice memory.swap.max interface is readable ("+value+"); this is not the session's effective swap policy")
	}
	r.add("service_cgroup", Warning, "MemoryMax, TasksMax and MemorySwapMax=0 must be applied and read back in the authorized service before receiving credentials; doctor created no service or cgroup")
	if canceled(ctx, r) {
		return
	}
	if kind, err := p.statfs("/proc"); err != nil || kind != unix.PROC_SUPER_MAGIC {
		r.add("namespaces", Required, "A mounted procfs is required to inspect kernel namespace availability; no namespace was created")
	} else {
		var missing []string
		for _, name := range []string{"mnt", "pid", "ipc", "uts", "net"} {
			info, err := p.lstat("/proc/self/ns/" + name)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				missing = append(missing, name)
			}
		}
		if len(missing) != 0 {
			r.add("namespaces", Required, "Required kernel namespace entries are unavailable: "+strings.Join(missing, ", "))
		} else {
			r.add("namespaces", Verified, "Kernel mnt, pid, ipc, uts and net namespace entries are exposed in procfs; creation, privilege and enforcement still require authorized startup")
		}
	}
	if data, err := p.readFile("/proc/filesystems", 16<<10); err != nil {
		r.add("tmpfs", Required, fmt.Sprintf("Cannot inspect tmpfs support: %v", err))
	} else if !filesystemAvailable(data, "tmpfs") {
		r.add("tmpfs", Required, "tmpfs is not listed as available; disk-backed fallback is not permitted")
	} else {
		r.add("tmpfs", Verified, "tmpfs is listed as available; no mount or noswap test was attempted")
	}
	for _, executable := range []struct {
		name, path  string
		allowSetuid bool
	}{
		{"installed_starter", protocol.StarterPath, false},
		{"installed_engine", protocol.EnginePath, false},
		{"bubblewrap", protocol.BubblewrapPath, false},
		{"authorization_tool", "/usr/bin/sudo", true},
	} {
		if err := executablePath(p, executable.path, executable.allowSetuid); err != nil {
			r.add(executable.name, Required, fmt.Sprintf("Fixed executable %s: %v", executable.path, err))
		} else {
			r.add(executable.name, Verified, "Fixed root-owned executable "+executable.path+" and its real ancestors are not writable by group/others; permission metadata checked, not executed")
		}
	}
	if canceled(ctx, r) {
		return
	}
	if inventory, err := p.verify(toolkit.Root); err != nil {
		r.add("toolkit", Required, fmt.Sprintf("Curated runtime verification failed at %s: %v; no host substitutes are used", toolkit.Root, err))
	} else {
		r.add("toolkit", Verified, "Curated runtime inventory, ownership, modes, contents and digest verified at "+toolkit.Root+": "+inventory.Digest)
		build := inventory.Build
		if build.Architecture != "amd64" || distro == "" || release == "" || build.Distro != distro || build.Release != release {
			r.add("toolkit_target", Required, "Verified runtime build metadata does not match this host's exact distro/release and amd64 architecture")
		} else {
			r.add("toolkit_target", Verified, "Verified runtime metadata matches "+build.Distro+" "+build.Release+" amd64; curated setpriv and setsid are inventoried dependencies")
		}
	}
	if canceled(ctx, r) {
		return
	}
	if cfg.Network.Mode == "wireguard" {
		if err := profilePermissions(p.lstat, cfg.Network.Profile); err != nil {
			r.add("network_profile", Required, "Requested profile permission metadata is unavailable or unsafe: "+err.Error()+"; no private key was loaded")
		} else {
			r.add("network_profile", Verified, "Requested profile files under "+network.ProfileDirectory+" have the required ownership, types, permissions and sizes; file contents and private-key validity were not inspected")
		}
	} else {
		r.add("network_profile", Verified, "Offline mode selected; no profile or credential files were inspected")
	}
	r.add("network_startup", Warning, "The selected "+cfg.Network.Mode+" network boundary and any WireGuard handshake/resolver readiness require authorized startup; no networking was activated or probed")
	memoryChecks(r, cfg, p.readFile)
	r.add("authorized_startup", Warning, "D-Bus authorization, service ownership, namespace isolation, privilege reduction, descriptor closure and cleanup require authorized startup; read-only prerequisites are not proof of these behaviors")
}

func memoryChecks(r *Report, cfg config.Config, readFile func(string, int64) ([]byte, error)) {
	if data, err := readFile("/proc/meminfo", 16<<10); err != nil {
		r.add("available_memory", Warning, "Available memory could not be read; configured limits are not reservations")
	} else if available, err := availableMemory(data); err != nil {
		r.add("available_memory", Warning, "MemAvailable is missing or invalid; configured limits are not reservations")
	} else {
		memory, _ := config.ParseSize(cfg.Resources.MemoryMax)
		workspace, _ := config.ParseSize(cfg.Resources.WorkspaceSize)
		status := Verified
		if available < memory {
			status = Warning
		}
		r.add("available_memory", status, fmt.Sprintf("MemAvailable reports %s; configured service maximum %s and workspace bound %s. Availability is transient, excludes tighter ancestor cgroup limits, and is not a reservation; memory pressure may cause ENOSPC/OOM", config.FormatSize(available), config.FormatSize(memory), config.FormatSize(workspace)))
	}
	if data, err := readFile("/proc/swaps", 64<<10); err != nil {
		r.add("host_swap", Warning, "Host swap state could not be read; session and frontend memory may be retained on disk")
	} else if !noActiveSwap(data) {
		r.add("host_swap", Warning, "Active swap is listed or the listing is unrecognized; anonymous memory and ordinary tmpfs pages may be written to swap; no host policy was changed")
	} else {
		r.add("host_swap", Verified, "No active swap is listed at probe time; future swap, hibernation and hypervisor policy remain unknown")
	}
	r.add("tmpfs_noswap", Warning, "tmpfs noswap support and effectiveness require an attempted mount and read-back during authorized startup, not a kernel-version inference; unavailable protection warns and continues with tmpfs, never a disk directory")
	r.add("frontend_heap", Warning, "The frontend's anonymous heap and caller-side buffers are outside the service cgroup and are not protected by MemorySwapMax=0 or tmpfs noswap; they may be swapped or captured")
	if data, err := readFile("/proc/sys/kernel/core_pattern", 4<<10); err != nil {
		r.add("memory_dumps", Warning, "Host core-dump policy could not be read; LimitCORE=0 is only mitigation, not proof that memory cannot be persisted")
	} else if strings.HasPrefix(strings.TrimSpace(string(data)), "|") {
		r.add("memory_dumps", Warning, "core_pattern reports a piped host core collector; its policy and retained metadata are unknown. LimitCORE=0 alone does not prevent piped collection; host policy is unchanged")
	} else {
		r.add("memory_dumps", Warning, "Host dump policy and retained metadata remain unknown; per-service LimitCORE=0 is mitigation only, not proof against memory capture")
	}
	r.add("hibernation_snapshots", Warning, "Hibernation, host/hypervisor snapshot policy and physical RAM retention are unknown and outside the guarantee; host terminal/history/audit logs and intentional stdout/exports may persist")
}

func readLimited(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("diagnostic read limit must be positive")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(errors.New("diagnostic input is not a readable regular file"), err)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(errors.New("diagnostic input is not a readable regular file"), err, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("diagnostic input exceeds its read limit")
	}
	return data, nil
}

func osRelease(data []byte) (string, string, error) {
	values := make(map[string]string, 2)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key != "ID" && key != "VERSION_ID" {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return "", "", errors.New("duplicate distribution identifier")
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if len(value) == 0 || len(value) > 64 {
			return "", "", errors.New("invalid distribution identifier")
		}
		for _, c := range value {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return "", "", errors.New("invalid distribution identifier")
			}
		}
		values[key] = value
	}
	if values["ID"] == "" || values["VERSION_ID"] == "" {
		return "", "", errors.New("ID and VERSION_ID are required in os-release")
	}
	return values["ID"], values["VERSION_ID"], nil
}

func hasField(data []byte, want string) bool {
	for _, field := range strings.Fields(string(data)) {
		if field == want {
			return true
		}
	}
	return false
}

func rootOwned(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && st.Gid == 0
}

func trustedDirectory(lstat func(string) (fs.FileInfo, error), name string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || strings.ContainsRune(name, 0) {
		return errors.New("must be a fixed clean absolute path")
	}
	for current := name; ; current = filepath.Dir(current) {
		info, err := lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || !rootOwned(info) || info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errors.New("every ancestor must be a real root:root-owned directory without group/other writes or special mode bits")
		}
		if current == "/" {
			return nil
		}
	}
}

func executablePath(p probes, name string, allowSetuid bool) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || strings.ContainsRune(name, 0) {
		return errors.New("must be a fixed clean absolute path")
	}
	if err := trustedDirectory(p.lstat, filepath.Dir(name)); err != nil {
		return err
	}
	info, err := p.lstat(name)
	if err != nil {
		return err
	}
	if !rootOwned(info) || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 || info.Mode()&(os.ModeSetgid|os.ModeSticky) != 0 || !allowSetuid && info.Mode()&os.ModeSetuid != 0 {
		return errors.New("must be a root:root-owned regular executable without group/other writes, unexpected privileged mode bits, or symlinks")
	}
	if _, err := p.xattr(name, "security.capability", nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.EOPNOTSUPP) {
		return errors.New("file capabilities are present or could not be ruled out")
	}
	return nil
}

func profilePermissions(lstat func(string) (fs.FileInfo, error), name string) error {
	if err := config.ValidateProfileID(name); err != nil {
		return err
	}
	if err := trustedDirectory(lstat, network.ProfileDirectory); err != nil {
		return err
	}
	for _, suffix := range []string{".json", ".key"} {
		info, err := lstat(network.ProfileDirectory + "/" + name + suffix)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !rootOwned(info) || !info.Mode().IsRegular() || st.Nlink != 1 {
			return errors.New("profile files must be real root:root-owned regular files with exactly one link")
		}
		mode := info.Mode()
		if mode != 0o600 && (suffix == ".key" || mode != 0o644) {
			return errors.New("profile credential must be 0600; public metadata must be 0600 or 0644")
		}
		if suffix == ".key" && info.Size() != 44 && info.Size() != 45 || suffix == ".json" && (info.Size() <= 0 || info.Size() > 16<<10) {
			return errors.New("profile metadata or credential size is outside the fixed format bounds")
		}
	}
	return nil
}

func filesystemAvailable(data []byte, name string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 1 && fields[0] == name || len(fields) == 2 && fields[0] == "nodev" && fields[1] == name {
			return true
		}
	}
	return false
}

func validCgroupLimit(value string) bool {
	if value == "max" {
		return true
	}
	if value == "" {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func availableMemory(data []byte) (uint64, error) {
	var value uint64
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "MemAvailable:" {
			continue
		}
		if found || len(fields) != 3 || fields[2] != "kB" || !validCgroupLimit(fields[1]) || fields[1] == "max" {
			return 0, errors.New("invalid MemAvailable field")
		}
		found = true
		value, _ = strconv.ParseUint(fields[1], 10, 64)
		if value > ^uint64(0)/1024 {
			return 0, errors.New("MemAvailable bytes overflow")
		}
	}
	if !found {
		return 0, errors.New("MemAvailable is missing")
	}
	return value * 1024, nil
}

func noActiveSwap(data []byte) bool {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		return false
	}
	fields := strings.Fields(lines[0])
	return len(fields) == 5 && fields[0] == "Filename" && fields[1] == "Type" && fields[2] == "Size" && fields[3] == "Used" && fields[4] == "Priority"
}
