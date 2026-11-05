//go:build linux && amd64

package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Lfardell1/Soteria/internal/entrypoint"
	"github.com/Lfardell1/Soteria/internal/filesystem"
	"github.com/Lfardell1/Soteria/internal/toolkit"
)

func resolveRuntimeCommand(name string) (string, error) {
	if err := validateExecutable(name); err != nil {
		return "", err
	}
	candidates := []string{name}
	if !strings.Contains(name, "/") {
		candidates = []string{"/usr/bin/" + name, "/bin/" + name}
	}
	for _, candidate := range candidates {
		info, err := os.Stat(filepath.Join(toolkit.Root, strings.TrimPrefix(candidate, "/")))
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", errors.New("requested executable is unavailable in the verified curated runtime")
}

func bubblewrapArguments(workspace *filesystem.Workspace, caller identity, request wireRequest, executable string) ([]string, error) {
	if caller.UID == 0 || caller.GID == 0 || caller.UID == ^uint32(0) || caller.GID == ^uint32(0) {
		return nil, errors.New("workload credentials must be the authenticated non-root caller")
	}
	if workspace == nil || workspace.Root == "" || len(request.Command) == 0 {
		return nil, errors.New("missing owned workspace or command")
	}
	if err := validateExecutable(executable); err != nil {
		return nil, err
	}
	args := []string{
		"--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
		"--hostname", "workspace", "--new-session", "--die-with-parent",
		"--preserve-fds", "1",
		"--json-status-fd", "4",
		"--ro-bind", toolkit.Root, "/",
		"--bind", workspace.Home, "/home/workspace",
		"--bind", workspace.Work, "/work",
		"--bind", workspace.Temp, "/tmp",
		"--bind", workspace.Run, "/run",
		"--bind", workspace.Var, "/var",
		"--proc", "/proc", "--dev", "/dev",
	}
	for _, name := range []string{"passwd", "group", "nsswitch.conf", "hosts", "resolv.conf"} {
		args = append(args, "--ro-bind", filepath.Join(workspace.Etc, name), "/etc/"+name)
	}
	args = append(args,
		"--chdir", "/work", "--clearenv",
		"--cap-drop", "ALL",
		"--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_SETPCAP",
	)
	for _, value := range entrypoint.Environment(request.Interactive) {
		name, contents, _ := strings.Cut(value, "=")
		args = append(args, "--setenv", name, contents)
	}
	// PID 2 is not a process-group leader. setsid execs in place without a
	// privileged waiter, preserving exact exit and signal status.
	args = append(args, "--", "/usr/bin/setsid")
	if request.Interactive {
		args = append(args, "--ctty")
	}
	// These are host credential transitions, not user-namespace UID mappings.
	// Only these three capabilities survive rootful bwrap setup; setpriv clears
	// the bounding/inheritable/ambient sets and all three UID/GID identities.
	args = append(args,
		"/usr/bin/setpriv",
		"--reuid="+strconv.FormatUint(uint64(caller.UID), 10),
		"--regid="+strconv.FormatUint(uint64(caller.GID), 10),
		"--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
		"--", entrypoint.Path,
		strconv.FormatUint(uint64(caller.UID), 10), strconv.FormatUint(uint64(caller.GID), 10),
		"--", executable,
	)
	args = append(args, request.Command[1:]...)
	return args, nil
}

func requirePrivateNamespaces() error {
	for _, kind := range []string{"net", "mnt"} {
		current, err := os.Stat("/proc/self/ns/" + kind)
		if err != nil {
			return err
		}
		host, err := os.Stat("/proc/1/ns/" + kind)
		if err != nil {
			return err
		}
		if os.SameFile(current, host) {
			return fmt.Errorf("refusing setup without a fresh private %s namespace", kind)
		}
	}
	return nil
}
