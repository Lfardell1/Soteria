//go:build linux && amd64

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/transfer"
	"golang.org/x/sys/unix"
)

type diagnosticBuffer struct{ data []byte }

func (buffer *diagnosticBuffer) Write(data []byte) (int, error) {
	n := min(len(data), 4096-len(buffer.data))
	buffer.data = append(buffer.data, data[:n]...)
	return len(data), nil
}

func runTransferHelper(ctx context.Context, operation string, plan namespacePlan, directory, input, output *os.File) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if operation != "receive" && operation != "send" {
		return errors.New("invalid transfer helper operation")
	}
	bytes, _ := config.ParseSize(plan.Request.Config.Transfers.MaxBytes)
	command := exec.CommandContext(ctx, installedExecutable, "__transfer", operation, strconv.FormatUint(bytes, 10), strconv.FormatUint(plan.Request.Config.Transfers.MaxFiles, 10))
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=/nonexistent"}
	command.ExtraFiles = []*os.File{directory}
	command.Stdin, command.Stdout = input, output
	if input == nil {
		command.Stdin = nil
	}
	if output == nil {
		command.Stdout = io.Discard
	}
	buffer := new(diagnosticBuffer)
	command.Stderr = buffer
	// The credential drop occurs in fork/exec before any filename in the stream
	// is decoded. No root archive extraction/chown pass exists.
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: plan.Caller.UID, Gid: plan.Caller.GID, Groups: []uint32{}}}
	command.WaitDelay = controlTimeout
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if len(buffer.data) != 0 {
			return fmt.Errorf("non-root transfer helper: %w: %s", err, boundedDiagnostic(errors.New(string(buffer.data))))
		}
		return fmt.Errorf("non-root transfer helper: %w", err)
	}
	return nil
}

func transferHelper(ctx context.Context, args []string) (int, error) {
	if len(args) != 3 || args[0] != "receive" && args[0] != "send" {
		return InfrastructureFailure, errors.New("transfer helper requires a fixed operation and numeric limits")
	}
	if os.Getuid() == 0 || os.Getgid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return InfrastructureFailure, errors.New("transfer streams must never be processed with root credentials")
	}
	groups, err := unix.Getgroups()
	if err != nil || len(groups) != 0 {
		return InfrastructureFailure, errors.New("transfer helper must have cleared supplementary groups")
	}
	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || noNewPrivileges != 1 {
		return InfrastructureFailure, errors.New("transfer helper requires inherited no_new_privs")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return InfrastructureFailure, err
	}
	for _, field := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"} {
		if !zeroStatusCapability(string(status), field) {
			return InfrastructureFailure, errors.New("transfer helper retained capabilities")
		}
	}
	maxBytes, byteErr := strconv.ParseUint(args[1], 10, 64)
	maxFiles, fileErr := strconv.ParseUint(args[2], 10, 64)
	if byteErr != nil || fileErr != nil || maxBytes == 0 || maxBytes > 32<<30 || maxFiles == 0 || maxFiles > 100000 {
		return InfrastructureFailure, errors.New("invalid bounded transfer limits")
	}
	directory := os.NewFile(3, "explicit workspace transfer directory")
	defer directory.Close()
	unix.CloseOnExec(3)
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(3, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Getuid()) || st.Gid != uint32(os.Getgid()) || st.Mode&0o7777 != 0o700 {
		return InfrastructureFailure, errors.New("transfer helper requires its explicit caller-owned workspace directory FD")
	}
	if err := unix.Fstatfs(3, &fs); err != nil || fs.Type != unix.TMPFS_MAGIC {
		return InfrastructureFailure, errors.New("transfer workspace directory is not tmpfs; no disk fallback")
	}
	unix.Umask(0o077)
	limits := transfer.Limits{MaxBytes: maxBytes, MaxFiles: maxFiles}
	const root = "/proc/self/fd/3"
	if args[0] == "receive" {
		err = transfer.Receive(ctx, os.Stdin, root, limits)
	} else {
		var sources []transfer.Source
		sources, err = transfer.Outputs(root)
		if err == nil {
			err = transfer.Send(ctx, os.Stdout, sources, limits)
		}
	}
	if err != nil {
		return InfrastructureFailure, err
	}
	return 0, nil
}

func zeroStatusCapability(status, field string) bool {
	for _, line := range strings.Split(status, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == field {
			value, err := strconv.ParseUint(parts[1], 16, 64)
			return err == nil && value == 0
		}
	}
	return false
}
