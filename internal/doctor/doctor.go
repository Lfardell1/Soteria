// Package doctor reports read-only host prerequisites, not a runtime isolation verdict.
package doctor

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"unicode"

	"github.com/Lfardell1/Soteria/internal/config"
)

const (
	Verified    = "verified"
	Warning     = "warning"
	Required    = "required"
	Unsupported = "unsupported"
)

// CheckResult is named separately from the Check function because Go shares the
// namespace for package-level functions and types.
type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Report struct {
	Checks []CheckResult  `json:"checks"`
	Config *config.Config `json:"config,omitempty"`
}

// OK means no required prerequisite is missing or unsupported. Memory-retention
// warnings and behavior requiring authorized startup are not a safety score.
func (r Report) OK() bool {
	for _, check := range r.Checks {
		if check.Status == Required || check.Status == Unsupported {
			return false
		}
	}
	return true
}

// Check neither executes programs nor requests privilege, mounts, networking,
// service activation, or changes to host policy. It never loads credentials.
func Check(ctx context.Context, cfg config.Config) Report {
	r := Report{Checks: []CheckResult{}}
	if err := cfg.Validate(); err != nil {
		r.add("configuration", Required, "Invalid configured bounds or network selection: "+err.Error())
		return r
	}
	// Include only validated, bounded public settings, never raw invalid input.
	for _, size := range []*string{&cfg.Resources.MemoryMax, &cfg.Resources.WorkspaceSize, &cfg.Transfers.MaxBytes} {
		value, _ := config.ParseSize(*size)
		*size = config.FormatSize(value)
	}
	r.Config = &cfg
	r.add("configuration", Verified, fmt.Sprintf("Valid version-1 settings: service memory maximum %s, workspace bound %s, task maximum %d; bounds are not reservations", cfg.Resources.MemoryMax, cfg.Resources.WorkspaceSize, cfg.Resources.TasksMax))
	if err := SupportError(runtime.GOOS, runtime.GOARCH); err != nil {
		r.add("platform", Unsupported, err.Error())
		return r
	}
	r.add("platform", Verified, "Linux amd64 backend; this is not proof of workload isolation or release validation")
	if canceled(ctx, &r) {
		return r
	}
	probeHost(ctx, cfg, &r)
	return r
}

// SupportError describes the implemented backend, including staged VM support.
// Configuration inspection and version/help remain available on unsupported hosts.
func SupportError(goos, goarch string) error {
	if goos == "linux" && goarch == "amd64" {
		return nil
	}
	staged := "additional architectures require separately validated runtime artifacts and engine support"
	switch goos {
	case "darwin":
		staged = "macOS support is staged through a dedicated disposable Linux VM backend, which is not implemented; native macOS isolation is not supported"
	case "windows":
		staged = "Windows support is staged after the macOS VM backend and is not implemented; native Windows or shared default WSL isolation is not supported"
	}
	return fmt.Errorf("unsupported platform %s/%s: Soteria requires Linux amd64 on Debian 13 or Ubuntu 24.04 with systemd and cgroup v2; %s", goos, goarch, staged)
}

func (r *Report) add(name, status, detail string) {
	r.Checks = append(r.Checks, CheckResult{Name: name, Status: status, Detail: bounded(detail, 768)})
}

func canceled(ctx context.Context, r *Report) bool {
	if ctx.Err() != nil {
		r.add("diagnostics", Required, "Diagnostics canceled; remaining prerequisites were not checked")
		return true
	}
	return false
}

func bounded(value string, limit int) string {
	var out strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = ' '
		}
		if out.Len()+len(string(r)) > limit-3 {
			out.WriteString("...")
			break
		}
		out.WriteRune(r)
	}
	return out.String()
}
