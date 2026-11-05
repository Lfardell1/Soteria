package doctor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lfardell1/Soteria/internal/config"
)

func TestSupportScope(t *testing.T) {
	for _, test := range []struct{ os, arch, want string }{
		{"linux", "amd64", ""},
		{"linux", "arm64", "separately validated"},
		{"darwin", "arm64", "disposable Linux VM"},
		{"windows", "amd64", "not implemented"},
		{"freebsd", "amd64", "unsupported platform"},
	} {
		t.Run(test.os+"/"+test.arch, func(t *testing.T) {
			err := SupportError(test.os, test.arch)
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsupported platform error: %v", err)
			}
		})
	}
}

func TestReportOK(t *testing.T) {
	for _, test := range []struct {
		name     string
		statuses []string
		ok       bool
	}{
		{"no fatal checks", nil, true},
		{"facts and risks", []string{Verified, Warning}, true},
		{"missing prerequisite", []string{Warning, Required, Verified}, false},
		{"unsupported prerequisite", []string{Unsupported, Warning}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := Report{}
			for _, status := range test.statuses {
				r.add("fact", status, "Individual fact, not a safety verdict")
			}
			if r.OK() != test.ok {
				t.Fatalf("OK() = %v, want %v", r.OK(), test.ok)
			}
		})
	}
}

func TestReportJSON(t *testing.T) {
	r := Report{Checks: []CheckResult{{Name: "memory", Status: Warning, Detail: "Swap/dump risk"}}}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"checks":[{"name":"memory","status":"warning","detail":"Swap/dump risk"}]}`
	if string(data) != want {
		t.Fatalf("report JSON = %s, want %s", data, want)
	}
	var got Report
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&got); err != nil || !got.OK() || len(got.Checks) != 1 || got.Checks[0] != r.Checks[0] {
		t.Fatalf("report round trip: %+v, %v", got, err)
	}
	for _, word := range []string{`"secure"`, `"anonymous"`, `"ok"`, `"required_failures"`} {
		if strings.Contains(string(data), word) {
			t.Fatalf("diagnostics contain aggregate verdict or obsolete field %s", word)
		}
	}
}

func TestInvalidConfigStopsBeforeHostReads(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*config.Config)
	}{
		{"version", func(c *config.Config) { c.Version = 0 }},
		{"zero memory", func(c *config.Config) { c.Resources.MemoryMax = "0" }},
		{"overflow memory", func(c *config.Config) { c.Resources.MemoryMax = "18446744073709551615G" }},
		{"workspace equal memory", func(c *config.Config) { c.Resources.WorkspaceSize = "1G" }},
		{"workspace above memory", func(c *config.Config) { c.Resources.WorkspaceSize = "2G" }},
		{"missing tasks", func(c *config.Config) { c.Resources.TasksMax = 0 }},
		{"network selection", func(c *config.Config) { c.Network.Mode = "legacy" }},
		{"profile traversal", func(c *config.Config) {
			c.Network = config.NetworkConfig{Mode: "wireguard", Profile: "../private-key-must-not-appear"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.Default()
			test.edit(&cfg)
			r := Check(context.Background(), cfg)
			if r.OK() || r.Config != nil || len(r.Checks) != 1 || r.Checks[0].Name != "configuration" || r.Checks[0].Status != Required {
				t.Fatalf("invalid configuration report: %+v", r)
			}
			data, err := json.Marshal(r)
			if err != nil || strings.Contains(string(data), "private-key-must-not-appear") {
				t.Fatalf("invalid raw config reflected in diagnostics: %s, %v", data, err)
			}
		})
	}
}

func TestConfigReportIsNormalizedCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := config.Default()
	cfg.Resources.MemoryMax = " 1024m "
	cfg.Resources.WorkspaceSize = "536870912B"
	cfg.Transfers.MaxBytes = " 262144k "
	r := Check(ctx, cfg)
	if r.Config == nil || r.Config.Resources.MemoryMax != "1G" || r.Config.Resources.WorkspaceSize != "512M" || r.Config.Transfers.MaxBytes != "256M" {
		t.Fatalf("effective public settings were not normalized: %+v", r.Config)
	}
	if cfg.Resources.MemoryMax != " 1024m " || r.OK() {
		t.Fatal("caller config was changed or canceled/unsupported report succeeded")
	}
}

func TestDetailsAreBoundedAndTerminalSafe(t *testing.T) {
	r := Report{}
	r.add("bounded", Warning, strings.Repeat("x\x1b\n\u202e", 4000))
	detail := r.Checks[0].Detail
	if len(detail) > 768 || strings.ContainsAny(detail, "\x1b\n\u202e") || !strings.HasSuffix(detail, "...") {
		t.Fatalf("unbounded or terminal-unsafe detail: %q", detail)
	}
}
