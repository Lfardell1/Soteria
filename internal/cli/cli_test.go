package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Lfardell1/Soteria/internal/buildinfo"
	"github.com/Lfardell1/Soteria/internal/client"
	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/doctor"
)

func TestRunOptionsPreserveDirectArgv(t *testing.T) {
	argv := []string{"printf", "%s", "argument with spaces", "$(not-executed)", ";", "", "--config", "relative"}
	args := append([]string{"--import", "missing-input", "--import=another", "--export", "missing-output", "--"}, argv...)
	options, err := parseRun(args, false)
	if err != nil || !reflect.DeepEqual(options.argv, argv) {
		t.Fatalf("argv changed: %#v err=%v", options.argv, err)
	}
	if !reflect.DeepEqual([]string(options.imports), []string{"missing-input", "another"}) || options.export != "missing-output" {
		t.Fatalf("transfer options=%#v", options)
	}
	if options.configExplicit || options.netExplicit || options.profileSet {
		t.Fatal("command arguments were parsed as frontend flags")
	}
}

func TestRunOptionFailuresAndShellPolicy(t *testing.T) {
	for _, args := range [][]string{
		{}, {"command"}, {"--"}, {"--", ""}, {"--unknown", "--", "tool"},
		{"--import=", "--", "tool"}, {"--export=", "--", "tool"},
		{"--", "tool", "nul\x00arg"}, {"--", "tool", "\xff"},
		{"--", "tool", strings.Repeat("x", 32<<10)},
	} {
		if _, err := parseRun(args, false); err == nil {
			t.Errorf("accepted invalid options: %#v", args)
		}
	}
	if _, err := parseRun([]string{"--help"}, false); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help=%v", err)
	}
	options, err := parseRun(nil, true)
	if err != nil || !reflect.DeepEqual(options.argv, []string{"/bin/bash", "--noprofile", "--norc", "-i"}) {
		t.Fatalf("shell argv=%#v err=%v", options.argv, err)
	}
	if _, err := parseRun([]string{"unexpected"}, true); err == nil {
		t.Fatal("shell accepted user command argv")
	}
}

func TestWireGuardRequiresBothExplicitFlagsRegardlessOfConfig(t *testing.T) {
	configured := config.Default()
	configured.Network = config.NetworkConfig{Mode: "wireguard", Profile: "configured-provider"}
	for _, tc := range []struct {
		args    []string
		mode    string
		profile string
		valid   bool
	}{
		{nil, "offline", "", true},
		{[]string{"--network=offline"}, "offline", "", true},
		{[]string{"--network=wireguard"}, "", "", false},
		{[]string{"--profile=chosen"}, "", "", false},
		{[]string{"--network=offline", "--profile="}, "", "", false},
		{[]string{"--network=wireguard", "--profile="}, "", "", false},
		{[]string{"--network=wireguard", "--profile=chosen"}, "wireguard", "chosen", true},
		{[]string{"--network=wireguard", "--profile=../bad"}, "", "", false},
		{[]string{"--network=unknown"}, "", "", false},
	} {
		args := append(append([]string(nil), tc.args...), "--", "tool")
		options, err := parseRun(args, false)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := applyNetwork(configured, options)
		if (err == nil) != tc.valid || tc.valid && (actual.Network.Mode != tc.mode || actual.Network.Profile != tc.profile) {
			t.Errorf("args=%#v network=%#v err=%v", tc.args, actual.Network, err)
		}
	}
	if configured.Network.Mode != "wireguard" || configured.Network.Profile != "configured-provider" {
		t.Fatal("applying network policy mutated the selected config")
	}
}

func writeConfig(t *testing.T, name string, cfg config.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSelectionUsesOnlyExplicitOrFixedDefaultPath(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	// A malicious working-directory config must not be discovered.
	if err := os.WriteFile("config.json", []byte(`{"version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fixed := filepath.Join(directory, "installed.json")
	selected, err := selectConfig("", false, fixed)
	if err != nil || !reflect.DeepEqual(selected.cfg, config.Default()) || !strings.Contains(selected.source, "builtin") {
		t.Fatalf("built-in selection=%#v err=%v", selected, err)
	}
	cfg := config.Default()
	cfg.Resources.TasksMax = 128
	writeConfig(t, fixed, cfg)
	selected, err = selectConfig("", false, fixed)
	if err != nil || selected.cfg.Resources.TasksMax != 128 || selected.source != `"`+fixed+`"` {
		t.Fatalf("fixed selection=%#v err=%v", selected, err)
	}
	for _, path := range []string{"", "config.json", "../config.json", directory + "/../not-clean"} {
		if _, err := selectConfig(path, true, fixed); err == nil {
			t.Errorf("accepted nonabsolute/unclean explicit config %q", path)
		}
	}
	if _, err := selectConfig(directory, true, fixed); err == nil {
		t.Fatal("accepted a directory config")
	}
	broken := filepath.Join(directory, "broken.json")
	if err := os.Symlink(filepath.Join(directory, "missing.json"), broken); err != nil {
		t.Fatal(err)
	}
	if _, err := selectConfig("", false, broken); err == nil {
		t.Fatal("broken installed config silently fell back to built-in settings")
	}
}

func TestEffectiveSettingsAreCanonicalAndRedacted(t *testing.T) {
	cfg := config.Default()
	cfg.Network = config.NetworkConfig{Mode: "wireguard", Profile: "sensitive-provider-name"}
	cfg.Resources.MemoryMax = "1073741824"
	var output bytes.Buffer
	if err := showConfig(&output, selection{cfg: cfg, source: "chosen\x1b[31m\nfile"}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Contains(text, cfg.Network.Profile) || strings.ContainsRune(text, '\x1b') || !strings.Contains(text, `"memory_max":"1G"`) || !strings.Contains(text, "redacted") {
		t.Fatalf("unsafe report: %q", text)
	}
	if cfg.Resources.MemoryMax != "1073741824" || cfg.Network.Profile != "sensitive-provider-name" {
		t.Fatal("presentation changed effective config")
	}
}

type cliFixture struct {
	t       *testing.T
	dir     string
	streams client.Streams
}

func newCLIFixture(t *testing.T) *cliFixture {
	t.Helper()
	f := &cliFixture{t: t, dir: t.TempDir()}
	open := func(name string) *os.File {
		file, err := os.Create(filepath.Join(f.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return file
	}
	f.streams = client.Streams{In: open("stdin"), Out: open("stdout"), Err: open("stderr")}
	return f
}

func (f *cliFixture) read(name string) string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

func TestRunReportsSelectedEffectiveConfigOnlyOnStderr(t *testing.T) {
	f := newCLIFixture(t)
	path := filepath.Join(f.dir, "selected.json")
	cfg := config.Default()
	cfg.Network = config.NetworkConfig{Mode: "wireguard", Profile: "must-not-enable"}
	writeConfig(t, path, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Never reach sudo, including when ordinary tests run as non-root.
	code := Run(ctx, []string{"run", "--config", path, "--", "tool"}, f.streams)
	if code != client.InfrastructureExit || f.read("stdout") != "" {
		t.Fatalf("code=%d stdout=%q", code, f.read("stdout"))
	}
	stderr := f.read("stderr")
	if !strings.Contains(stderr, path) || !strings.Contains(stderr, `"mode":"offline"`) || !strings.Contains(stderr, "using offline") || strings.Contains(stderr, "must-not-enable") {
		t.Fatalf("effective settings report=%q", stderr)
	}
}

func TestReadOnlyCommandsAndDoctorJSON(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"help"}, {"run", "--help"}, {"shell", "--help"}, {"doctor", "--help"}, {"cleanup", "--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			f := newCLIFixture(t)
			if code := Run(context.Background(), args, f.streams); code != 0 || f.read("stdout") == "" || f.read("stderr") != "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, f.read("stdout"), f.read("stderr"))
			}
		})
	}
	t.Run("config check", func(t *testing.T) {
		f := newCLIFixture(t)
		path := filepath.Join(f.dir, "valid.json")
		writeConfig(t, path, config.Default())
		if code := Run(context.Background(), []string{"config", "check", "--config", path}, f.streams); code != 0 || !strings.Contains(f.read("stdout"), "Configuration is valid") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, f.read("stdout"), f.read("stderr"))
		}
	})
	t.Run("doctor JSON", func(t *testing.T) {
		f := newCLIFixture(t)
		path := filepath.Join(f.dir, "valid.json")
		writeConfig(t, path, config.Default())
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Deterministic read-only report without depending on this host.
		code := Run(ctx, []string{"doctor", "--json", "--config", path}, f.streams)
		var report doctor.Report
		if code != 1 || json.Unmarshal([]byte(f.read("stdout")), &report) != nil || len(report.Checks) == 0 || report.OK() {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, f.read("stdout"), f.read("stderr"))
		}
	})
}

func TestVersionIncludesProvenance(t *testing.T) {
	f := newCLIFixture(t)
	if code := Run(context.Background(), []string{"version"}, f.streams); code != 0 {
		t.Fatal(code)
	}
	for _, value := range []string{buildinfo.Version, "commit: " + buildinfo.Commit, "runtime digest: " + buildinfo.RuntimeDigest} {
		if !strings.Contains(f.read("stdout"), value) {
			t.Errorf("missing version metadata %q", value)
		}
	}
}

func TestInvalidCommandsCannotRequestPrivilege(t *testing.T) {
	for _, args := range [][]string{
		{}, {"unknown"}, {"--internal-supervisor"}, {"version", "extra"}, {"doctor", "extra"},
		{"run", "tool"}, {"run", "--", ""}, {"shell", "extra"}, {"config"}, {"config", "other"},
		{"cleanup"}, {"cleanup", strings.Repeat("A", 32)}, {"cleanup", strings.Repeat("a", 32), "extra"},
		{"help", "private"}, {"version", "--config", "/tmp/anything"},
	} {
		f := newCLIFixture(t)
		if code := Run(context.Background(), args, f.streams); code != 2 || f.read("stdout") != "" {
			t.Errorf("args=%#v code=%d stdout=%q stderr=%q", args, code, f.read("stdout"), f.read("stderr"))
		}
	}
}

func TestSessionIDsAndDiagnosticBounds(t *testing.T) {
	for _, id := range []string{"", "../anything", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("G", 32), strings.Repeat("a", 31) + "\n"} {
		if validSessionID(id) {
			t.Errorf("accepted invalid session ID %q", id)
		}
	}
	if !validSessionID("0123456789abcdef0123456789abcdef") {
		t.Fatal("valid session ID rejected")
	}
	text := clean("\x1b[31m\r\n\u202e"+strings.Repeat("x", 2048), 128)
	if len(text) > 128 || strings.ContainsAny(text, "\x1b\r\n\u202e") {
		t.Fatalf("unbounded/unsafe diagnostic: %q", text)
	}
}

func TestStrictLoaderAndOutputFailures(t *testing.T) {
	f := newCLIFixture(t)
	path := filepath.Join(f.dir, "unknown.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"disable_isolation":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := Run(context.Background(), []string{"config", "check", "--config", path}, f.streams); code != 1 || !strings.Contains(f.read("stderr"), "unknown config field") {
		t.Fatalf("strict loader bypassed: code=%d stderr=%q", code, f.read("stderr"))
	}
	for _, args := range [][]string{{"version"}, {"help"}, {"config", "check", "--config", path}} {
		f := newCLIFixture(t)
		writeConfig(t, path, config.Default())
		_ = f.streams.Out.Close()
		if code := Run(context.Background(), args, f.streams); code != client.InfrastructureExit {
			t.Errorf("lost output error for %#v: code=%d", args, code)
		}
	}
}
