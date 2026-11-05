package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestDefault(t *testing.T) {
	want := Config{
		Version:   1,
		Resources: ResourceConfig{MemoryMax: "1G", WorkspaceSize: "512M", TasksMax: 256},
		Network:   NetworkConfig{Mode: "offline"},
		Transfers: TransferConfig{MaxBytes: "256M", MaxFiles: 10000},
	}
	got := Default()
	if got != want {
		t.Fatalf("Default() = %+v, want %+v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Default().Validate(): %v", err)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"profile"`) {
		t.Fatalf("empty profile must be omitted: %s", data)
	}
	parsed, err := Parse(bytes.NewReader(data))
	if err != nil || parsed != want {
		t.Fatalf("default JSON round trip = %+v, %v", parsed, err)
	}
	got.Resources.MemoryMax = "2G"
	if Default() != want {
		t.Fatal("modifying a default config changed later defaults")
	}
}

func TestExampleMatchesDefault(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "config", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != Default() {
		t.Fatalf("example = %+v, want %+v", got, Default())
	}
}

func TestParseDefaultsAndOverrides(t *testing.T) {
	tests := []struct {
		name  string
		input string
		edit  func(*Config)
	}{
		{"version only", `{"version":1}`, nil},
		{"escaped version key", `{"\u0076ersion":1}`, nil},
		{"empty sections", `{"version":1,"resources":{},"network":{},"transfers":{}}`, nil},
		{"empty offline profile", `{"version":1,"network":{"profile":""}}`, nil},
		{"whitespace and order", " \n{\"transfers\":{},\"version\":1}\r\n\t", nil},
		{"tasks override", `{"version":1,"resources":{"tasks_max":512}}`, func(c *Config) { c.Resources.TasksMax = 512 }},
		{"file count override", `{"version":1,"transfers":{"max_files":1}}`, func(c *Config) { c.Transfers.MaxFiles = 1 }},
		{"byte units", `{"version":1,"resources":{"memory_max":"1073741824B"}}`, func(c *Config) { c.Resources.MemoryMax = "1073741824B" }},
		{"lowercase size", `{"version":1,"resources":{"memory_max":" 1g "}}`, func(c *Config) { c.Resources.MemoryMax = " 1g " }},
		{"wireguard", `{"version":1,"network":{"profile":"eu_1-west","mode":"wireguard"}}`, func(c *Config) { c.Network = NetworkConfig{Mode: "wireguard", Profile: "eu_1-west"} }},
		{"maximum profile length", `{"version":1,"network":{"mode":"wireguard","profile":"` + strings.Repeat("a", 48) + `"}}`, func(c *Config) { c.Network = NetworkConfig{Mode: "wireguard", Profile: strings.Repeat("a", 48)} }},
		{"minimum limits", `{"version":1,"resources":{"memory_max":"128M","workspace_size":"16M","tasks_max":32},"transfers":{"max_bytes":"1B","max_files":1}}`, func(c *Config) {
			c.Resources = ResourceConfig{MemoryMax: "128M", WorkspaceSize: "16M", TasksMax: 32}
			c.Transfers = TransferConfig{MaxBytes: "1B", MaxFiles: 1}
		}},
		{"maximum limits", `{"version":1,"resources":{"memory_max":"64G","workspace_size":"32G","tasks_max":4096},"transfers":{"max_bytes":"32G","max_files":100000}}`, func(c *Config) {
			c.Resources = ResourceConfig{MemoryMax: "64G", WorkspaceSize: "32G", TasksMax: 4096}
			c.Transfers = TransferConfig{MaxBytes: "32G", MaxFiles: 100000}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := Default()
			if tt.edit != nil {
				tt.edit(&want)
			}
			got, err := Parse(iotest.OneByteReader(strings.NewReader(tt.input)))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("Parse() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestParseRejectsLegacy(t *testing.T) {
	for _, input := range []string{`{}`, `{"resources":{}}`, `{"network":{"mode":"offline"}}`} {
		requireParseError(t, input, "migrate")
	}
	for _, field := range []string{"filesystem", "monitoring", "vpn", "tor", "dnscrypt", "proxychains"} {
		t.Run(field, func(t *testing.T) {
			for _, prefix := range []string{"", `"version":1,`} {
				requireParseError(t, `{`+prefix+`"`+field+`":{}}`, "migrate")
			}
		})
	}
	for _, field := range []string{"check_connectivity", "gateway", "kill_switch"} {
		t.Run("network."+field, func(t *testing.T) {
			for _, prefix := range []string{"", `"version":1,`} {
				requireParseError(t, `{`+prefix+`"network":{"`+field+`":true}}`, "migrate")
			}
		})
	}
	requireParseError(t, `{"version":1,"resources":{"memory_max":"2G"},"vpn":{"enabled":true,"config_file":"/etc/openvpn/client.conf"}}`, "migrate")
	requireParseError(t, `{"version":1,"vpn":{"enabled":false},"tor":{"enabled":false},"network":{"kill_switch":false}}`, "migrate")
	requireParseError(t, `{"version":1,"network":{"mode":"offline","kill_switch":false}}`, "migrate")
	requireParseError(t, `{"version":1,"network":{"mode":"wireguard","profile":"office","kill_switch":false}}`, "migrate")
}

func TestParseRejectsInvalidJSONAndUnknownFields(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", "parse config"},
		{"whitespace", " \n\t", "parse config"},
		{"null root", `null`, "object"},
		{"array root", `[]`, "object"},
		{"string root", `"config"`, "object"},
		{"number root", `1`, "object"},
		{"boolean root", `true`, "object"},
		{"unterminated object", `{"version":1`, "parse config"},
		{"unterminated nested", `{"version":1,"resources":{`, "parse config"},
		{"missing comma", `{"version":1 "network":{}}`, "parse config"},
		{"trailing comma", `{"version":1,}`, "parse config"},
		{"comment", `{"version":1/*comment*/}`, "parse config"},
		{"second object", `{"version":1}{}`, "trailing"},
		{"second scalar", `{"version":1} true`, "trailing"},
		{"trailing null", `{"version":1} null`, "trailing"},
		{"trailing garbage", `{"version":1}x`, "trailing"},
		{"invalid utf8", "{\"version\":1,\"network\":{\"profile\":\"\xff\"}}", "UTF-8"},
		{"version case", `{"Version":1}`, "unknown"},
		{"shadow version case", `{"version":1,"VERSION":1}`, "unknown"},
		{"root typo", `{"version":1,"resouces":{}}`, "unknown"},
		{"nested resources", `{"version":1,"resources":{"memory_mx":"2G"}}`, "unknown"},
		{"nested network", `{"version":1,"network":{"mod":"offline"}}`, "unknown"},
		{"nested transfers", `{"version":1,"transfers":{"max_file":1}}`, "unknown"},
		{"nested case", `{"version":1,"resources":{"Memory_Max":"2G"}}`, "unknown"},
		{"runtime directory", `{"version":1,"runtime_dir":"/run/other"}`, "unknown"},
		{"caller uid", `{"version":1,"uid":0}`, "unknown"},
		{"caller gid", `{"version":1,"gid":0}`, "unknown"},
		{"admin path", `{"version":1,"network":{"profile_path":"/etc/secret"}}`, "unknown"},
		{"mount path", `{"version":1,"resources":{"mount_point":"/mnt/host"}}`, "unknown"},
		{"transfer host path", `{"version":1,"transfers":{"directory":"/home"}}`, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { requireParseError(t, tt.input, tt.want) })
	}
}

func TestParseRejectsDuplicateFields(t *testing.T) {
	for _, root := range []struct{ field, value string }{
		{"version", "1"}, {"resources", "{}"}, {"network", "{}"}, {"transfers", "{}"},
	} {
		t.Run(root.field, func(t *testing.T) {
			prefix := `"version":1,`
			if root.field == "version" {
				prefix = ""
			}
			for _, second := range []string{root.field, fmt.Sprintf(`\u%04x%s`, root.field[0], root.field[1:])} {
				input := `{` + prefix + `"` + root.field + `":` + root.value + `,"` + second + `":` + root.value + `}`
				requireParseError(t, input, "duplicate")
			}
		})
	}
	for _, field := range []struct{ path, value string }{
		{"resources.memory_max", `"1G"`},
		{"resources.workspace_size", `"512M"`},
		{"resources.tasks_max", "256"},
		{"network.mode", `"offline"`},
		{"network.profile", `""`},
		{"transfers.max_bytes", `"256M"`},
		{"transfers.max_files", "10000"},
	} {
		t.Run(field.path, func(t *testing.T) {
			parts := strings.SplitN(field.path, ".", 2)
			for _, second := range []string{parts[1], fmt.Sprintf(`\u%04x%s`, parts[1][0], parts[1][1:])} {
				object := `{"` + parts[1] + `":` + field.value + `,"` + second + `":` + field.value + `}`
				requireParseError(t, configWithJSONField(parts[0], object), "duplicate")
			}
		})
	}
	requireParseError(t, `{"version":1,"version":2}`, "duplicate")
	requireParseError(t, `{"version":1,"network":{"mode":"offline","mode":"wireguard","profile":"office"}}`, "duplicate")
}

func TestParseRejectsNullsAndWrongTypes(t *testing.T) {
	for _, field := range []string{"resources", "network", "transfers"} {
		t.Run(field, func(t *testing.T) {
			for _, value := range []string{"null", "[]", "true", "1", `"object"`} {
				requireParseError(t, configWithJSONField(field, value), "object")
			}
		})
	}
	for _, field := range []string{
		"version", "resources.memory_max", "resources.workspace_size", "resources.tasks_max",
		"network.mode", "network.profile", "transfers.max_bytes", "transfers.max_files",
	} {
		t.Run(field, func(t *testing.T) {
			for _, value := range []string{"null", "[]", "{}", "true"} {
				requireParseError(t, configWithJSONField(field, value), "")
			}
		})
	}
	for _, field := range []string{"version", "resources.tasks_max", "transfers.max_files"} {
		t.Run("integer "+field, func(t *testing.T) {
			for _, value := range []string{`"1"`, "-1", "-0", "1.0", "1e0", "18446744073709551616", "1e10000"} {
				requireParseError(t, configWithJSONField(field, value), "")
			}
		})
	}
	for _, field := range []string{"resources.memory_max", "resources.workspace_size", "network.mode", "network.profile", "transfers.max_bytes"} {
		t.Run("string "+field, func(t *testing.T) {
			requireParseError(t, configWithJSONField(field, "1"), "")
		})
	}
	for _, value := range []string{"0", "2", "9223372036854775808"} {
		requireParseError(t, configWithJSONField("version", value), "")
	}
}

func TestValidateAndParsedCombinations(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"missing version", func(c *Config) { c.Version = 0 }, "migrate"},
		{"future version", func(c *Config) { c.Version = 2 }, "version"},
		{"negative version", func(c *Config) { c.Version = -1 }, "version"},
		{"memory missing", func(c *Config) { c.Resources.MemoryMax = "" }, "resources.memory_max"},
		{"memory zero", func(c *Config) { c.Resources.MemoryMax = "0G" }, "resources.memory_max"},
		{"memory below minimum", func(c *Config) { c.Resources.MemoryMax = "134217727B" }, "resources.memory_max"},
		{"memory above maximum", func(c *Config) { c.Resources.MemoryMax = "68719476737B" }, "resources.memory_max"},
		{"memory overflow", func(c *Config) { c.Resources.MemoryMax = "17179869184G" }, "resources.memory_max"},
		{"memory maximum", func(c *Config) { c.Resources.MemoryMax = "64G" }, ""},
		{"workspace missing", func(c *Config) { c.Resources.WorkspaceSize = "" }, "resources.workspace_size"},
		{"workspace zero", func(c *Config) { c.Resources.WorkspaceSize = "0" }, "resources.workspace_size"},
		{"workspace below minimum", func(c *Config) { c.Resources.WorkspaceSize = "16777215B" }, "resources.workspace_size"},
		{"workspace above maximum", func(c *Config) { c.Resources.WorkspaceSize = "34359738369B" }, "resources.workspace_size"},
		{"workspace overflow", func(c *Config) { c.Resources.WorkspaceSize = "17592186044416M" }, "resources.workspace_size"},
		{"workspace equals memory", func(c *Config) { c.Resources.WorkspaceSize = "1G" }, "strictly below"},
		{"workspace above memory", func(c *Config) { c.Resources.WorkspaceSize = "2G" }, "strictly below"},
		{"workspace larger than lowered memory", func(c *Config) { c.Resources.MemoryMax = "128M" }, "strictly below"},
		{"minimum resource combination", func(c *Config) {
			c.Resources = ResourceConfig{MemoryMax: "128M", WorkspaceSize: "16M", TasksMax: 32}
			c.Transfers = TransferConfig{MaxBytes: "16M", MaxFiles: 1}
		}, ""},
		{"maximum resource combination", func(c *Config) {
			c.Resources = ResourceConfig{MemoryMax: "64G", WorkspaceSize: "32G", TasksMax: 4096}
			c.Transfers = TransferConfig{MaxBytes: "32G", MaxFiles: 100000}
		}, ""},
		{"one byte below memory", func(c *Config) { c.Resources.WorkspaceSize = "1073741823B" }, ""},
		{"tasks zero", func(c *Config) { c.Resources.TasksMax = 0 }, "resources.tasks_max"},
		{"tasks below minimum", func(c *Config) { c.Resources.TasksMax = 31 }, "resources.tasks_max"},
		{"tasks minimum", func(c *Config) { c.Resources.TasksMax = 32 }, ""},
		{"tasks maximum", func(c *Config) { c.Resources.TasksMax = 4096 }, ""},
		{"tasks above maximum", func(c *Config) { c.Resources.TasksMax = 4097 }, "resources.tasks_max"},
		{"tasks uint64 maximum", func(c *Config) { c.Resources.TasksMax = ^uint64(0) }, "resources.tasks_max"},
		{"transfer missing", func(c *Config) { c.Transfers.MaxBytes = "" }, "transfers.max_bytes"},
		{"transfer zero", func(c *Config) { c.Transfers.MaxBytes = "0B" }, "transfers.max_bytes"},
		{"transfer one byte", func(c *Config) { c.Transfers.MaxBytes = "1B" }, ""},
		{"transfer equals workspace", func(c *Config) { c.Transfers.MaxBytes = "512M" }, ""},
		{"transfer exceeds workspace", func(c *Config) { c.Transfers.MaxBytes = "536870913B" }, "transfers.max_bytes"},
		{"transfer not automatically clamped", func(c *Config) { c.Resources.WorkspaceSize = "16M" }, "transfers.max_bytes"},
		{"transfer overflow", func(c *Config) { c.Transfers.MaxBytes = "18446744073709551616B" }, "transfers.max_bytes"},
		{"files zero", func(c *Config) { c.Transfers.MaxFiles = 0 }, "transfers.max_files"},
		{"files minimum", func(c *Config) { c.Transfers.MaxFiles = 1 }, ""},
		{"files maximum", func(c *Config) { c.Transfers.MaxFiles = 100000 }, ""},
		{"files above maximum", func(c *Config) { c.Transfers.MaxFiles = 100001 }, "transfers.max_files"},
		{"files uint64 maximum", func(c *Config) { c.Transfers.MaxFiles = ^uint64(0) }, "transfers.max_files"},
		{"offline profile", func(c *Config) { c.Network.Profile = "office" }, "network.profile"},
		{"offline invalid profile", func(c *Config) { c.Network.Profile = "../office" }, "network.profile"},
		{"wireguard missing profile", func(c *Config) { c.Network.Mode = "wireguard" }, "network.profile"},
		{"wireguard profile", func(c *Config) { c.Network = NetworkConfig{Mode: "wireguard", Profile: "office_1-west"} }, ""},
		{"wireguard profile maximum", func(c *Config) { c.Network = NetworkConfig{Mode: "wireguard", Profile: strings.Repeat("a", 48)} }, ""},
		{"wireguard profile too long", func(c *Config) { c.Network = NetworkConfig{Mode: "wireguard", Profile: strings.Repeat("a", 49)} }, "network.profile"},
		{"wireguard path", func(c *Config) { c.Network = NetworkConfig{Mode: "wireguard", Profile: "../office"} }, "network.profile"},
		{"mode missing", func(c *Config) { c.Network.Mode = "" }, "network.mode"},
		{"mode case", func(c *Config) { c.Network.Mode = "WireGuard" }, "network.mode"},
		{"mode whitespace", func(c *Config) { c.Network.Mode = "offline " }, "network.mode"},
		{"openvpn mode", func(c *Config) { c.Network.Mode = "openvpn" }, "network.mode"},
		{"tor mode", func(c *Config) { c.Network.Mode = "tor" }, "network.mode"},
		{"direct mode", func(c *Config) { c.Network.Mode = "direct" }, "network.mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.edit(&cfg)
			before := cfg
			err := cfg.Validate()
			if cfg != before {
				t.Fatal("Validate mutated the config")
			}
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.want)
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if tt.want != "" {
				requireParseError(t, string(data), tt.want)
				return
			}
			parsed, err := Parse(bytes.NewReader(data))
			if err != nil || parsed != cfg {
				t.Fatalf("Parse(valid config) = %+v, %v; want %+v", parsed, err, cfg)
			}
		})
	}
}

func TestValidateProfileID(t *testing.T) {
	for _, id := range []string{"a", "0", "office", "1office", "eu_1-west", "a_", "a-", strings.Repeat("a", 48)} {
		if err := ValidateProfileID(id); err != nil {
			t.Errorf("ValidateProfileID(%q): %v", id, err)
		}
	}
	for _, id := range []string{"", "_office", "-office", "Office", "aB", ".", "..", "a.b", "a/b", `a\b`, "a b", " a", "a\n", "a\x00", "a:b", "a@b", "a%2fb", "\u00e9", strings.Repeat("a", 49)} {
		if err := ValidateProfileID(id); err == nil {
			t.Errorf("ValidateProfileID(%q) accepted an invalid ID", id)
		}
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
	}{
		{"1", 1}, {"1B", 1}, {"2b", 2}, {"001024", 1024},
		{"1K", 1 << 10}, {"2k", 2 << 10}, {"100M", 100 << 20},
		{"512m", 512 << 20}, {"1G", 1 << 30}, {"64g", 64 << 30},
		{" \t1G\n", 1 << 30}, {"18446744073709551615", ^uint64(0)},
		{"18446744073709551615B", ^uint64(0)},
		{"18014398509481983K", (^uint64(0) / (1 << 10)) * (1 << 10)},
		{"17592186044415M", (^uint64(0) / (1 << 20)) * (1 << 20)},
		{"17179869183G", (^uint64(0) / (1 << 30)) * (1 << 30)},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseSize(tt.input)
			if err != nil || got != tt.want {
				t.Fatalf("ParseSize(%q) = %d, %v; want %d", tt.input, got, err, tt.want)
			}
		})
	}
}

func TestParseSizeRejectsZeroMalformedAndOverflow(t *testing.T) {
	for _, input := range []string{
		"", " ", "0", "00", "0B", "0K", "0M", "0G", "G", "B", "abc",
		"-1", "-0M", "+1G", "1.5G", "1e3", "1 024", "1 G", "1MB", "1GiB", "1T", "0x10", "1\x00G", "\u0661G",
		"18446744073709551616", "18446744073709551616B", "18014398509481984K", "17592186044416M", "17179869184G",
		"18446744073709551615G", strings.Repeat("9", 1024) + "G",
	} {
		t.Run(input, func(t *testing.T) {
			got, err := ParseSize(input)
			if err == nil || got != 0 {
				t.Fatalf("ParseSize(%q) = %d, %v; want zero and error", input, got, err)
			}
		})
	}
}

func TestFormatSizeExact(t *testing.T) {
	for _, tt := range []struct {
		n    uint64
		want string
	}{
		{0, "0B"}, {1, "1B"}, {1023, "1023B"}, {1 << 10, "1K"},
		{1536, "1536B"}, {512 << 20, "512M"}, {1 << 30, "1G"},
		{64 << 30, "64G"}, {1<<63 + 1, "9223372036854775809B"},
		{^uint64(0), "18446744073709551615B"},
	} {
		if got := FormatSize(tt.n); got != tt.want {
			t.Errorf("FormatSize(%d) = %q, want %q", tt.n, got, tt.want)
		}
		if tt.n != 0 {
			got, err := ParseSize(FormatSize(tt.n))
			if err != nil || got != tt.n {
				t.Errorf("size round trip %d = %d, %v", tt.n, got, err)
			}
		}
	}
}

func TestParseBoundedInputAndReaderErrors(t *testing.T) {
	base := `{"version":1}`
	atLimit := base + strings.Repeat(" ", maxConfigBytes-len(base))
	if got, err := Parse(strings.NewReader(atLimit)); err != nil || got != Default() {
		t.Fatalf("exactly 1 MiB input = %+v, %v", got, err)
	}
	requireParseError(t, atLimit+" ", "1 MiB")
	reader := &countingReader{Reader: strings.NewReader(strings.Repeat(" ", maxConfigBytes+100))}
	if _, err := Parse(reader); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("oversized reader: %v", err)
	}
	if reader.n != maxConfigBytes+1 {
		t.Fatalf("read %d bytes, want only %d", reader.n, maxConfigBytes+1)
	}
	sentinel := errors.New("reader failed")
	for _, reader := range []io.Reader{
		errorReader{sentinel},
		io.MultiReader(strings.NewReader(base), errorReader{sentinel}),
	} {
		got, err := Parse(reader)
		if !errors.Is(err, sentinel) || got != (Config{}) {
			t.Fatalf("reader error = %+v, %v", got, err)
		}
	}
	if got, err := Parse(nil); err == nil || got != (Config{}) {
		t.Fatalf("nil reader = %+v, %v", got, err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(path); err != nil || got != Default() {
		t.Fatalf("Load() = %+v, %v", got, err)
	}
	for _, input := range []string{
		"", ".", "config.json", "./config.json", "../config.json", "~/config.json",
		dir + "/./config.json", dir + "//config.json", dir + "/unused/../config.json", path + "/", path + "\x00",
	} {
		t.Run(input, func(t *testing.T) {
			got, err := Load(input)
			if err == nil || !strings.Contains(err.Error(), "clean absolute") || got != (Config{}) {
				t.Fatalf("Load(%q) = %+v, %v", input, got, err)
			}
		})
	}
	if got, err := Load(dir); err == nil || !strings.Contains(err.Error(), "regular file") || got != (Config{}) {
		t.Fatalf("Load(directory) = %+v, %v", got, err)
	}
	if got, err := Load(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) || got != (Config{}) {
		t.Fatalf("Load(missing) = %+v, %v", got, err)
	}
	for _, tt := range []struct{ input, want string }{
		{`{}`, "migrate"},
		{`{"version":1,"network":{"mode":"wireguard"}}`, "network.profile"},
		{`{"version":1}{}`, "trailing"},
		{strings.Repeat(" ", maxConfigBytes+1), "1 MiB"},
	} {
		if err := os.WriteFile(path, []byte(tt.input), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), tt.want) || got != (Config{}) {
			t.Fatalf("Load(invalid) = %+v, %v; want %q", got, err, tt.want)
		}
	}
}

func requireParseError(t *testing.T, input, want string) {
	t.Helper()
	got, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Parse() error = %v, want error containing %q", err, want)
	}
	if got != (Config{}) {
		t.Fatalf("Parse returned partial config on error: %+v", got)
	}
}

func configWithJSONField(path, value string) string {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) == 2 {
		return `{"version":1,"` + parts[0] + `":{"` + parts[1] + `":` + value + `}}`
	}
	if path == "version" {
		return `{"version":` + value + `}`
	}
	return `{"version":1,"` + path + `":` + value + `}`
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type countingReader struct {
	io.Reader
	n int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += n
	return n, err
}
