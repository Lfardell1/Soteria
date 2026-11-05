package config

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`{"version":1}`,
		`{"version":1,"network":{"mode":"wireguard","profile":"office_1-west"}}`,
		`{"version":1,"resources":{"memory_max":"128M","workspace_size":"16M","tasks_max":32},"transfers":{"max_bytes":"1B","max_files":1}}`,
		`{}`, `null`, `{"vpn":{"enabled":true}}`,
		`{"version":1,"version":1}`, `{"version":1,"\u0076ersion":1}`,
		`{"version":1,"resources":{"tasks_max":18446744073709551616}}`,
		`{"version":1,"resources":{"memory_max":"17179869184G"}}`,
		`{"version":1,"resources":{"memory_max":null}}`,
		`{"version":1,"transfers":{"max_bytes":"1B","max_bytes":"2B"}}`,
		`{"version":1,"network":{"unknown":true}}`, `{"version":1}{}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := Parse(bytes.NewReader(data))
		if err != nil {
			if cfg != (Config{}) {
				t.Fatalf("error returned partial config: %+v", cfg)
			}
			return
		}
		if len(data) > maxConfigBytes {
			t.Fatal("accepted oversized input")
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("accepted invalid config: %v", err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			t.Fatal(err)
		}
		var explicitVersion int
		if err := json.Unmarshal(object["version"], &explicitVersion); err != nil || explicitVersion != 1 {
			t.Fatalf("accepted config without explicit version 1: %v", err)
		}
		encoded, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, err := Parse(bytes.NewReader(encoded))
		if err != nil || roundTrip != cfg {
			t.Fatalf("JSON round trip = %+v, %v; want %+v", roundTrip, err, cfg)
		}
	})
}

func FuzzParseSize(f *testing.F) {
	for _, seed := range []string{"1", "128M", "64G", " 1g ", "0", "-0", "1e3", "17179869184G", "18446744073709551615B", "18446744073709551616"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		n, err := ParseSize(input)
		if err != nil {
			if n != 0 {
				t.Fatal("error returned a nonzero size")
			}
			return
		}
		if n == 0 {
			t.Fatal("accepted zero size")
		}
		got, err := ParseSize(FormatSize(n))
		if err != nil || got != n {
			t.Fatalf("size round trip = %d, %v; want %d", got, err, n)
		}
	})
}

func FuzzFormatSize(f *testing.F) {
	for _, seed := range []uint64{0, 1, 1023, 1024, 1536, 128 << 20, 64 << 30, 1 << 63, 1<<63 + 1, ^uint64(0)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, n uint64) {
		got, err := ParseSize(FormatSize(n))
		if n == 0 {
			if err == nil || got != 0 {
				t.Fatal("zero must not become a valid size")
			}
			return
		}
		if err != nil || got != n {
			t.Fatalf("exact size round trip = %d, %v; want %d", got, err, n)
		}
	})
}

func FuzzValidateProfileID(f *testing.F) {
	for _, seed := range []string{"", "a", "0", "office_1-west", strings.Repeat("a", 48), strings.Repeat("a", 49), "_a", "A", "../a", "a/b", "a\x00", "\u00e9"} {
		f.Add(seed)
	}
	pattern := regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
	f.Fuzz(func(t *testing.T, id string) {
		got := ValidateProfileID(id) == nil
		if want := pattern.MatchString(id); got != want {
			t.Fatalf("ValidateProfileID() accepted=%v, want %v", got, want)
		}
	})
}

func FuzzValidateCombinations(f *testing.F) {
	f.Add(uint64(1<<30), uint64(512<<20), uint64(256), uint64(256<<20), uint64(10000), "offline", "")
	f.Add(uint64(128<<20), uint64(16<<20), uint64(32), uint64(1), uint64(1), "wireguard", "office_1-west")
	f.Add(uint64(64<<30), uint64(32<<30), uint64(4096), uint64(32<<30), uint64(100000), "offline", "")
	f.Add(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), "", "")
	f.Add(^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), "wireguard", "../office")
	f.Fuzz(func(t *testing.T, memory, workspace, tasks, transfer, files uint64, mode, profile string) {
		cfg := Config{
			Version:   1,
			Resources: ResourceConfig{MemoryMax: FormatSize(memory), WorkspaceSize: FormatSize(workspace), TasksMax: tasks},
			Network:   NetworkConfig{Mode: mode, Profile: profile},
			Transfers: TransferConfig{MaxBytes: FormatSize(transfer), MaxFiles: files},
		}
		want := memory >= 128<<20 && memory <= 64<<30 &&
			workspace >= 16<<20 && workspace <= 32<<30 && workspace < memory &&
			tasks >= 32 && tasks <= 4096 && transfer > 0 && transfer <= workspace && files > 0 && files <= 100000 &&
			(mode == "offline" && profile == "" || mode == "wireguard" && ValidateProfileID(profile) == nil)
		if got := cfg.Validate() == nil; got != want {
			t.Fatalf("Validate() accepted=%v, want %v", got, want)
		}
	})
}
