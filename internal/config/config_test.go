package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
	}{
		{"2G", 2 << 30},
		{"100M", 100 << 20},
		{"512K", 512 << 10},
		{"1024", 1024},
		{"1B", 1},
	}
	for _, tc := range tests {
		got, err := ParseSize(tc.in)
		if err != nil {
			t.Fatalf("ParseSize(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseSize(%q)=%d want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseSizeInvalid(t *testing.T) {
	for _, in := range []string{"", "abc", "G", "-1M"} {
		if _, err := ParseSize(in); err == nil {
			t.Fatalf("ParseSize(%q) expected error", in)
		}
	}
}

func TestValidateDefaults(t *testing.T) {
	cfg := Default()
	cfg.Network.KillSwitch = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate with kill_switch off: %v", err)
	}
}

func TestValidateKillSwitchRequiresTunnel(t *testing.T) {
	cfg := Default()
	cfg.Network.KillSwitch = true
	cfg.VPN.Enabled = false
	cfg.Tor.Enabled = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected kill_switch without tunnel to fail")
	}
}

func TestLoadAndValidateWithVPN(t *testing.T) {
	dir := t.TempDir()
	vpnConf := filepath.Join(dir, "client.conf")
	if err := os.WriteFile(vpnConf, []byte("remote example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "config.json")
	content := `{
  "filesystem": {"tmpfs_size": "1G", "mount_point": "/mnt/secure", "tools_dir": "/tmp"},
  "monitoring": {"processes": ["openvpn"], "tmpfs_free_space_min": "50M", "poll_interval_seconds": 1},
  "vpn": {"enabled": true, "config_file": "` + vpnConf + `", "interface": "tun0"},
  "network": {"check_connectivity": true, "gateway": "1.1.1.1", "kill_switch": true}
}`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.VPN.Enabled || cfg.VPN.Interface != "tun0" {
		t.Fatalf("unexpected vpn config: %+v", cfg.VPN)
	}
}

func TestLoadMissingVPNFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	content := `{
  "filesystem": {"tmpfs_size": "1G", "mount_point": "/mnt/secure"},
  "monitoring": {"tmpfs_free_space_min": "50M", "poll_interval_seconds": 1},
  "vpn": {"enabled": true, "config_file": "/no/such/vpn.conf", "interface": "tun0"},
  "network": {"kill_switch": true}
}`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected missing vpn config file to fail")
	}
}
