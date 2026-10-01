package network

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Lfardell1/Soteria/internal/config"
)

func TestModeLabel(t *testing.T) {
	st := Status{VPN: true, Tor: true, DNSCrypt: true}
	if got := st.ModeLabel(); got != "VPN+Tor+DNSCrypt" {
		t.Fatalf("got %q", got)
	}
	if (Status{}).ModeLabel() != "none" {
		t.Fatal("expected none")
	}
}

func TestProxychainsPrefix(t *testing.T) {
	s := New(config.Config{
		Proxychains: config.ProxychainsConfig{Enabled: true, ConfigFile: "/etc/proxychains4.conf"},
	})
	prefix := s.ProxychainsPrefix()
	if len(prefix) != 4 || prefix[0] != "proxychains4" {
		t.Fatalf("unexpected prefix: %v", prefix)
	}
}

func TestKillSwitchSaveRestoreDry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for iptables")
	}
	// Only exercise save/restore if iptables-save exists.
	if _, err := os.Stat("/sbin/iptables-save"); err != nil {
		if _, err2 := os.Stat("/usr/sbin/iptables-save"); err2 != nil {
			t.Skip("iptables-save not available")
		}
	}

	cfg := config.Default()
	cfg.Network.KillSwitch = true
	cfg.VPN.Enabled = true
	cfg.VPN.Interface = "tun0"
	// Config file must exist for validation elsewhere; create a stub for stack construction.
	dir := t.TempDir()
	cfg.VPN.ConfigFile = filepath.Join(dir, "client.conf")
	_ = os.WriteFile(cfg.VPN.ConfigFile, []byte("nobind\n"), 0o644)

	s := New(cfg)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.applyKillSwitchLocked(); err != nil {
		t.Fatalf("applyKillSwitch: %v", err)
	}
	if !s.killActive {
		t.Fatal("expected kill switch active")
	}
	if err := s.restoreKillSwitchLocked(); err != nil {
		t.Fatalf("restoreKillSwitch: %v", err)
	}
}
