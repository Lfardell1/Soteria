package session

import (
	"os"
	"testing"

	"github.com/Lfardell1/Soteria/internal/config"
)

func TestNewWiresComponents(t *testing.T) {
	cfg := config.Default()
	cfg.Network.KillSwitch = false
	s := New(cfg)
	if s.Filesystem() == nil || s.Network() == nil {
		t.Fatal("expected filesystem and network to be initialized")
	}
}

func TestStartRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; cannot assert non-root failure")
	}
	cfg := config.Default()
	cfg.Network.KillSwitch = false
	cfg.VPN.Enabled = false
	cfg.Tor.Enabled = false
	s := New(cfg)
	if err := s.Start(); err == nil {
		t.Fatal("expected non-root Start to fail")
	}
}
