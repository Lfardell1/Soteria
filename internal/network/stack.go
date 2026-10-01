package network

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
)

func lookPath(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		candidate := filepath.Join(dir, name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH or common sbin locations", name)
}

func command(name string, args ...string) (*exec.Cmd, error) {
	bin, err := lookPath(name)
	if err != nil {
		return nil, err
	}
	return exec.Command(bin, args...), nil
}

// Stack manages VPN, Tor, DNSCrypt, and the iptables kill-switch.
type Stack struct {
	cfg config.Config

	mu          sync.Mutex
	iptablesBak string
	killActive  bool
	vpnCmd      *exec.Cmd
	torCmd      *exec.Cmd
	dnsCmd      *exec.Cmd
	resolvBak   string
	started     bool
}

// New creates a networking stack from config.
func New(cfg config.Config) *Stack {
	return &Stack{cfg: cfg}
}

// Start applies the kill-switch (if enabled), then brings up configured services.
func (s *Stack) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return nil
	}

	if s.cfg.Network.KillSwitch {
		if err := s.applyKillSwitchLocked(); err != nil {
			return err
		}
	}

	if s.cfg.VPN.Enabled {
		if err := s.startVPNLocked(); err != nil {
			_ = s.stopLocked()
			return err
		}
	}

	if s.cfg.Tor.Enabled {
		if err := s.startTorLocked(); err != nil {
			_ = s.stopLocked()
			return err
		}
	}

	if s.cfg.DNSCrypt.Enabled {
		if err := s.startDNSCryptLocked(); err != nil {
			_ = s.stopLocked()
			return err
		}
	}

	if err := s.verifyLocked(); err != nil {
		_ = s.stopLocked()
		return err
	}

	s.started = true
	return nil
}

// Stop reverses networking setup and restores iptables/resolv.conf.
func (s *Stack) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked()
}

// Status summarizes the active network mode for the TUI.
func (s *Stack) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()

	st := Status{
		KillSwitch: s.killActive,
		VPN:        s.cfg.VPN.Enabled && s.vpnCmd != nil && s.vpnCmd.Process != nil,
		Tor:        s.cfg.Tor.Enabled && (s.torCmd != nil || torPortOpen(s.cfg.Tor.SocksPort)),
		DNSCrypt:   s.cfg.DNSCrypt.Enabled && s.dnsCmd != nil,
		Interface:  s.cfg.VPN.Interface,
		SocksPort:  s.cfg.Tor.SocksPort,
	}
	if s.cfg.Proxychains.Enabled {
		st.Proxychains = s.cfg.Proxychains.ConfigFile
	}
	return st
}

// Status is a snapshot of networking state.
type Status struct {
	KillSwitch  bool
	VPN         bool
	Tor         bool
	DNSCrypt    bool
	Interface   string
	SocksPort   int
	Proxychains string
}

func (s *Stack) stopLocked() error {
	var firstErr error
	capture := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if s.dnsCmd != nil && s.dnsCmd.Process != nil {
		_ = s.dnsCmd.Process.Signal(os.Interrupt)
		_, _ = s.dnsCmd.Process.Wait()
		s.dnsCmd = nil
	}
	if s.resolvBak != "" {
		capture(restoreResolv(s.resolvBak))
		s.resolvBak = ""
	}

	if s.torCmd != nil && s.torCmd.Process != nil {
		_ = s.torCmd.Process.Signal(os.Interrupt)
		_, _ = s.torCmd.Process.Wait()
		s.torCmd = nil
	}

	if s.vpnCmd != nil && s.vpnCmd.Process != nil {
		_ = s.vpnCmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_, _ = s.vpnCmd.Process.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = s.vpnCmd.Process.Kill()
		}
		s.vpnCmd = nil
	}

	if s.killActive {
		capture(s.restoreKillSwitchLocked())
	}

	s.started = false
	return firstErr
}

func (s *Stack) applyKillSwitchLocked() error {
	bak := filepath.Join(os.TempDir(), fmt.Sprintf("soteria-iptables-%d.bak", os.Getpid()))
	saveCmd, err := command("iptables-save")
	if err != nil {
		return err
	}
	out, err := saveCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-save: %w (%s)", err, string(out))
	}
	if err := os.WriteFile(bak, out, 0o600); err != nil {
		return err
	}
	s.iptablesBak = bak

	iface := s.cfg.VPN.Interface
	if iface == "" {
		iface = "tun0"
	}

	rules := [][]string{
		{"-P", "OUTPUT", "DROP"},
		{"-P", "FORWARD", "DROP"},
		{"-F", "OUTPUT"},
		{"-F", "FORWARD"},
		{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}

	if s.cfg.VPN.Enabled {
		rules = append(rules,
			[]string{"-A", "OUTPUT", "-o", iface, "-j", "ACCEPT"},
			// Allow initiating the VPN connection itself on the physical iface.
			[]string{"-A", "OUTPUT", "-p", "udp", "--dport", "1194", "-j", "ACCEPT"},
			[]string{"-A", "OUTPUT", "-p", "tcp", "--dport", "1194", "-j", "ACCEPT"},
			[]string{"-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "ACCEPT"},
			[]string{"-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"},
		)
	}

	if s.cfg.Tor.Enabled {
		port := strconv.Itoa(s.cfg.Tor.SocksPort)
		rules = append(rules,
			[]string{"-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", port, "-j", "ACCEPT"},
			[]string{"-A", "OUTPUT", "-m", "owner", "--uid-owner", "debian-tor", "-j", "ACCEPT"},
		)
	}

	// DNSCrypt local listener
	if s.cfg.DNSCrypt.Enabled {
		rules = append(rules,
			[]string{"-A", "OUTPUT", "-p", "udp", "-d", "127.0.0.1", "--dport", "53", "-j", "ACCEPT"},
			[]string{"-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", "53", "-j", "ACCEPT"},
		)
	}

	for _, r := range rules {
		cmd, err := command("iptables", r...)
		if err != nil {
			_ = s.restoreKillSwitchLocked()
			return err
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			_ = s.restoreKillSwitchLocked()
			return fmt.Errorf("iptables %v: %w (%s)", r, err, string(out))
		}
	}

	s.killActive = true
	return nil
}

func (s *Stack) restoreKillSwitchLocked() error {
	if s.iptablesBak == "" {
		s.killActive = false
		return nil
	}
	cmd, err := command("iptables-restore", s.iptablesBak)
	if err != nil {
		return err
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-restore: %w (%s)", err, string(out))
	}
	_ = os.Remove(s.iptablesBak)
	s.iptablesBak = ""
	s.killActive = false
	return nil
}

func (s *Stack) startVPNLocked() error {
	cmd, err := command("openvpn", "--config", s.cfg.VPN.ConfigFile, "--verb", "1")
	if err != nil {
		return err
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start openvpn: %w", err)
	}
	s.vpnCmd = cmd

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if ifaceUp(s.cfg.VPN.Interface) {
			return nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return fmt.Errorf("openvpn exited before interface %s came up", s.cfg.VPN.Interface)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for VPN interface %s", s.cfg.VPN.Interface)
}

func (s *Stack) startTorLocked() error {
	// Prefer an already-running system Tor if SOCKS is open.
	if torPortOpen(s.cfg.Tor.SocksPort) {
		return nil
	}

	args := []string{}
	if s.cfg.Tor.ConfigFile != "" {
		args = append(args, "-f", s.cfg.Tor.ConfigFile)
	} else {
		args = append(args,
			"--SocksPort", strconv.Itoa(s.cfg.Tor.SocksPort),
			"--CookieAuthentication", "0",
		)
	}
	cmd, err := command("tor", args...)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tor: %w", err)
	}
	s.torCmd = cmd

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if torPortOpen(s.cfg.Tor.SocksPort) {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for Tor SOCKS on %d", s.cfg.Tor.SocksPort)
}

func (s *Stack) startDNSCryptLocked() error {
	cmd, err := command("dnscrypt-proxy", "-config", s.cfg.DNSCrypt.ConfigFile)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start dnscrypt-proxy: %w", err)
	}
	s.dnsCmd = cmd

	bak, err := backupAndSetResolv("nameserver 127.0.0.1\noptions edns0\n")
	if err != nil {
		return err
	}
	s.resolvBak = bak
	return nil
}

func (s *Stack) verifyLocked() error {
	if s.cfg.VPN.Enabled && !ifaceUp(s.cfg.VPN.Interface) {
		return fmt.Errorf("vpn interface %s is down", s.cfg.VPN.Interface)
	}
	if s.cfg.Tor.Enabled && !torPortOpen(s.cfg.Tor.SocksPort) {
		return fmt.Errorf("tor socks port %d not accepting connections", s.cfg.Tor.SocksPort)
	}
	return nil
}

func ifaceUp(name string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	return iface.Flags&net.FlagUp != 0
}

func torPortOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func backupAndSetResolv(content string) (string, error) {
	const resolv = "/etc/resolv.conf"
	bak := filepath.Join(os.TempDir(), fmt.Sprintf("soteria-resolv-%d.bak", os.Getpid()))
	data, err := os.ReadFile(resolv)
	if err != nil {
		return "", fmt.Errorf("read resolv.conf: %w", err)
	}
	if err := os.WriteFile(bak, data, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(resolv, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("write resolv.conf: %w", err)
	}
	return bak, nil
}

func restoreResolv(bak string) error {
	data, err := os.ReadFile(bak)
	if err != nil {
		return err
	}
	if err := os.WriteFile("/etc/resolv.conf", data, 0o644); err != nil {
		return err
	}
	return os.Remove(bak)
}

// ProxychainsPrefix returns argv prefix for wrapping commands when enabled.
func (s *Stack) ProxychainsPrefix() []string {
	if !s.cfg.Proxychains.Enabled {
		return nil
	}
	return []string{"proxychains4", "-f", s.cfg.Proxychains.ConfigFile, "-q"}
}

// ModeLabel returns a short human label for the active anonymity stack.
func (st Status) ModeLabel() string {
	parts := []string{}
	if st.VPN {
		parts = append(parts, "VPN")
	}
	if st.Tor {
		parts = append(parts, "Tor")
	}
	if st.DNSCrypt {
		parts = append(parts, "DNSCrypt")
	}
	if st.Proxychains != "" {
		parts = append(parts, "Proxychains")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "+")
}
