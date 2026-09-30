package session

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/filesystem"
	"github.com/Lfardell1/Soteria/internal/monitor"
	"github.com/Lfardell1/Soteria/internal/network"
	"github.com/Lfardell1/Soteria/internal/tui"
)

// Session owns the full secure-mode lifecycle.
type Session struct {
	cfg config.Config
	fs  *filesystem.Manager
	net *network.Stack
	mon *monitor.Monitor

	mu       sync.Mutex
	started  bool
	stopping bool
	cancel   context.CancelFunc
}

// New builds a session from config.
func New(cfg config.Config) *Session {
	fs := filesystem.New(cfg.Filesystem)
	netStack := network.New(cfg)
	mon := monitor.New(cfg, fs, netStack, 64)
	return &Session{cfg: cfg, fs: fs, net: netStack, mon: mon}
}

// Start brings up filesystem, network, monitoring, and the TUI.
func (s *Session) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("session already started")
	}
	s.started = true
	s.mu.Unlock()

	if os.Geteuid() != 0 {
		return fmt.Errorf("soteria must run as root")
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			_ = s.Stop()
		case <-ctx.Done():
		}
		signal.Stop(sigCh)
	}()

	if err := s.fs.Mount(); err != nil {
		_ = s.Stop()
		return fmt.Errorf("mount ephemeral filesystem: %w", err)
	}

	if err := s.fs.Populate(); err != nil {
		_ = s.Stop()
		return fmt.Errorf("populate ephemeral filesystem: %w", err)
	}

	if s.cfg.VPN.Enabled || s.cfg.Tor.Enabled || s.cfg.Network.KillSwitch {
		if err := s.net.Start(); err != nil {
			_ = s.Stop()
			return fmt.Errorf("start network stack: %w", err)
		}
	}

	go s.mon.Run(ctx)

	err := tui.Run(s.mon, func() {
		_ = s.Stop()
	})
	// Ensure teardown even if TUI exits without onQuit.
	_ = s.Stop()
	return err
}

// Stop reverses startup order and is idempotent.
func (s *Session) Stop() error {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil
	}
	s.stopping = true
	cancel := s.cancel
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	var firstErr error
	capture := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	capture(s.net.Stop())
	capture(s.fs.Teardown())

	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
	return firstErr
}

// Filesystem exposes the ephemeral FS manager (for tests).
func (s *Session) Filesystem() *filesystem.Manager { return s.fs }

// Network exposes the network stack (for tests).
func (s *Session) Network() *network.Stack { return s.net }
