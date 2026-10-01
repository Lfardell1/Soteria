package monitor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/filesystem"
	"github.com/Lfardell1/Soteria/internal/network"
)

// Kind classifies an alert.
type Kind string

const (
	ProcessDown      Kind = "ProcessDown"
	DiskLow          Kind = "DiskLow"
	LeakRisk         Kind = "LeakRisk"
	ConnectivityLost Kind = "ConnectivityLost"
	Info             Kind = "Info"
)

// Severity levels for TUI coloring.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert is a typed monitoring event.
type Alert struct {
	Time     time.Time
	Kind     Kind
	Severity Severity
	Message  string
}

// ProcessStatus describes one watched process.
type ProcessStatus struct {
	Name    string
	Running bool
	PIDs    []int
}

// Snapshot is a point-in-time monitoring view.
type Snapshot struct {
	Time       time.Time
	Processes  []ProcessStatus
	Disk       filesystem.Usage
	DiskOK     bool
	Network    network.Status
	ConnOK     bool
	Alerts     []Alert
}

// Monitor polls processes, disk, and connectivity.
type Monitor struct {
	cfg     config.Config
	fs      *filesystem.Manager
	net     *network.Stack
	alerts  chan Alert
	mu      sync.RWMutex
	latest  Snapshot
	history []Alert
}

// New creates a monitor. alertBuffer sizes the outbound alert channel.
func New(cfg config.Config, fs *filesystem.Manager, netStack *network.Stack, alertBuffer int) *Monitor {
	if alertBuffer <= 0 {
		alertBuffer = 32
	}
	return &Monitor{
		cfg:    cfg,
		fs:     fs,
		net:    netStack,
		alerts: make(chan Alert, alertBuffer),
	}
}

// Alerts returns the read-only alert channel.
func (m *Monitor) Alerts() <-chan Alert {
	return m.alerts
}

// Latest returns the most recent snapshot.
func (m *Monitor) Latest() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.latest
}

// Run polls until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	interval := time.Duration(m.cfg.Monitoring.PollIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	m.tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.tick()
		}
	}
}

func (m *Monitor) tick() {
	snap := Snapshot{Time: time.Now()}

	for _, name := range m.cfg.Monitoring.Processes {
		pids := findPIDs(name)
		running := len(pids) > 0
		snap.Processes = append(snap.Processes, ProcessStatus{Name: name, Running: running, PIDs: pids})
		if !running {
			m.emit(Alert{
				Time:     time.Now(),
				Kind:     ProcessDown,
				Severity: SeverityCritical,
				Message:  fmt.Sprintf("critical process %q is not running", name),
			})
		}
	}

	if m.fs != nil && m.fs.IsMounted() {
		usage, err := m.fs.Stats()
		if err == nil {
			snap.Disk = usage
			minFree, _ := config.ParseSize(m.cfg.Monitoring.TmpfsFreeSpaceMin)
			snap.DiskOK = usage.Free >= minFree
			if !snap.DiskOK {
				m.emit(Alert{
					Time:     time.Now(),
					Kind:     DiskLow,
					Severity: SeverityWarning,
					Message:  fmt.Sprintf("tmpfs free space low: %s remaining", config.FormatSize(usage.Free)),
				})
			}
		}
	}

	if m.net != nil {
		snap.Network = m.net.Status()
		if m.cfg.Network.KillSwitch {
			if m.cfg.VPN.Enabled && !snap.Network.VPN {
				m.emit(Alert{
					Time:     time.Now(),
					Kind:     LeakRisk,
					Severity: SeverityCritical,
					Message:  "VPN tunnel down while kill-switch is active",
				})
			}
			if m.cfg.Tor.Enabled && !snap.Network.Tor {
				m.emit(Alert{
					Time:     time.Now(),
					Kind:     LeakRisk,
					Severity: SeverityCritical,
					Message:  "Tor SOCKS unavailable while kill-switch is active",
				})
			}
		}
	}

	snap.ConnOK = true
	if m.cfg.Network.CheckConnectivity && m.cfg.Network.Gateway != "" {
		snap.ConnOK = checkGateway(m.cfg.Network.Gateway)
		if !snap.ConnOK {
			m.emit(Alert{
				Time:     time.Now(),
				Kind:     ConnectivityLost,
				Severity: SeverityWarning,
				Message:  fmt.Sprintf("cannot reach gateway %s", m.cfg.Network.Gateway),
			})
		}
	}

	m.mu.Lock()
	snap.Alerts = append([]Alert{}, m.history...)
	m.latest = snap
	m.mu.Unlock()
}

func (m *Monitor) emit(a Alert) {
	m.mu.Lock()
	m.history = append(m.history, a)
	if len(m.history) > 50 {
		m.history = m.history[len(m.history)-50:]
	}
	m.mu.Unlock()

	select {
	case m.alerts <- a:
	default:
		// Drop if consumer is slow; snapshot history still retains it.
	}
}

func findPIDs(name string) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(cmdline))
		if comm == name || strings.HasPrefix(comm, name) {
			pids = append(pids, pid)
			continue
		}
		// Also check argv0 basename from cmdline.
		full, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil || len(full) == 0 {
			continue
		}
		argv0 := strings.Split(string(full), "\x00")[0]
		base := filepath.Base(argv0)
		if base == name {
			pids = append(pids, pid)
		}
	}
	return pids
}

func checkGateway(gateway string) bool {
	// Prefer TCP connect to avoid requiring CAP_NET_RAW for ICMP.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(gateway, "443"), 2*time.Second)
	if err == nil {
		_ = conn.Close()
		return true
	}
	conn, err = net.DialTimeout("tcp", net.JoinHostPort(gateway, "53"), 2*time.Second)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}

// FindPIDs is exported for tests.
func FindPIDs(name string) []int {
	return findPIDs(name)
}
