package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/monitor"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	critStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	boxStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
)

type tickMsg time.Time
type alertMsg monitor.Alert

// Model is the Bubble Tea TUI model.
type Model struct {
	mon       *monitor.Monitor
	alerts    <-chan monitor.Alert
	width     int
	height    int
	quitting  bool
	recent    []monitor.Alert
	viewport  viewport.Model
	ready     bool
	onQuit    func()
}

// New builds the TUI model.
func New(mon *monitor.Monitor, onQuit func()) Model {
	return Model{
		mon:    mon,
		alerts: mon.Alerts(),
		onQuit: onQuit,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tick(), waitAlert(m.alerts))
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func waitAlert(ch <-chan monitor.Alert) tea.Cmd {
	return func() tea.Msg {
		a, ok := <-ch
		if !ok {
			return nil
		}
		return alertMsg(a)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			if m.onQuit != nil {
				m.onQuit()
			}
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if !m.ready {
			m.viewport = viewport.New(msg.Width, max(1, msg.Height-1))
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = max(1, msg.Height-1)
		}
	case tickMsg:
		return m, tick()
	case alertMsg:
		m.recent = append(m.recent, monitor.Alert(msg))
		if len(m.recent) > 20 {
			m.recent = m.recent[len(m.recent)-20:]
		}
		return m, waitAlert(m.alerts)
	}
	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return mutedStyle.Render("Shutting down Soteria secure mode...\n")
	}

	snap := m.mon.Latest()
	var b strings.Builder

	b.WriteString(titleStyle.Render(" SOTERIA ") + mutedStyle.Render("secure mode") + "\n\n")

	// Session / network
	netLabel := snap.Network.ModeLabel()
	ks := "off"
	if snap.Network.KillSwitch {
		ks = okStyle.Render("ON")
	}
	conn := okStyle.Render("OK")
	if !snap.ConnOK {
		conn = warnStyle.Render("DEGRADED")
	}
	b.WriteString(boxStyle.Render(fmt.Sprintf(
		"Network: %s\nKill-switch: %s\nConnectivity: %s\nInterface: %s",
		netLabel, ks, conn, valueOr(snap.Network.Interface, "-"),
	)))
	b.WriteString("\n\n")

	// Disk
	diskLine := fmt.Sprintf("tmpfs used %s / %s (free %s)",
		config.FormatSize(snap.Disk.Used),
		config.FormatSize(snap.Disk.Total),
		config.FormatSize(snap.Disk.Free),
	)
	if snap.Disk.Total == 0 {
		diskLine = "tmpfs: unavailable"
	} else if !snap.DiskOK {
		diskLine = warnStyle.Render(diskLine + " — LOW")
	} else {
		diskLine = okStyle.Render(diskLine)
	}
	b.WriteString(boxStyle.Render(diskLine))
	b.WriteString("\n\n")

	// Processes
	var procLines []string
	for _, p := range snap.Processes {
		status := critStyle.Render("DOWN")
		if p.Running {
			status = okStyle.Render("UP")
		}
		procLines = append(procLines, fmt.Sprintf("%-16s %s", p.Name, status))
	}
	if len(procLines) == 0 {
		procLines = append(procLines, mutedStyle.Render("no processes configured"))
	}
	b.WriteString(boxStyle.Render("Processes\n" + strings.Join(procLines, "\n")))
	b.WriteString("\n\n")

	// Alerts
	var alertLines []string
	src := m.recent
	if len(src) == 0 {
		src = snap.Alerts
		if len(src) > 8 {
			src = src[len(src)-8:]
		}
	}
	for i := len(src) - 1; i >= 0 && len(alertLines) < 8; i-- {
		alertLines = append(alertLines, styleAlert(src[i]))
	}
	if len(alertLines) == 0 {
		alertLines = append(alertLines, mutedStyle.Render("no alerts"))
	}
	b.WriteString(boxStyle.Render("Alerts\n" + strings.Join(alertLines, "\n")))
	b.WriteString("\n\n")
	b.WriteString(mutedStyle.Render("press q to quit and tear down secure mode"))

	return b.String()
}

func styleAlert(a monitor.Alert) string {
	ts := a.Time.Format("15:04:05")
	line := fmt.Sprintf("%s [%s] %s", ts, a.Kind, a.Message)
	switch a.Severity {
	case monitor.SeverityCritical:
		return critStyle.Render(line)
	case monitor.SeverityWarning:
		return warnStyle.Render(line)
	default:
		return mutedStyle.Render(line)
	}
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Run starts the Bubble Tea program.
func Run(mon *monitor.Monitor, onQuit func()) error {
	p := tea.NewProgram(New(mon, onQuit), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
