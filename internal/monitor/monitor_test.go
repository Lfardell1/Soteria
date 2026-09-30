package monitor

import (
	"os"
	"testing"
	"time"

	"github.com/Lfardell1/Soteria/internal/config"
)

func TestFindPIDsSelf(t *testing.T) {
	// Our own process should be findable by a unique-ish name substring.
	// Use "soteria" only if binary name matches; fall back to checking init or go test binary.
	pids := FindPIDs("go")
	// In `go test`, the binary may be named after the package. At least ensure function runs.
	_ = pids

	selfComm, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	name := string(selfComm)
	if len(name) > 0 && name[len(name)-1] == '\n' {
		name = name[:len(name)-1]
	}
	found := FindPIDs(name)
	if len(found) == 0 {
		t.Fatalf("expected to find self process %q", name)
	}
}

func TestMonitorEmitsProcessDown(t *testing.T) {
	cfg := config.Default()
	cfg.Network.KillSwitch = false
	cfg.Monitoring.Processes = []string{"this-process-should-not-exist-xyz"}
	cfg.Monitoring.PollIntervalSeconds = 1
	cfg.Network.CheckConnectivity = false

	m := New(cfg, nil, nil, 8)
	done := make(chan struct{})
	go func() {
		m.tick()
		close(done)
	}()

	select {
	case a := <-m.Alerts():
		if a.Kind != ProcessDown {
			t.Fatalf("expected ProcessDown, got %s", a.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for alert")
	}
	<-done
}
