//go:build linux && amd64

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Lfardell1/Soteria/internal/protocol"
)

func TestBubblewrapStatusRequiresExactLaunchThenExit(t *testing.T) {
	for _, test := range []struct {
		name    string
		stream  string
		count   int
		invalid bool
	}{
		{"success", `{"child-pid":1234,"mnt-namespace":4000,"pid-namespace":4001} {"exit-code":0}`, 2, false},
		{"signaled", "{\"child-pid\":1234}\n{\"exit-code\":143}\n", 2, false},
		{"setup failure", `{"child-pid":1234}`, 1, false},
		{"no setup", "", 0, false},
		{"exit first", `{"exit-code":0}`, 0, true},
		{"duplicate pid", `{"child-pid":1234,"child-pid":4321}`, 0, true},
		{"case alias", `{"Child-Pid":1234}`, 0, true},
		{"mixed", `{"child-pid":1234,"exit-code":0}`, 0, true},
		{"root pid", `{"child-pid":1}`, 0, true},
		{"invalid pid", `{"child-pid":-12}`, 0, true},
		{"unknown field", `{"child-pid":1234,"caller_pid":99}`, 0, true},
		{"out of range", `{"child-pid":1234}{"exit-code":256}`, 1, true},
		{"negative exit", `{"child-pid":1234}{"exit-code":-1}`, 1, true},
		{"duplicate launch", `{"child-pid":1234}{"child-pid":1234}`, 1, true},
		{"third document", `{"child-pid":1234}{"exit-code":0}{"exit-code":0}`, 2, true},
		{"truncated", `{"child-pid":`, 0, true},
		{"null", `{"child-pid":null}`, 0, true},
		{"oversized", `{"child-pid":` + strings.Repeat("1", 20<<10) + "}", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var count int
			var invalid bool
			for event := range readBubblewrapStatus(strings.NewReader(test.stream)) {
				if event.err != nil {
					invalid = !errors.Is(event.err, io.EOF)
					break
				}
				count++
			}
			if count != test.count || invalid != test.invalid {
				t.Fatalf("count=%d invalid=%v, want %d %v", count, invalid, test.count, test.invalid)
			}
		})
	}
}

func TestPayloadExportRequiresEveryQuiescenceAndSuccessCondition(t *testing.T) {
	good := payloadResult{started: true, code: 0, quiescent: true}
	if !good.exportable() {
		t.Fatal("verified successful quiescent payload cannot export")
	}
	for _, mutate := range []func(*payloadResult){
		func(r *payloadResult) { r.started = false },
		func(r *payloadResult) { r.code = 17 },
		func(r *payloadResult) { r.code = 125 },
		func(r *payloadResult) { r.code = 143 },
		func(r *payloadResult) { r.err = context.Canceled },
		func(r *payloadResult) { r.cleanupErr = errors.New("adopted writer remains") },
		func(r *payloadResult) { r.quiescent = false },
		func(r *payloadResult) { r.signaled = true },
	} {
		result := good
		mutate(&result)
		if result.exportable() {
			t.Fatalf("unsafe export was authorized: %+v", result)
		}
	}
	result := protocol.Result{ChildStarted: true, ChildExit: 17, CleanupError: "descendant cleanup failed"}
	if result.ExitCode() != InfrastructureFailure || result.ChildExit != 17 || !result.ChildStarted {
		t.Fatal("cleanup failure erased the distinct child's exit status")
	}
}

func TestSupervisorMessagesHavePerOperationShapes(t *testing.T) {
	valid := []namespaceMessage{
		{Version: protocolVersion, Kind: "run"},
		{Version: protocolVersion, Kind: "cancel"},
		{Version: protocolVersion, Kind: "network"},
		{Version: protocolVersion, Kind: "network", Link: "st0123456789abc"},
		{Version: protocolVersion, Kind: "resize", Rows: 24, Cols: 80},
		{Version: protocolVersion, Kind: "export-result"},
		{Version: protocolVersion, Kind: "export-result", Code: InfrastructureFailure, Text: "partial output"},
	}
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		valid = append(valid, namespaceMessage{Version: protocolVersion, Kind: "signal", Signal: int(signal)})
	}
	for _, message := range valid {
		if err := validateSupervisorMessage(message); err != nil {
			t.Errorf("valid message rejected: %+v %v", message, err)
		}
	}
	invalid := []namespaceMessage{
		{Kind: "run"},
		{Version: protocolVersion, Kind: "run", Text: "unexpected"},
		{Version: protocolVersion, Kind: "run", Plan: &namespacePlan{}},
		{Version: protocolVersion, Kind: "run", Result: &protocol.Result{}},
		{Version: protocolVersion, Kind: "network", Facts: &protocol.Facts{}},
		{Version: protocolVersion, Kind: "network", Link: strings.Repeat("a", 16)},
		{Version: protocolVersion, Kind: "signal", Signal: int(syscall.SIGKILL)},
		{Version: protocolVersion, Kind: "signal", Signal: int(syscall.SIGINT), Rows: 24},
		{Version: protocolVersion, Kind: "resize", Rows: 24},
		{Version: protocolVersion, Kind: "resize", Cols: 80},
		{Version: protocolVersion, Kind: "resize", Rows: 24, Cols: 80, Link: "stother"},
		{Version: protocolVersion, Kind: "export-result", Code: 17},
		{Version: protocolVersion, Kind: "export-result", Text: "success cannot carry an error"},
		{Version: protocolVersion, Kind: "cancel", Code: 125},
		{Version: protocolVersion, Kind: "facts"},
	}
	for _, message := range invalid {
		if err := validateSupervisorMessage(message); err == nil {
			t.Errorf("invalid message accepted: %+v", message)
		}
	}
}

func TestSupervisorRecordsSignalAndCancelsActiveExport(t *testing.T) {
	connection, peer, err := socketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	defer peer.Close()
	sender, err := connectionFromFile(peer)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	state := &supervisorControl{}
	state.exporting.Store(true)
	_ = monitorSupervisor(ctx, connection, cancel, state)
	writer := packetWriter{connection: sender}
	if err := writer.send(namespaceMessage{Version: protocolVersion, Kind: "signal", Signal: int(syscall.SIGINT)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		if !state.signaled.Load() || !strings.Contains(context.Cause(ctx).Error(), "during export") {
			t.Fatalf("signal receipt was not preserved: %v", context.Cause(ctx))
		}
	case <-time.After(time.Second):
		t.Fatal("active export was not canceled on signal receipt")
	}
}

func TestNamespaceUsesRealLifecycleOwnerEvenWhenAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(context.Canceled)
	result := executeNamespace(ctx, serviceEnvironment{}, namespacePlan{}, nil, nil, nil, cancel, &supervisorControl{})
	if result.ChildStarted || result.Error == "" || result.Facts.Cleanup != "completed" || result.CleanupError != "" || result.ExitCode() != InfrastructureFailure {
		t.Fatalf("canceled owner acquired resources or lost lifecycle cleanup facts: %+v", result)
	}
}

func TestClosingNamespaceStreamsRevokesEachAuthorityOnce(t *testing.T) {
	files := make([]*os.File, 5)
	for i := range files {
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		files[i] = read
		defer write.Close()
	}
	defer closeNamespaceFiles(files)
	if err := closeNamespaceFiles(files); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, make([]*os.File, 5)) {
		t.Fatal("closed stream authorities were retained")
	}
	if err := closeNamespaceFiles(files); err != nil {
		t.Fatalf("idempotent close tried to close a reused descriptor: %v", err)
	}
}

func TestProcessStartTimeIsNotConfusedByComms(t *testing.T) {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = "S", "12345"
	for _, comm := range []string{"normal", "spaces in comm", "ends) with) parentheses", "new\nline"} {
		stat := fmt.Sprintf("1234 (%s) %s", comm, strings.Join(fields, " "))
		start, err := processStart(stat, 1234)
		if err != nil || start != 12345 {
			t.Fatalf("comm confused kernel start-time parsing: %q %d %v", comm, start, err)
		}
	}
	for _, stat := range []string{"", "1234 () S 0", "4321 (other) " + strings.Join(fields, " "), "1234 (invalid " + strings.Join(fields, " ")} {
		if _, err := processStart(stat, 1234); err == nil {
			t.Errorf("accepted invalid process stat %q", stat)
		}
	}
}

func FuzzBubblewrapStatus(f *testing.F) {
	f.Add(`{"child-pid":1234}{"exit-code":0}`)
	f.Add(`{"child-pid":1}`)
	f.Fuzz(func(t *testing.T, stream string) {
		for range readBubblewrapStatus(strings.NewReader(stream)) {
		}
	})
}

func FuzzProcessStart(f *testing.F) {
	f.Add("1 (init) S 0")
	f.Fuzz(func(t *testing.T, stat string) { _, _ = processStart(stat, 1234) })
}
