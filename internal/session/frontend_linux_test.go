//go:build linux && amd64

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestHeadlessStdioPipesAndTailDrain(t *testing.T) {
	var output, diagnostics bytes.Buffer
	streams := normalizeStreams(Streams{In: strings.NewReader("input data"), Out: &output, Err: &diagnostics})
	bridge, err := newFrontendIO(false, streams)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()
	if err := bridge.start(streams); err != nil {
		t.Fatal(err)
	}
	input, err := io.ReadAll(bridge.service[0])
	if err != nil || string(input) != "input data" {
		t.Fatalf("headless stdin missing EOF/data: %q %v", input, err)
	}
	_, _ = bridge.service[1].Write([]byte("output tail"))
	_, _ = bridge.service[2].Write([]byte("diagnostic tail"))
	bridge.releaseServiceFiles()
	if err := bridge.drain(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "output tail" || diagnostics.String() != "diagnostic tail" {
		t.Fatalf("stdio truncated: out=%q err=%q", &output, &diagnostics)
	}
}

func TestInteractiveDoesNotPretendAPipeIsATerminal(t *testing.T) {
	if _, err := newFrontendIO(true, normalizeStreams(Streams{In: strings.NewReader(""), Out: io.Discard})); err == nil {
		t.Fatal("interactive mode accepted no terminal")
	}
}

func TestCanceledNamespaceDoesNotReachMountOrProcessBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code, err := executeNamespace(ctx, serviceEnvironment{}, namespacePlan{}, nil, nil, nil, nil); code != InfrastructureFailure || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled namespace setup progressed: %d %v", code, err)
	}
	if code, err := superviseNamespace(ctx, serviceEnvironment{}, identity{}, wireRequest{}, nil, nil, nil, nil, nil); code != InfrastructureFailure || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled supervisor acquired namespace process: %d %v", code, err)
	}
}

func TestInternalEntrypointsRejectBuildTreeExecution(t *testing.T) {
	handled, code, err := Internal([]string{"__worker"})
	if !handled || code != InfrastructureFailure || err == nil {
		t.Fatalf("privileged internal entrypoint accepted unauthenticated build tree: %v %d %v", handled, code, err)
	}
	if handled, _, _ := Internal([]string{"doctor"}); handled {
		t.Fatal("public CLI command intercepted")
	}
	if os.Getuid() == 0 {
		if err := frontendIdentity(context.Background()); err == nil {
			t.Fatal("root frontend accepted")
		}
	}
}
