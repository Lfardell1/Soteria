//go:build !linux || !amd64

package session

import (
	"context"
	"strings"
	"testing"
)

func TestUnsupportedDoesNotAttemptAHostFallback(t *testing.T) {
	if code, err := Run(context.Background(), Request{}, Streams{}); code != InfrastructureFailure || err == nil || !strings.Contains(err.Error(), "Linux") {
		t.Fatalf("unsupported platform appeared to work: %d %v", code, err)
	}
	if err := Cleanup(context.Background(), "not even a valid ID", Streams{}); err == nil {
		t.Fatal("unsupported cleanup appeared to mutate the host")
	}
	if handled, code, err := Internal([]string{"__start"}); !handled || code != InfrastructureFailure || err == nil {
		t.Fatalf("unsupported internal helper appeared to work: %v %d %v", handled, code, err)
	}
	if handled, _, _ := Internal([]string{"doctor"}); handled {
		t.Fatal("public CLI command intercepted")
	}
}
