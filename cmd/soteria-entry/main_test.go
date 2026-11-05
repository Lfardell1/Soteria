//go:build linux && amd64

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInvalidEntryReturnsInfrastructureFailureWithoutEchoingArgs(t *testing.T) {
	name, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(name, "-test.run=^TestEntryMainFixture$")
	command.Env = append(os.Environ(), "SOTERIA_ENTRY_MAIN_TEST=1")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	err = command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 125 || !strings.Contains(stderr.String(), "verification or exec failed") || strings.Contains(stderr.String(), "private-argument") {
		t.Fatalf("unexpected entrypoint error: %v %q", err, stderr.String())
	}
}

func TestEntryMainFixture(t *testing.T) {
	if os.Getenv("SOTERIA_ENTRY_MAIN_TEST") == "1" {
		os.Args = []string{"soteria-entry", "0", "0", "--", "/bin/bash", "private-argument"}
		main()
		t.Fatal("invalid entry unexpectedly returned success")
	}
}
