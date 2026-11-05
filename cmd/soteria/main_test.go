package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPublicEntrypoint(t *testing.T) {
	for _, tc := range []struct {
		command string
		code    int
		output  string
	}{
		{"version", 0, "runtime digest: sha256:test-runtime"},
		{"help", 0, "--network wireguard --profile NAME"},
		{"__worker", 2, "unknown command"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEntrypointProcess$")
			cmd.Env = append(os.Environ(), "SOTERIA_ENTRYPOINT_TEST="+tc.command)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.code || !strings.Contains(stdout.String()+stderr.String(), tc.output) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, &stdout, &stderr)
			}
			if tc.command == "version" && (!strings.Contains(stdout.String(), "1.2.3-test") || !strings.Contains(stdout.String(), "commit: test-commit")) {
				t.Fatal("main build metadata was not wired to the CLI")
			}
		})
	}
}

func TestEntrypointProcess(t *testing.T) {
	command := os.Getenv("SOTERIA_ENTRYPOINT_TEST")
	if command == "" {
		return
	}
	version, commit, runtimeDigest = "1.2.3-test", "test-commit", "sha256:test-runtime"
	os.Args = []string{"soteria", command}
	main()
}
