package main

import (
	"context"
	"os"

	"github.com/Lfardell1/Soteria/internal/buildinfo"
	"github.com/Lfardell1/Soteria/internal/cli"
	"github.com/Lfardell1/Soteria/internal/client"
)

var (
	version       string
	commit        string
	runtimeDigest string
)

func main() {
	// Preserve scripts/build.sh's main.* symbols without masking buildinfo -X values.
	if version != "" {
		buildinfo.Version = version
	}
	if commit != "" {
		buildinfo.Commit = commit
	}
	if runtimeDigest != "" {
		buildinfo.RuntimeDigest = runtimeDigest
	}
	os.Exit(cli.Run(context.Background(), os.Args[1:], client.Streams{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}))
}
