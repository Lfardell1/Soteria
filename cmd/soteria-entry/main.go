//go:build linux && amd64

package main

import (
	"fmt"
	"os"

	"github.com/Lfardell1/Soteria/internal/entrypoint"
)

func main() {
	if err := entrypoint.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "soteria-entry: workload verification or exec failed")
		os.Exit(125)
	}
}
