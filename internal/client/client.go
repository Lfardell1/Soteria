// Package client implements the unprivileged side of a one-shot Soteria session.
package client

import (
	"os"

	"github.com/Lfardell1/Soteria/internal/config"
)

const InfrastructureExit = 125

// Request contains host transfer paths only on the caller side. They are never
// sent to the starter or supervisor, nor included in their argv or environment.
type Request struct {
	Config          config.Config
	Argv            []string
	Imports         []string
	ExportDirectory string
	RequireTTY      bool
}

type Streams struct {
	In  *os.File
	Out *os.File
	Err *os.File
}
