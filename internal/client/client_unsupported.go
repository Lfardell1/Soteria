//go:build !linux || !amd64

package client

import (
	"context"
	"errors"
)

func Run(context.Context, Request, Streams) (int, error) {
	return InfrastructureExit, errors.New("sessions require the Linux amd64 backend; disposable VM backends are not implemented")
}

func Cleanup(context.Context, string, Streams) (int, error) {
	return InfrastructureExit, errors.New("cleanup requires the Linux amd64 backend")
}
