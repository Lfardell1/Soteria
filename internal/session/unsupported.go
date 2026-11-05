//go:build !linux || !amd64

package session

import (
	"context"
	"errors"
	"strings"
)

var errUnsupported = errors.New("the experimental session engine requires Linux amd64; other platforms need a separately validated Linux VM backend")

func Run(context.Context, Request, Streams) (int, error) {
	return InfrastructureFailure, errUnsupported
}

func Cleanup(context.Context, string, Streams) error { return errUnsupported }

func Internal(args []string) (bool, int, error) {
	if len(args) > 0 && strings.HasPrefix(args[0], "__") {
		return true, InfrastructureFailure, errUnsupported
	}
	return false, 0, nil
}
