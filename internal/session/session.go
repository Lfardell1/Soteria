//go:build linux

// Package session serializes resource acquisition and cleanup. Stop only
// cancels the owner; it never tears down resources underneath a running stage.
package session

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Lfardell1/Soteria/internal/protocol"
)

type Phase string

const (
	Validating   Phase = "validating"
	Preparing    Phase = "preparing"
	NetworkReady Phase = "network-ready"
	Running      Phase = "running"
	Exporting    Phase = "exporting"
	Stopping     Phase = "stopping"
	Finished     Phase = "finished"
	Failed       Phase = "failed"
)

type cleanup struct {
	name  string
	close func() error
}
type Session struct {
	mu        sync.Mutex
	started   bool
	stopped   bool
	cancel    context.CancelFunc
	done      chan struct{}
	phase     Phase
	resources []cleanup
	result    protocol.Result
}

func New() *Session { return &Session{done: make(chan struct{}), phase: Validating} }

func (s *Session) Phase() Phase { s.mu.Lock(); defer s.mu.Unlock(); return s.phase }

func (s *Session) Advance(ctx context.Context, phase Phase) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.stopped {
		return context.Canceled
	}
	allowed := map[Phase]Phase{Validating: Preparing, Preparing: NetworkReady, NetworkReady: Running, Running: Exporting}
	if allowed[s.phase] != phase {
		return fmt.Errorf("invalid lifecycle transition %s -> %s", s.phase, phase)
	}
	s.phase = phase
	return nil
}

// Acquire is called by the sole Run owner. A partially acquired resource must
// return its cleanup even alongside an error, so registration is immediate.
func (s *Session) Acquire(ctx context.Context, name string, acquire func(context.Context) (func() error, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		return context.Canceled
	}
	close, err := acquire(ctx)
	if close != nil {
		s.resources = append(s.resources, cleanup{name, close})
	}
	return errors.Join(err, ctx.Err())
}

func (s *Session) Run(parent context.Context, work func(context.Context, *Session) protocol.Result) protocol.Result {
	s.mu.Lock()
	if s.started || s.stopped {
		s.mu.Unlock()
		return protocol.Result{Error: "session cannot be reused"}
	}
	s.started = true
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.mu.Unlock()
	result := work(ctx, s)
	if err := ctx.Err(); err != nil && result.Error == "" {
		result.Error = "session canceled; no export performed"
	}
	cancel()
	s.mu.Lock()
	s.phase = Stopping
	s.mu.Unlock()
	var cleanupErr error
	for i := len(s.resources) - 1; i >= 0; i-- {
		if err := s.resources[i].close(); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("%s: %w", s.resources[i].name, err))
		}
	}
	if cleanupErr != nil {
		result.CleanupError = cleanupErr.Error()
		result.Facts.Cleanup = "failed"
	} else {
		result.Facts.Cleanup = "completed"
	}
	s.mu.Lock()
	s.result = result
	if result.ExitCode() == 125 && (result.Error != "" || result.CleanupError != "" || !result.ChildStarted) {
		s.phase = Failed
	} else {
		s.phase = Finished
	}
	close(s.done)
	s.mu.Unlock()
	return result
}

func (s *Session) Stop() protocol.Result {
	s.mu.Lock()
	s.stopped = true
	if !s.started {
		s.result = protocol.Result{Error: "session canceled before start"}
		s.phase = Failed
		s.mu.Unlock()
		return s.result
	}
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()
	cancel()
	<-done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result
}
