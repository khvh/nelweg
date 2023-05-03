package server

import (
	"context"
	"fmt"

	"github.com/khvh/nelweg"
	"github.com/rs/zerolog/log"
)

// Mock ...
type Mock struct{}

// MockBuilder ...
type MockBuilder struct {
	cfgs   []Config[*Mock]
	server *Mock
}

// NewMockBuilder ...
func NewMockBuilder() *MockBuilder {
	return &MockBuilder{}
}

// Server ...
func (b *MockBuilder) Server() *Mock {
	b.server = NewMock(b.cfgs...)

	return b.server
}

func (b *MockBuilder) add(cfg Config[*Mock]) *MockBuilder {
	b.cfgs = append(b.cfgs, cfg)

	return b
}

// WithConfig ...
func (b *MockBuilder) WithConfig(...Options) *MockBuilder {
	return b.add(func(s *Mock) error {
		return nil
	})
}

// NewMock ...
func NewMock(cfgs ...Config[*Mock]) *Mock {
	s := &Mock{}

	for _, cfg := range cfgs {
		if err := cfg(s); err != nil {
			log.Fatal().Err(fmt.Errorf("apply server configuration %w", err)).Send()

			return nil
		}
	}

	return s
}

// Group creates a new spec group
func (s *Mock) Group(_ string, _ ...*nelweg.Spec) Server {
	return s
}

// Run starts the server
func (s *Mock) Run() error {
	return nil
}

// Stop stops the server
func (s *Mock) Stop(_ context.Context) error {
	return nil
}
