package server

import (
	"context"

	"github.com/khvh/nelweg"
	"github.com/khvh/nelweg/queue"
)

// Options ...
type Options struct {
	ID            string `json:"id,omitempty" yaml:"id,omitempty"`
	Description   string `json:"description,omitempty" yaml:"description,omitempty"`
	Version       string `json:"version,omitempty" yaml:"version,omitempty"`
	Host          string `json:"host,omitempty" yaml:"host,omitempty"`
	Port          int    `json:"port,omitempty" yaml:"port,omitempty"`
	HideBanner    bool   `json:"hideBanner,omitempty" yaml:"hideBanner,omitempty"`
	RequestLogger bool   `json:"requestLogger,omitempty" yaml:"requestLogger,omitempty"`
	LogLevel      int    `json:"logLevel,omitempty" yaml:"logLevel,omitempty"`
	Env           string `json:"env,omitempty" yaml:"env,omitempty"`
}

// OIDCOptions ...
type OIDCOptions struct {
	Issuer            string `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	AuthURI           string `json:"authUri,omitempty" yaml:"authUri,omitempty"`
	KeysURI           string `json:"keysURI,omitempty" yaml:"keysURI,omitempty"`
	TokenURI          string `json:"tokenURI,omitempty" yaml:"tokenURI,omitempty"`
	ClientID          string `json:"clientId,omitempty" yaml:"clientId,omitempty"`
	Secret            string `json:"secret,omitempty" yaml:"secret,omitempty"`
	RedirectURI       string `json:"redirectURI,omitempty" yaml:"redirectURI,omitempty"`
	ClientRedirectURI string `json:"clientRedirectURI,omitempty" yaml:"clientRedirectURI,omitempty"`
}

// Server represents the abstact server which can be implemented
type Server interface {
	// Group creates a new spec group
	Group(string, ...*nelweg.Spec) Server

	// Run starts the server
	Run() error

	// Stop stops the server
	Stop(context.Context) error
}

// Config ...
type Config[T Server] func(s T) error

// Builder ...
type Builder interface {
	With(cfg Config[Server]) *Builder
	WithConfig(...Options) *Builder
	WithDefaultMiddleware() *Builder
	WithRequestLogger() *Builder
	WithTracing(string) *Builder
	WithMetrics(string) *Builder
	WithQueue(string, string, queue.Queues, func(q *queue.Queue)) *Builder
	WithLogging() *Builder
	WithAuth(OIDCOptions) *Builder
	Server() Server
	add(cfg Config[Server]) *Builder
}

/**

server.
	MockBuilder().
	WithBlah().
	WithLog().
	Server().
	Run()

	fib := server.FiberBuilder()

	server.New(
		fib.WithMetrics(),
		fib.WithLogging()
	).Run()

*/
