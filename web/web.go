package web

import (
  "context"
  "errors"
  "fmt"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "net"
  "os"
  "time"
)

var (
  // ErrFullAuthUnauthorized for empty key & bearer
  ErrFullAuthUnauthorized = errors.New("api key or bearer token empty")

  // ErrFullAuthUnauthorizedInvalidTokens for invalid key and bearer
  ErrFullAuthUnauthorizedInvalidTokens = errors.New("api key or bearer token invalid or missing")
)

// ServerOptions ...
type ServerOptions struct {
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
  TokenLocation     string `json:"tokenLocation" yaml:"tokenLocation"`
}

// CodeResponse == oidc successful login dao
type CodeResponse struct {
  AccessToken      string `json:"access_token" url:"accessToken"`
  ExpiresIn        int    `json:"expires_in" url:"expiresIn"`
  RefreshExpiresIn int    `json:"refresh_expires_in" url:"refresh_expires_in"`
  RefreshToken     string `json:"refresh_token" url:"refresh_token"`
  TokenType        string `json:"token_type" url:"token_type"`
  NotBeforePolicy  int    `json:"not-before-policy" url:"notBeforePolicy"`
  SessionState     string `json:"session_state" url:"sessionState"`
  Scope            string `json:"scope" url:"scope"`
}

// Server ...
type Server interface {
  Routes(func(s Server) error) Server
  // Run the server, return error
  Run() error
}

// Configuration ...
type Configuration[T any] func(s *T) error

// Keys gets JWKS
func Keys(issuer, jwksPath string) (jwk.Set, error) {
  ctx, cancel := context.WithCancel(context.Background())

  defer cancel()

  p := fmt.Sprintf("%s/%s", issuer, jwksPath)

  c := jwk.NewCache(ctx)

  if err := c.Register(p, jwk.WithMinRefreshInterval(30*time.Minute)); err != nil {
    return nil, err
  }

  keySet, err := c.Refresh(ctx, p)
  if err != nil {
    return nil, err
  }

  return keySet, err
}

// Adresses returns Adresses the server can bind to
func Adresses() []string {
  host, _ := os.Hostname()
  addresses, _ := net.LookupIP(host)

  hosts := []string{
    "127.0.0.1",
    "0.0.0.0",
  }

  for _, addr := range addresses {
    if ipv4 := addr.To4(); ipv4 != nil {
      hosts = append(hosts, ipv4.String())
    }
  }

  return hosts
}

func MkGeneric[T any]() *T {
  t := new(T)

  return t
}