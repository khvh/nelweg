package web

import (
  "context"
  "embed"
  "encoding/json"
  "fmt"
  "github.com/khvh/nelweg/logger"
  "github.com/khvh/nelweg/queue"
  "github.com/khvh/nelweg/telemetry"
  "github.com/hashicorp/consul/api"
  "github.com/hibiken/asynq"
  "github.com/labstack/echo/v4"
  "io"
  "io/fs"
  "net"
  "net/http"
  "net/url"
  "os"
  "os/exec"
  "reflect"
  "strings"

  gonanoid "github.com/matoous/go-nanoid/v2"

  "github.com/go-playground/validator/v10"
  "github.com/imdario/mergo"
  "github.com/labstack/echo-contrib/prometheus"
  "github.com/labstack/echo/v4/middleware"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/rs/zerolog/log"
  "github.com/swaggest/openapi-go/openapi3"
  "go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
  "go.opentelemetry.io/otel"
)

// Validator ...
type Validator struct {
  validator *validator.Validate
}

// Validate ...
func (v *Validator) Validate(i any) error {
  if err := v.validator.Struct(i); err != nil {
    return err
  }

  return nil
}

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
}

// Server ...
type Server struct {
  e            *echo.Echo
  groups       map[string][]*Spec
  ref          *openapi3.Reflector
  opts         *ServerOptions
  oidc         *OIDCOptions
  jwks         jwk.Set
  qRef         *queue.Queue
  consulClient *api.Client
}

// Configuration ...
type Configuration func(s *Server) error

// New constructs Server
func New(cfgs ...Configuration) *Server {
  s := &Server{
    groups: make(map[string][]*Spec),
    opts:   createDefaults(),
  }

  for _, cfg := range cfgs {
    if err := cfg(s); err != nil {
      log.Fatal().Err(fmt.Errorf("apply server configuration %w", err)).Send()

      return nil
    }
  }

  if s.e == nil {
    s.e = CreateEchoInstance(s.opts.HideBanner)
  }

  refOpts := &ReflectorOptions{
    Servers:     addresses(),
    Port:        s.opts.Port,
    Title:       s.opts.ID + "-api",
    Description: s.opts.Description,
    Version:     s.opts.Version,
    APIKeyAuth:  false,
  }

  if s.oidc != nil {
    refOpts.OpenAPIAuthorizationURL = fmt.Sprintf("%s/%s", s.oidc.Issuer, s.oidc.AuthURI)
  }

  s.ref = CreateReflector(refOpts)

  return s
}

// WithConfig ...
func WithConfig(opts ServerOptions) Configuration {
  return func(s *Server) error {
    s.opts = createDefaults(*s.opts, opts)

    return nil
  }
}

// WithDefaultMiddleware ...
func WithDefaultMiddleware() Configuration {
  return func(s *Server) error {
    if s.e == nil {
      s.e = CreateEchoInstance(s.opts.HideBanner)
    }

    s.e.Use(middleware.RequestID())
    s.e.Use(middleware.CORS())
    s.e.Use(middleware.Recover())

    return nil
  }
}

// WithRequestLogger ...
func WithRequestLogger() Configuration {
  return func(s *Server) error {
    if s.e == nil {
      s.e = CreateEchoInstance(s.opts.HideBanner)
    }

    s.e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
      LogURI:    true,
      LogStatus: true,
      LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
        log.Trace().
          Str("method", c.Request().Method).
          Int("code", v.Status).
          Str("uri", v.URI).
          Str("from", c.Request().RemoteAddr).
          Send()

        return nil
      },
    }))

    return nil
  }
}

// WithTracing ...
func WithTracing(url ...string) Configuration {
  return func(s *Server) error {
    if s.e == nil {
      s.e = CreateEchoInstance(s.opts.HideBanner)
    }

    id := strings.ReplaceAll(s.opts.ID, "-", "_")
    u := "http://localhost:14268/api/traces"

    otel.Tracer(id)

    if len(url) > 0 {
      u = url[0]
    }

    telemetry.New(id, u)

    s.e.Use(otelecho.Middleware(id))

    return nil
  }
}

func (s *Server) startYarnDev(dir string) {
  cmd := exec.Command("yarn", "dev")

  cmd.Dir = dir

  out, err := cmd.Output()

  log.Trace().Err(err).Bytes("out", out).Send()
}

func (s *Server) buildYarn(dir string) {
  cmd := exec.Command("yarn", "build")

  cmd.Dir = dir

  out, err := cmd.Output()

  log.Trace().Err(err).Bytes("out", out).Send()
}

// WithFrontend ...
func WithFrontend(data embed.FS, dir string) Configuration {
  return func(s *Server) error {
    if s.e == nil {
      s.e = CreateEchoInstance(s.opts.HideBanner)
    }

    dev := s.opts.Env == "dev"

    if dev {
      go s.startYarnDev(dir)

      fePort := 3000

      file, err := os.ReadFile(dir + "/../package.json")
      if err != nil {
        log.Trace().Err(err).Send()
      }

      var packageJson map[string]interface{}

      err = json.Unmarshal(file, &packageJson)
      if err != nil {
        log.Trace().Err(err).Send()
      } else {
        fePort = int(packageJson["devPort"].(float64))
      }

      u, err := url.Parse(fmt.Sprintf("http://localhost:%d", fePort))

      //s.e.Use(middleware.Proxy(middleware.NewRoundRobinBalancer([]*middleware.ProxyTarget{{URL: u}})))

      rrb := middleware.NewRoundRobinBalancer([]*middleware.ProxyTarget{{URL: u}})

      s.e.Use(middleware.ProxyWithConfig(middleware.ProxyConfig{
        Balancer:   rrb,
        ContextKey: "target",
        Skipper: func(c echo.Context) bool {
          p := c.Request().URL.Path

          if strings.HasPrefix(p, "/monitoring") ||
            strings.HasPrefix(p, "/docs") ||
            strings.HasPrefix(p, "/spec") ||
            strings.HasPrefix(p, "/metrics") ||
            strings.HasPrefix(p, "/health") ||
            strings.HasPrefix(p, "/_internal") ||
            strings.HasPrefix(p, "/api") {
            return true
          }

          return false
        },
      }))
    } else {
      fsContent := getFileSystem(data, dir, dev)

      s.e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
        Filesystem: fsContent,
        HTML5:      true,
        Skipper: func(c echo.Context) bool {
          p := c.Request().URL.Path

          if strings.HasPrefix(p, "/monitoring") ||
            strings.HasPrefix(p, "/docs") ||
            strings.HasPrefix(p, "/spec") ||
            strings.HasPrefix(p, "/metrics") ||
            strings.HasPrefix(p, "/health") ||
            strings.HasPrefix(p, "/_internal") ||
            strings.HasPrefix(p, "/api") {
            return true
          }

          return false
        },
      }))
    }

    return nil
  }
}

// WithMetrics ...
func WithMetrics() Configuration {
  return func(s *Server) error {
    if s.e == nil {
      s.e = CreateEchoInstance(s.opts.HideBanner)
    }

    prometheus.NewPrometheus(strings.ReplaceAll(s.opts.ID, "-", "_"), nil).Use(s.e)

    return nil
  }
}

// WithQueue ...
func WithQueue(url, pw string, opts queue.Queues, fn func(q *queue.Queue)) Configuration {
  return func(s *Server) error {
    if s.e == nil {
      s.e = CreateEchoInstance(s.opts.HideBanner)
    }

    q, mon := queue.
      CreateServer(url, 60, opts).
      MountMonitor("127.0.0.1:6379", "")

    s.e.Any("/monitoring/tasks/*", echo.WrapHandler(mon))

    fn(q)

    s.qRef = q.Run()

    log.Trace().Msgf("Asynq running on http://0.0.0.0:%d/monitoring/tasks", s.opts.Port)

    return nil
  }
}

// WithLogging ...
func WithLogging() Configuration {
  return func(s *Server) error {
    logger.Init(s.opts.LogLevel, s.opts.Env == "dev", s.opts.ID)

    return nil
  }
}

// WithOIDC enables OpenID Connect auth
func WithOIDC(opts OIDCOptions) Configuration {
  return func(s *Server) error {
    if s.e == nil {
      s.e = CreateEchoInstance(s.opts.HideBanner)
    }

    s.oidc = &opts

    keySet, err := keys(opts.Issuer, opts.KeysURI)
    if err != nil {
      log.Err(err).Send()

      return nil
    }

    s.jwks = keySet

    s.mountAuthEndpoints()

    return nil
  }
}

// WithMiddleware add middleware to Echo
func WithMiddleware(middleware ...echo.MiddlewareFunc) Configuration {
  return func(s *Server) error {
    if s.e == nil {
      s.e = CreateEchoInstance(s.opts.HideBanner)
    }

    s.e.Use(middleware...)

    return nil
  }
}

// WithServiceMesh register the API with a service mesh (Consul for now)
func WithServiceMesh(meshType string, address string) Configuration {
  return func(s *Server) error {
    if meshType == "consul" {
      client, err := api.NewClient(api.DefaultConfig())
      if err != nil {
        return err
      }

      if err := client.Agent().ServiceRegister(&api.AgentServiceRegistration{
        ID:   s.opts.ID,
        Name: s.opts.ID,
        Port: s.opts.Port,
      }); err != nil {
        return err
      }

      s.consulClient = client
    }

    return nil
  }
}

// Group ...
func (s *Server) Group(path string, specs ...*Spec) *Server {
  s.groups[path] = specs

  return s
}

func (s *Server) processSpecs() *Server {
  for k, v := range s.groups {
    for _, spec := range v {
      spec.PathPrefix = k

      if err := spec.Build(s.ref); err != nil {
        log.Err(err).Send()
      }

      if spec.Auth {
        spec.Route.middleware = append(spec.Route.middleware, func(next echo.HandlerFunc) echo.HandlerFunc {
          return func(c echo.Context) error {
            claims, err := s.ValidateJWTToken(c.Request().Context(), strings.ReplaceAll(c.Request().Header.Get("authorization"), "Bearer ", ""))
            if err != nil {
              log.Debug().Err(err).Send()
              return c.JSON(http.StatusUnauthorized, nil)
            }

            c.Set("claims", claims)

            return next(c)
          }
        })
      }

      switch spec.Method {
      case MethodGet:
        s.e.GET(spec.FullRouterPath(), spec.Route.handler, spec.Route.middleware...)
      case MethodDelete:
        s.e.DELETE(spec.FullRouterPath(), spec.Route.handler, spec.Route.middleware...)
      case MethodPost:
        s.e.POST(spec.FullRouterPath(), spec.Route.handler, spec.Route.middleware...)
      case MethodPut:
        s.e.PUT(spec.FullRouterPath(), spec.Route.handler, spec.Route.middleware...)
      case MethodPatch:
        s.e.PATCH(spec.FullRouterPath(), spec.Route.handler, spec.Route.middleware...)
      }
    }
  }

  return s
}

func (s *Server) build() *Server {
  yamlBytes, err := s.ref.Spec.MarshalYAML()
  if err != nil {
    log.Err(err).Send()

    return s
  }

  s.e.GET("/spec/spec.yaml", func(c echo.Context) error {
    return c.Blob(200, "application/openapi+yaml", yamlBytes)
  })

  s.e.GET("/spec/spec.yml", func(c echo.Context) error {
    return c.Blob(200, "application/openapi+yaml", yamlBytes)
  })

  jsonBytes, err := s.ref.Spec.MarshalJSON()
  if err != nil {
    log.Err(err).Send()

    return s
  }

  s.e.GET("/spec/spec.json", func(c echo.Context) error {
    return c.Blob(200, "application/openapi+json", jsonBytes)
  })

  s.e.GET("/_runtask", func(c echo.Context) error {

    queue.NewClient("127.0.0.1:6379").Add(asynq.NewTask("srv:info", nil), asynq.Queue("critical"))

    return c.JSON(200, nil)
  })

  return s
}

//go:embed docs
var content embed.FS

// Run starts the server
func (s *Server) Run() {
  s.processSpecs().build()

  fsContent := getFileSystem(content, "docs", s.opts.Env == "dev")
  assetHandler := http.FileServer(fsContent)

  s.e.Any("/docs", echo.WrapHandler(http.StripPrefix("/docs", assetHandler)))
  s.e.Any("/docs/*", echo.WrapHandler(http.StripPrefix("/docs", assetHandler)))

  s.e.Any("/oauth-receiver.html*", func(c echo.Context) error {
    return c.Redirect(http.StatusTemporaryRedirect, "/docs"+c.Request().RequestURI)
  })

  for _, host := range addresses() {
    log.
      Info().
      Str("id", s.opts.ID).
      Str("URL", fmt.Sprintf("http://%s:%d", host, s.opts.Port)).
      Str("OpenAPI", fmt.Sprintf("http://%s:%d/docs", host, s.opts.Port)).
      Send()
  }

  log.Info().Str("server", s.opts.ID).Send()

  log.Err(s.e.Start(fmt.Sprintf("%s:%d", s.opts.Host, s.opts.Port))).Send()
  go func() {
  }()
}

// Stop ...
func (s *Server) Stop(ctx context.Context) error {
  if s.consulClient != nil {
    if err := s.consulClient.Agent().ServiceDeregister(s.opts.ID); err != nil {
      log.Trace().Err(err).Send()
    }
  }

  if s.qRef != nil {
    s.qRef.Stop()
  }

  if err := s.Stop(ctx); err != nil {
    log.Fatal().Err(err).Send()
  }

  return s.e.Shutdown(ctx)
}

// Get ...
func Get[T any](path string, handler echo.HandlerFunc, mw ...echo.MiddlewareFunc) *Spec {
  return GetOp(path, mkGeneric[T](), WithRoute(&Route{
    handler:    handler,
    middleware: mw,
  }))
}

// Delete ...
func Delete[T any](path string, handler echo.HandlerFunc, mw ...echo.MiddlewareFunc) *Spec {
  return DeleteOp(path, mkGeneric[T](), WithRoute(&Route{
    handler:    handler,
    middleware: mw,
  }))
}

// Post ...
func Post[T, B any](path string, handler echo.HandlerFunc, mw ...echo.MiddlewareFunc) *Spec {
  return PostOp(path, mkGeneric[B](), mkGeneric[T](), WithRoute(&Route{
    handler:    handler,
    middleware: mw,
    bodyType:   reflect.TypeOf(mkGeneric[B]()),
  }))
}

// Patch ...
func Patch[T, B any](path string, handler echo.HandlerFunc, mw ...echo.MiddlewareFunc) *Spec {
  return PatchOp(path, mkGeneric[B](), mkGeneric[T](), WithRoute(&Route{
    handler:    handler,
    middleware: mw,
  }))
}

// Put ...
func Put[T, B any](path string, handler echo.HandlerFunc, mw ...echo.MiddlewareFunc) *Spec {
  return PutOp(path, mkGeneric[B](), mkGeneric[T](), WithRoute(&Route{
    handler:    handler,
    middleware: mw,
  }))
}

func getFileSystem(embededFiles embed.FS, dir string, isDev bool) http.FileSystem {
  sub, err := fs.Sub(embededFiles, dir)
  if err != nil {
    log.Fatal().Err(err).Send()
  }

  return http.FS(sub)
}

func CreateEchoInstance(hideBanner bool) *echo.Echo {
  e := echo.New()

  e.HideBanner = hideBanner
  e.HidePort = hideBanner
  e.Validator = &Validator{validator: validator.New()}

  return e
}

func createDefaults(opts ...ServerOptions) *ServerOptions {
  id, err := gonanoid.New()
  if err != nil {
    log.Err(err).Send()
  }

  defaults := ServerOptions{
    ID:            id,
    Port:          1234,
    Host:          "0.0.0.0",
    HideBanner:    true,
    RequestLogger: false,
    Version:       "1.0",
    LogLevel:      -1,
    Env:           "dev",
  }

  for _, opt := range opts {
    if err := mergo.Merge(&defaults, opt, mergo.WithSliceDeepCopy); err != nil {
      log.Fatal().Err(fmt.Errorf("merge server options: %w", err)).Send()
    }
  }

  return &defaults
}

// APIError ...
func APIError(c echo.Context, statusCode int, err ...*Error) error {
  if len(err) > 0 {
    return c.JSON(statusCode, err)
  }

  return c.JSON(statusCode, Err(fmt.Sprintf("E_%d", statusCode)))
}

// addresses returns addresses the server can bind to
func addresses() []string {
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

func mkGeneric[T any]() *T {
  t := new(T)

  return t
}
