package nelweg

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"github.com/hashicorp/consul/api"
	"github.com/hibiken/asynq"
	"github.com/khvh/nelweg/logger"
	"github.com/khvh/nelweg/queue"
	"github.com/khvh/nelweg/telemetry"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/samber/lo"

	gonanoid "github.com/matoous/go-nanoid/v2"

	echoPrometheus "github.com/globocom/echo-prometheus"
	"github.com/go-playground/validator/v10"
	"github.com/imdario/mergo"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"github.com/swaggest/openapi-go/openapi3"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/otel"
)

// Template ...
type Template struct {
	templates *template.Template
}

// Render ...
func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

// TemplateSpec ...
type TemplateSpec struct {
	Method     Method
	Path       string
	Handler    echo.HandlerFunc
	Middleware []echo.MiddlewareFunc
}

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

// ValidateKey is def for validating API Keys
type ValidateKey func(key string) (map[string]any, error)

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
	Templates     string `json:"templates,omitempty" yaml:"templates,omitempty"`
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

// EchoServer ...
type EchoServer struct {
	e            *echo.Echo
	groups       map[string][]*Spec
	ref          *openapi3.Reflector
	opts         *ServerOptions
	oidc         *OIDCOptions
	jwks         jwk.Set
	qRef         *queue.Queue
	consulClient *api.Client
	keyValidator ValidateKey
}

// Configuration ...
type Configuration func(s *EchoServer) error

// New constructs Server
func New(cfgs ...Configuration) *EchoServer {
	s := &EchoServer{
		groups: make(map[string][]*Spec),
		opts:   createDefaults(),
	}

	for _, cfg := range cfgs {
		if err := cfg(s); err != nil {
			log.Fatal().Err(fmt.Errorf("apply server configuration %w", err)).Send()

			return nil
		}
	}

	s.groups[s.opts.ID] = []*Spec{}

	if s.e == nil {
		s.e = CreateEchoInstance(s.opts.HideBanner)
	}

	refOpts := &ReflectorOptions{
		Servers:     addresses(),
		Port:        s.opts.Port,
		Title:       s.opts.ID + "-api",
		Description: s.opts.Description,
		Version:     s.opts.Version,
		APIKeyAuth:  s.keyValidator != nil,
	}

	if s.oidc != nil {
		refOpts.OpenAPIAuthorizationURL = fmt.Sprintf("%s/%s", s.oidc.Issuer, s.oidc.AuthURI)
		refOpts.OpenAPIClientID = s.oidc.ClientID
		refOpts.OpenAPISecret = s.oidc.Secret
	}

	s.ref = CreateReflector(refOpts)

	return s
}

// WithConfig ...
func WithConfig(opts ServerOptions) Configuration {
	return func(s *EchoServer) error {
		s.opts = createDefaults(*s.opts, opts)

		return nil
	}
}

// WithDefaultMiddleware ...
func WithDefaultMiddleware() Configuration {
	return func(s *EchoServer) error {
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
	return func(s *EchoServer) error {
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
	return func(s *EchoServer) error {
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

func (s *EchoServer) startYarnDev(dir string) {
	cmd := exec.Command("yarn", "dev")

	cmd.Dir = dir

	out, err := cmd.Output()

	log.Trace().Err(err).Bytes("out", out).Send()
}

func (s *EchoServer) buildYarn(dir string) {
	cmd := exec.Command("yarn", "build")

	cmd.Dir = dir

	out, err := cmd.Output()

	log.Trace().Err(fmt.Errorf("startYarnDev: %w", err)).Bytes("out", out).Send()
}

// WithFrontend ...
func WithFrontend(data embed.FS, dir string, exceptions ...string) Configuration {
	pathExceptions := []string{"/monitoring", "/docs", "/spec", "/metrics", "/health", "/_internal", "/api"}
	pathExceptions = append(pathExceptions, exceptions...)

	return func(s *EchoServer) error {
		if s.e == nil {
			s.e = CreateEchoInstance(s.opts.HideBanner)
		}

		dev := s.opts.Env == "dev"

		if dev {
			go s.startYarnDev(dir)

			fePort := 3000

			file, err := os.ReadFile(dir + "/package.json")
			if err != nil {
				log.Trace().
					Err(fmt.Errorf("WithFrontend -> read package.json: %w", err)).
					Str("path", dir+"/package.json").
					Send()
			}

			var packageJSON map[string]interface{}

			err = json.Unmarshal(file, &packageJSON)
			if err != nil {
				log.Trace().Err(err).Send()
			} else {
				fePort = int(packageJSON["devPort"].(float64))
			}

			u, err := url.Parse(fmt.Sprintf("http://0.0.0.0:%d", fePort))

			rrb := middleware.NewRoundRobinBalancer([]*middleware.ProxyTarget{{URL: u}})

			s.e.Use(middleware.ProxyWithConfig(middleware.ProxyConfig{
				Balancer:   rrb,
				ContextKey: "target",
				Skipper: func(c echo.Context) bool {
					p := c.Request().URL.Path

					_, found := lo.Find(pathExceptions, func(i string) bool {
						return strings.HasPrefix(p, i)
					})

					return found
				},
			}))
		} else {
			fsContent := getFileSystem(data, dir, dev)

			s.e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
				Filesystem: fsContent,
				HTML5:      true,
				Skipper: func(c echo.Context) bool {
					p := c.Request().URL.Path

					_, found := lo.Find(pathExceptions, func(i string) bool {
						return strings.HasPrefix(p, i)
					})

					return found
				},
			}))
		}

		return nil
	}
}

// WithMetrics ...
func WithMetrics() Configuration {
	return func(s *EchoServer) error {
		if s.e == nil {
			s.e = CreateEchoInstance(s.opts.HideBanner)
		}

		s.e.Use(echoPrometheus.MetricsMiddleware())
		s.e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

		return nil
	}
}

// WithQueue ...
func WithQueue(url, pw string, opts queue.Queues, fn func(q *queue.Queue)) Configuration {
	return func(s *EchoServer) error {
		if s.e == nil {
			s.e = CreateEchoInstance(s.opts.HideBanner)
		}

		q, mon := queue.
			CreateServer(url, 60, opts).
			MountMonitor("127.0.0.1:6379", "")

		s.e.Any("/monitoring/tasks/*", echo.WrapHandler(mon))

		if fn != nil {
			fn(q)
		}

		s.qRef = q.Run()

		log.Trace().Msgf("Asynq running on http://0.0.0.0:%d/monitoring/tasks", s.opts.Port)

		return nil
	}
}

// WithLogging ...
func WithLogging() Configuration {
	return func(s *EchoServer) error {
		logger.Init(s.opts.LogLevel, s.opts.Env == "dev", s.opts.ID)

		return nil
	}
}

// WithOIDC enables OpenID Connect auth
func WithOIDC(opts OIDCOptions) Configuration {
	return func(s *EchoServer) error {
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

// WithMiddleware add EchoMiddleware to Echo
func WithMiddleware(middleware ...echo.MiddlewareFunc) Configuration {
	return func(s *EchoServer) error {
		if s.e == nil {
			s.e = CreateEchoInstance(s.opts.HideBanner)
		}

		s.e.Use(middleware...)

		return nil
	}
}

// WithServiceMesh register the API with a service mesh (Consul for now)
func WithServiceMesh(meshType string, address string) Configuration {
	return func(s *EchoServer) error {
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

// WithKeyValidator for validating API Keys
func WithKeyValidator(v ValidateKey) Configuration {
	return func(s *EchoServer) error {
		s.keyValidator = v

		return nil
	}
}

// Group ...
func (s *EchoServer) Group(path string, specs ...*Spec) *EchoServer {
	s.groups[path] = specs

	return s
}

// TemplateGroup ...
func (s *EchoServer) TemplateGroup(path string, specs ...*TemplateSpec) *EchoServer {
	for _, templateSpec := range specs {
		s.RawRoute(templateSpec.Method, fmt.Sprintf("%s/%s", path, strings.TrimPrefix(templateSpec.Path, "/")), templateSpec.Handler, templateSpec.Middleware...)
	}

	return s
}

// Route adds a route to predefined group (erver id group)
func (s *EchoServer) Route(path string, spec *Spec) *EchoServer {
	s.groups[s.opts.ID] = append([]*Spec{}, spec)

	return s
}

// RawRoute adds a path + method + EchoMiddleware directly echo bypassing OpenAPI and without doing any checks
func (s *EchoServer) RawRoute(method Method, path string, fn echo.HandlerFunc, mw ...echo.MiddlewareFunc) *EchoServer {
	switch method {
	case MethodGet:
		s.e.GET(path, fn, mw...)
	case MethodDelete:
		s.e.DELETE(path, fn, mw...)
	case MethodPost:
		s.e.POST(path, fn, mw...)
	case MethodPut:
		s.e.PUT(path, fn, mw...)
	case MethodPatch:
		s.e.PATCH(path, fn, mw...)
	}

	return s
}

func (s *EchoServer) authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := strings.ReplaceAll(c.Request().Header.Get("Authorization"), "Bearer ", "")

		claims, err := s.ValidateJWTToken(c.Request().Context(), token)
		if err != nil {
			log.Debug().Err(err).Send()
			return c.JSON(http.StatusUnauthorized, nil)
		}

		c.Set("claims", claims)

		return next(c)
	}
}

func (s *EchoServer) apiAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims, err := s.keyValidator(c.Request().Header.Get("x-api-key"))
		if err != nil {
			log.Debug().Err(err).Send()
			return c.JSON(http.StatusUnauthorized, nil)
		}

		c.Set("claims", claims)

		return next(c)
	}
}

var (
	// ErrFullAuthUnauthorized for empty key & bearer
	ErrFullAuthUnauthorized = errors.New("api key and bearer token empty")

	// ErrFullAuthUnauthorizedInvalidTokens for invalid key and bearer
	ErrFullAuthUnauthorizedInvalidTokens = errors.New("api key and bearer token empty")
)

func (s *EchoServer) fullAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		apiKey := c.Request().Header.Get("x-api-key")
		bearer := strings.ReplaceAll(c.Request().Header.Get("authorization"), "Bearer ", "")

		if apiKey == "" && bearer == "" {
			log.Debug().Err(ErrFullAuthUnauthorized).Send()
			return c.JSON(http.StatusUnauthorized, nil)
		}

		keyClaims, keyErr := s.keyValidator(apiKey)
		bearerClaims, bearerErr := s.ValidateJWTToken(c.Request().Context(), bearer)

		if keyErr != nil && bearerErr != nil {
			log.Debug().Err(ErrFullAuthUnauthorizedInvalidTokens).Send()
			return c.JSON(http.StatusUnauthorized, nil)
		}

		if keyClaims != nil {
			c.Set("claims", keyClaims)
		}

		if bearerClaims != nil {
			c.Set("claims", bearerClaims)
		}

		return next(c)
	}
}

func (s *EchoServer) processSpecs() *EchoServer {
	for k, v := range s.groups {
		for _, spec := range v {
			spec.PathPrefix = k

			if err := spec.Build(s.ref); err != nil {
				log.Err(err).Send()
			}

			if spec.Auth && !spec.AuthAPI {
				spec.Route.EchoMiddleware = append(spec.Route.EchoMiddleware, s.authMiddleware)
			}

			if !spec.Auth && spec.AuthAPI {
				spec.Route.EchoMiddleware = append(spec.Route.EchoMiddleware, s.apiAuthMiddleware)
			}

			if spec.Auth && spec.AuthAPI {
				spec.Route.EchoMiddleware = append(spec.Route.EchoMiddleware, s.fullAuth)
			}

			switch spec.Method {
			case MethodGet:
				s.e.GET(spec.FullRouterPath(), spec.Route.EchoHandler, spec.Route.EchoMiddleware...)
			case MethodDelete:
				s.e.DELETE(spec.FullRouterPath(), spec.Route.EchoHandler, spec.Route.EchoMiddleware...)
			case MethodPost:
				s.e.POST(spec.FullRouterPath(), spec.Route.EchoHandler, spec.Route.EchoMiddleware...)
			case MethodPut:
				s.e.PUT(spec.FullRouterPath(), spec.Route.EchoHandler, spec.Route.EchoMiddleware...)
			case MethodPatch:
				s.e.PATCH(spec.FullRouterPath(), spec.Route.EchoHandler, spec.Route.EchoMiddleware...)
			}
		}
	}

	return s
}

func (s *EchoServer) build() *EchoServer {
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
func (s *EchoServer) Run() {
	s.processSpecs().build()

	fsContent := getFileSystem(content, "docs", s.opts.Env == "dev")
	assetHandler := http.FileServer(fsContent)

	s.e.Any("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"status": true})
	})

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
func (s *EchoServer) Stop(ctx context.Context) error {
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
		EchoHandler:    handler,
		EchoMiddleware: mw,
	}))
}

// Delete ...
func Delete[T any](path string, handler echo.HandlerFunc, mw ...echo.MiddlewareFunc) *Spec {
	return DeleteOp(path, mkGeneric[T](), WithRoute(&Route{
		EchoHandler:    handler,
		EchoMiddleware: mw,
	}))
}

// Post ...
func Post[T, B any](path string, handler echo.HandlerFunc, mw ...echo.MiddlewareFunc) *Spec {
	return PostOp(path, mkGeneric[B](), mkGeneric[T](), WithRoute(&Route{
		EchoHandler:    handler,
		EchoMiddleware: mw,
		BodyType:       reflect.TypeOf(mkGeneric[B]()),
	}))
}

// Patch ...
func Patch[T, B any](path string, handler echo.HandlerFunc, mw ...echo.MiddlewareFunc) *Spec {
	return PatchOp(path, mkGeneric[B](), mkGeneric[T](), WithRoute(&Route{
		EchoHandler:    handler,
		EchoMiddleware: mw,
	}))
}

// Put ...
func Put[T, B any](path string, handler echo.HandlerFunc, mw ...echo.MiddlewareFunc) *Spec {
	return PutOp(path, mkGeneric[B](), mkGeneric[T](), WithRoute(&Route{
		EchoHandler:    handler,
		EchoMiddleware: mw,
	}))
}

func getFileSystem(embededFiles embed.FS, dir string, isDev bool) http.FileSystem {
	sub, err := fs.Sub(embededFiles, dir)
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	return http.FS(sub)
}

// CreateEchoInstance ...
func CreateEchoInstance(hideBanner bool, templates ...string) *echo.Echo {
	e := echo.New()

	e.HideBanner = hideBanner
	e.HidePort = hideBanner
	e.Validator = &Validator{validator: validator.New()}

	if len(templates) > 0 {
		t := &Template{
			templates: template.Must(template.ParseGlob(templates[0])),
		}

		e.Renderer = t
	}

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
