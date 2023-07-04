package fib

import (
  "context"
  "embed"
  "encoding/json"
  "fmt"
  "github.com/ansrivas/fiberprometheus/v2"
  "github.com/gofiber/contrib/otelfiber"
  "github.com/gofiber/fiber/v2"
  "github.com/gofiber/fiber/v2/middleware/cors"
  "github.com/gofiber/fiber/v2/middleware/filesystem"
  "github.com/gofiber/fiber/v2/middleware/proxy"
  "github.com/gofiber/fiber/v2/middleware/recover"
  "github.com/gofiber/fiber/v2/middleware/requestid"
  "github.com/google/go-querystring/query"
  "github.com/khvh/nelweg"
  "github.com/khvh/nelweg/logger"
  "github.com/khvh/nelweg/telemetry"
  "github.com/khvh/nelweg/web"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jwt"
  "github.com/rs/zerolog/log"
  "github.com/swaggest/openapi-go/openapi3"
  "go.opentelemetry.io/otel"
  "io"
  "io/fs"
  "net/http"
  "net/url"
  "os"
  "os/exec"
  "strconv"
  "strings"
)

type fiberServer struct {
  instance *fiber.App

  groups map[string][]*nelweg.Spec
  ref    *openapi3.Reflector
  docsFS *embed.FS

  opts     *web.ServerOptions
  oidcOpts *web.OIDCOptions

  jwks         jwk.Set
  keyValidator nelweg.ValidateKey
}

// NewFiberServer ...
func NewFiberServer(cfgs ...web.Configuration[fiberServer]) web.Server {
  s := &fiberServer{
    instance: fiber.New(fiber.Config{
      DisableStartupMessage: true,
    }),
    groups: make(map[string][]*nelweg.Spec),
  }

  for _, cfg := range cfgs {
    if err := cfg(s); err != nil {
      log.Debug().Err(err).Stack().Send()
    }
  }

  s.groups[""] = []*nelweg.Spec{}

  refOpts := &nelweg.ReflectorOptions{
    Servers:     web.Adresses(),
    Port:        s.opts.Port,
    Title:       s.opts.ID + "-api",
    Description: s.opts.Description,
    Version:     s.opts.Version,
    APIKeyAuth:  s.keyValidator != nil,
  }

  if s.oidcOpts != nil {
    refOpts.OpenAPIAuthorizationURL = fmt.Sprintf("%s/%s", s.oidcOpts.Issuer, s.oidcOpts.AuthURI)
    refOpts.OpenAPIClientID = s.oidcOpts.ClientID
    refOpts.OpenAPISecret = s.oidcOpts.Secret
  }

  s.ref = nelweg.CreateReflector(refOpts)

  return s
}

// WithOptions sets options for fiberServer.opts
func WithOptions(opts web.ServerOptions) web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    s.opts = &opts

    return nil
  }
}

// WithMiddleware sets the default middleware and allows to pass additional middleware to Fiber
func WithMiddleware(mw ...fiber.Handler) web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    s.instance.Use(requestid.New())
    s.instance.Use(cors.New())
    s.instance.Use(recover.New())

    for _, handler := range mw {
      s.instance.Use(handler)
    }

    return nil
  }
}

// WithTracing enables request tracing with OTEL + Jaeger
func WithTracing(url ...string) web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    id := strings.ReplaceAll(s.opts.ID, "-", "_")
    u := "http://localhost:14268/api/traces"

    otel.Tracer(id)

    if len(url) > 0 {
      u = url[0]
    }

    telemetry.New(id, u)

    s.instance.Use(otelfiber.Middleware(otelfiber.WithServerName(id)))

    return nil
  }
}

// WithMetrics expose a Prometheus compatible endpoint of metrics data
func WithMetrics() web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    id := strings.ReplaceAll(s.opts.ID, "-", "_")
    prometheus := fiberprometheus.New(id)

    prometheus.RegisterAt(s.instance, "/metrics")

    s.instance.Use(prometheus.Middleware)

    return nil
  }
}

func WithOIDC(opts web.OIDCOptions) web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    s.oidcOpts = &opts

    keySet, err := web.Keys(opts.Issuer, opts.KeysURI)
    if err != nil {
      log.Err(err).Send()

      return nil
    }

    s.jwks = keySet

    s.mountAuthEndpoints()

    return nil
  }
}

// WithFrontend ...
func WithFrontend(data *embed.FS, dir string) web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    if data != nil {
      s.mountFrontend(*data, dir)
    } else {
      go s.startYarnDev(dir)

      log.Trace().Msg("Frontend dev server proxy started")

      fePort := 3000

      file, err := os.ReadFile(dir + "/package.json")
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

      s.instance.Get("/*", func(c *fiber.Ctx) error {
        err := proxy.
          Do(c, strings.
            ReplaceAll(c.Request().URI().String(), strconv.Itoa(s.opts.Port), strconv.Itoa(fePort)),
          )
        if err != nil {
          log.Err(err).Send()
        }

        return c.Send(c.Response().Body())
      })
    }

    return nil
  }
}

// WithGroup ...
func WithGroup(path string, specs ...*nelweg.Spec) web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    s.groups[path] = specs

    return nil
  }
}

// WithRoute ...
func WithRoute(spec *nelweg.Spec) web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    s.groups["/"] = append(s.groups["/"], spec)

    return nil
  }
}

// WithFiberRoute ...
func WithFiberRoute(method nelweg.Method, path string, mw ...fiber.Handler) web.Configuration[fiberServer] {
  return func(f *fiberServer) error {
    switch method {
    case nelweg.MethodGet:
      f.instance.Get(path, mw...)
    case nelweg.MethodDelete:
      f.instance.Delete(path, mw...)
    case nelweg.MethodPost:
      f.instance.Post(path, mw...)
    case nelweg.MethodPut:
      f.instance.Put(path, mw...)
    case nelweg.MethodPatch:
      f.instance.Patch(path, mw...)
    }

    return nil
  }
}

// WithKeyValidator adds a validator for API keys
func WithKeyValidator(v nelweg.ValidateKey) web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    s.keyValidator = v

    return nil
  }
}

// WithLogging configures zerolog
func WithLogging() web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    logger.Init(s.opts.LogLevel, s.opts.Env == "dev", s.opts.ID)

    return nil
  }
}

// WithRapidoc ...
func WithRapidoc(content *embed.FS) web.Configuration[fiberServer] {
  return func(s *fiberServer) error {
    s.docsFS = content

    return nil
  }
}

func (s *fiberServer) Routes(fn func(s web.Server) error) web.Server {
  if err := fn(s); err != nil {
    log.Debug().Err(err).Stack().Send()
  }

  return s
}

//go:embed docs
var content embed.FS

func (s *fiberServer) Run() error {
  s.processSpecs().build()

  s.instance.Use("/docs", filesystem.New(filesystem.Config{
    Root:       http.FS(content),
    PathPrefix: "/docs",
    Browse:     false,
  }))

  s.instance.All("/oauth-receiver.html*", func(c *fiber.Ctx) error {
    return c.Redirect("/docs"+string(c.Request().RequestURI()), http.StatusTemporaryRedirect)
  })

  for _, host := range web.Adresses() {
    log.
      Info().
      Str("id", s.opts.ID).
      Str("URL", fmt.Sprintf("http://%s:%d", host, s.opts.Port)).
      Str("OpenAPI", fmt.Sprintf("http://%s:%d/docs", host, s.opts.Port)).
      Send()
  }

  log.Info().Str("server", s.opts.ID).Send()

  return s.instance.Listen(fmt.Sprintf("%s:%d", s.opts.Host, s.opts.Port))
}

func (s *fiberServer) startYarnDev(dir string) {
  cmd := exec.Command("yarn", "dev")

  cmd.Dir = dir

  out, err := cmd.Output()

  log.Trace().Err(err).Bytes("out", out).Send()
}

func (s *fiberServer) buildYarn(dir string) {
  cmd := exec.Command("yarn", "build")

  cmd.Dir = dir

  out, err := cmd.Output()

  log.Trace().Err(err).Bytes("out", out).Send()
}

func (s *fiberServer) mountFrontend(ui embed.FS, dir string) web.Server {
  s.buildYarn(dir)

  s.instance.Use("/*", filesystem.New(filesystem.Config{
    Root:       http.FS(ui),
    PathPrefix: "ui/dist",
    Browse:     false,
  }))

  log.Trace().Msg("Frontend mounted")

  return s
}

func (s *fiberServer) mountAuthEndpoints() web.Server {
  authURL := fmt.Sprintf(
    "%s/%s?client_id=%s&redirect_uri=%s&response_type=code",
    s.oidcOpts.Issuer,
    s.oidcOpts.AuthURI,
    s.oidcOpts.ClientID,
    url.QueryEscape(s.oidcOpts.RedirectURI),
  )

  s.instance.Get("/api/auth", func(c *fiber.Ctx) error {
    return c.Redirect(authURL, http.StatusTemporaryRedirect)
  })

  s.instance.All("/api/auth/code", func(c *fiber.Ctx) error {
    form := url.Values{}

    form.Add("grant_type", "authorization_code")
    form.Add("client_id", s.oidcOpts.ClientID)
    form.Add("client_secret", s.oidcOpts.Secret)
    form.Add("code", c.Query("code"))
    form.Add("redirect_uri", s.oidcOpts.RedirectURI)

    req, err := http.
      NewRequest(
        http.MethodPost, fmt.Sprintf("%s/%s", s.oidcOpts.Issuer, s.oidcOpts.TokenURI), strings.NewReader(form.Encode()))
    if err != nil {
      log.Err(fmt.Errorf("create http client %w", err)).Send()

      return c.Status(http.StatusBadRequest).JSON(nil)
    }

    req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

    res, err := http.DefaultClient.Do(req)
    if err != nil {
      log.Err(fmt.Errorf("send code req %w", err)).Send()

      return c.Status(http.StatusBadRequest).JSON(nil)
    }

    bts, err := io.ReadAll(res.Body)
    if err != nil {
      log.Err(fmt.Errorf("read body %w", err)).Send()

      return c.Status(http.StatusBadRequest).JSON(nil)
    }

    var data web.CodeResponse

    err = json.Unmarshal(bts, &data)
    if err != nil {
      log.Err(fmt.Errorf("unmarshal %w", err)).Send()

      return c.Status(http.StatusBadRequest).JSON(nil)
    }

    v, err := query.Values(data)
    if err != nil {
      log.Err(fmt.Errorf("encode %w", err)).Send()

      return c.Status(http.StatusBadRequest).JSON(nil)
    }

    return c.Redirect(fmt.Sprintf("%s?%s", s.oidcOpts.ClientRedirectURI, v.Encode()), http.StatusTemporaryRedirect)
  })

  s.instance.All("/api/auth/userinfo", func(c *fiber.Ctx) error {
    claims, err := s.validateJWTToken(c.UserContext(), c.Query("accessToken"))
    if err != nil {
      return c.Status(http.StatusUnauthorized).JSON(nil)
    }

    return c.JSON(claims)
  })

  return s
}

// validateJWTRequest validates jwt against jwks etc
func (s *fiberServer) validateJWTRequest(ctx context.Context, req *http.Request) (map[string]any, error) {
  token, err := jwt.ParseRequest(req)
  if err != nil {
    return nil, err
  }

  claims, err := token.AsMap(ctx)
  if err != nil {
    return nil, err
  }

  return claims, nil
}

// validateJWTToken validates jwt against jwks etc
func (s *fiberServer) validateJWTToken(ctx context.Context, token string) (map[string]any, error) {
  verified, err := jwt.ParseString(token, jwt.WithKeySet(s.jwks))
  if err != nil {
    return nil, err
  }

  claims, err := verified.AsMap(ctx)
  if err != nil {
    return nil, err
  }

  return claims, nil
}

func (s *fiberServer) authMiddleware(c *fiber.Ctx) error {
  claims, err := s.
    validateJWTToken(c.UserContext(), strings.ReplaceAll(c.Get("authorization"), "Bearer ", ""))
  if err != nil {
    return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
      "err": web.ErrFullAuthUnauthorizedInvalidTokens.Error(),
    })
  }

  c.Locals("claims", claims)

  return c.Next()
}

func (s *fiberServer) apiKeyMiddleware(c *fiber.Ctx) error {
  claims, err := s.keyValidator(c.Get("x-api-key"))
  if err != nil {
    return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
      "err": web.ErrFullAuthUnauthorizedInvalidTokens.Error(),
    })
  }

  c.Locals("claims", claims)

  return c.Next()
}

func (s *fiberServer) combinedAuthMiddleware(c *fiber.Ctx) error {
  apiKey := c.Get("x-api-key")
  bearer := strings.ReplaceAll(c.Get("authorization"), "Bearer ", "")

  if apiKey == "" && bearer == "" {
    return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
      "err": web.ErrFullAuthUnauthorized.Error(),
    })
  }

  keyClaims, keyErr := s.keyValidator(apiKey)
  bearerClaims, bearerErr := s.validateJWTToken(c.UserContext(), bearer)

  if keyErr != nil && bearerErr != nil {
    return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
      "err": web.ErrFullAuthUnauthorizedInvalidTokens.Error(),
    })
  }

  if keyClaims != nil {
    c.Locals("claims", keyClaims)
  }

  if bearerClaims != nil {
    c.Locals("claims", bearerClaims)
  }

  return c.Next()
}

func getFileSystem(embededFiles embed.FS) http.FileSystem {
  sub, err := fs.Sub(embededFiles, "docs")
  if err != nil {
    panic(err)
  }

  return http.FS(sub)
}

func (s *fiberServer) processSpecs() *fiberServer {
  for k, v := range s.groups {
    for _, spec := range v {
      spec.PathPrefix = k

      var mw []fiber.Handler

      if spec.Auth && !spec.AuthAPI {
        mw = append(mw, s.authMiddleware)
      }

      if !spec.Auth && spec.AuthAPI {
        mw = append(mw, s.apiKeyMiddleware)
      }

      if spec.Auth && spec.AuthAPI {
        mw = append(mw, s.combinedAuthMiddleware)
      }

      mw = append(mw, spec.Route.FiberMiddleware...)

      if err := spec.Build(s.ref); err != nil {
        log.Err(err).Send()
      }

      switch spec.Method {
      case nelweg.MethodGet:
        s.instance.Get(spec.FullRouterPath(), mw...)
      case nelweg.MethodDelete:
        s.instance.Delete(spec.FullRouterPath(), mw...)
      case nelweg.MethodPost:
        s.instance.Post(spec.FullRouterPath(), mw...)
      case nelweg.MethodPut:
        s.instance.Put(spec.FullRouterPath(), mw...)
      case nelweg.MethodPatch:
        s.instance.Patch(spec.FullRouterPath(), mw...)
      }
    }
  }

  return s
}

func (s *fiberServer) build() *fiberServer {
  yamlBytes, err := s.ref.Spec.MarshalYAML()
  if err != nil {
    log.Err(err).Send()

    return s
  }

  s.instance.Get("/spec/spec.yaml", func(c *fiber.Ctx) error {
    c.Set("content-type", "application/openapi+yaml")

    return c.Send(yamlBytes)
  })

  s.instance.Get("/spec/spec.yml", func(c *fiber.Ctx) error {
    c.Set("content-type", "application/openapi+yaml")

    return c.Send(yamlBytes)
  })

  jsonBytes, err := s.ref.Spec.MarshalJSON()
  if err != nil {
    log.Err(err).Send()

    return s
  }

  s.instance.Get("/spec/spec.json", func(c *fiber.Ctx) error {
    c.Set("content-type", "application/openapi+json")

    return c.Send(jsonBytes)
  })

  return s
}