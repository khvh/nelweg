package web

import (
  "context"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net/http"
  "net/url"
  "strings"
  "time"

  "github.com/google/go-querystring/query"
  "github.com/labstack/echo/v4"
  "github.com/lestrrat-go/jwx/v2/jwk"
  "github.com/lestrrat-go/jwx/v2/jwt"
  "github.com/rs/zerolog/log"
)

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

func keys(issuer, jwksPath string) (jwk.Set, error) {
  ctx, cancel := context.WithCancel(context.Background())

  defer cancel()

  p := fmt.Sprintf("%s/%s", issuer, jwksPath)

  c := jwk.NewCache(ctx)

  c.Register(p, jwk.WithMinRefreshInterval(30*time.Minute))

  keySet, err := c.Refresh(ctx, p)
  if err != nil {
    return nil, err
  }

  return keySet, err
}

func (s *Server) mountAuthEndpoints() *Server {
  authURL := fmt.Sprintf(
    "%s/%s?client_id=%s&redirect_uri=%s&response_type=code",
    s.oidc.Issuer,
    s.oidc.AuthURI,
    s.oidc.ClientID,
    url.QueryEscape(s.oidc.RedirectURI),
  )

  s.e.GET("/api/auth", func(c echo.Context) error {
    return c.Redirect(http.StatusTemporaryRedirect, authURL)
  })

  s.e.Any("/api/auth/code", func(c echo.Context) error {
    form := url.Values{}

    form.Add("grant_type", "authorization_code")
    form.Add("client_id", s.oidc.ClientID)
    form.Add("client_secret", s.oidc.Secret)
    form.Add("code", c.QueryParam("code"))
    form.Add("redirect_uri", s.oidc.RedirectURI)

    req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s", s.oidc.Issuer, s.oidc.TokenURI), strings.NewReader(form.Encode()))
    if err != nil {
      log.Debug().Err(fmt.Errorf("create http client %w", err)).Send()

      return c.JSON(http.StatusBadRequest, nil)
    }

    req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

    res, err := http.DefaultClient.Do(req)
    if err != nil {
      log.Debug().Err(fmt.Errorf("send code req %w", err)).Send()

      return c.JSON(http.StatusBadRequest, nil)
    }

    bts, err := ioutil.ReadAll(res.Body)
    if err != nil {
      log.Debug().Err(fmt.Errorf("read body %w", err)).Send()

      return c.JSON(http.StatusBadRequest, nil)
    }

    var data CodeResponse

    json.Unmarshal(bts, &data)

    v, err := query.Values(data)
    if err != nil {
      log.Debug().Err(fmt.Errorf("encode %w", err)).Send()

      return c.JSON(http.StatusBadRequest, nil)
    }

    return c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s?%s", s.oidc.ClientRedirectURI, v.Encode()))
  })

  s.e.Any("/api/auth/userinfo", func(c echo.Context) error {
    claims, err := s.ValidateJWTToken(c.Request().Context(), c.QueryParam("accessToken"))
    if err != nil {
      return c.JSON(http.StatusUnauthorized, nil)
    }

    return c.JSON(200, claims)
  })

  return s
}

// ValidateJWTRequest validates jwt against jwks etc
func (s *Server) ValidateJWTRequest(ctx context.Context, req *http.Request) (map[string]any, error) {
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

// ValidateJWTToken validates jwt against jwks etc
func (s *Server) ValidateJWTToken(ctx context.Context, token string) (map[string]any, error) {
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