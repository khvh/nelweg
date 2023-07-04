package main

import (
  "github.com/gofiber/fiber/v2"
  "github.com/khvh/nelweg/web"
  "github.com/khvh/nelweg/web/fib"
  "github.com/rs/zerolog/log"
)

type Example struct {
  ID string `json:"id"`
}

func main() {
  log.Err(
    fib.NewFiberServer(
      fib.WithOptions(web.ServerOptions{
        ID:   "nelweg_v2_test",
        Port: 8881,
        Env:  "dev",
      }),
      fib.WithLogging(),
      fib.WithMiddleware(),
      fib.WithTracing(),
      fib.WithOIDC(web.OIDCOptions{
        Issuer:            "http://localhost:8888/realms/haldri/protocol/openid-connect",
        AuthURI:           "auth",
        KeysURI:           "certs",
        TokenURI:          "token",
        ClientID:          "haldri-dev",
        Secret:            "8AaObfNT2lqBNk7bFtF7xWc8R5nfgjFn",
        RedirectURI:       "http://127.0.0.1:1337/api/auth/code",
        ClientRedirectURI: "http://127.0.0.1:1337/api/auth/userinfo",
      }),
      fib.WithRoute(fib.Get[Example]("/some/test", func(c *fiber.Ctx) error {
        return c.JSON(nil)
      }).WithAuth()),
      fib.WithGroup("/api/test", fib.Get[Example]("", func(c *fiber.Ctx) error {
        return c.JSON(nil)
      }).WithAuth()),
    ).
      Run(),
  ).Send()
}