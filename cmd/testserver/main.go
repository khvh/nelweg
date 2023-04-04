package main

import (
  "github.com/khvh/nelweg"
  "github.com/labstack/echo/v4"
  "github.com/pkg/errors"
  "net/http"
)

type example struct {
  Status bool `json:"status"`
}

var errBadKey = errors.New("unknown key")

func main() {
  nelweg.
    New(
      nelweg.WithConfig(nelweg.ServerOptions{
        Port: 1337,
        ID:   "nelweg-test",
      }),
      nelweg.WithLogging(),
      nelweg.WithKeyValidator(func(key string) (map[string]any, error) {
        err := errBadKey

        if key == "1337" {
          err = nil
        }

        return map[string]any{
          "WithKeyValidator": 1,
        }, err
      }),
    ).
    Group("/test", nelweg.Get[example]("", func(c echo.Context) error {
      return c.JSON(http.StatusOK, example{Status: true})
    }).WithAPIAuth()).
    Run()
}