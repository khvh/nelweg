package ech

import (
  "github.com/labstack/echo/v4"
  "github.com/rs/zerolog/log"
)

func Handler[RES, REQ any](p string, fn echo.HandlerFunc) (string, echo.HandlerFunc) {
  return p, func(c echo.Context) error {
    log.Info().Msg("1111")
    return fn(c)
  }
}