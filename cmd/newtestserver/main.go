package main

import (
  "github.com/khvh/nelweg/web/ech"
  "github.com/labstack/echo/v4"
  "github.com/rs/zerolog/log"
)

type Ex struct {
  ID string `json:"id"`
}

func testhandler(c echo.Context) error {
  return c.JSON(200, echo.Map{"status": true})
}

func main() {

  e := echo.New()

  g := e.Group("/api/test", func(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
      log.Info().Msg("middleware fn")
      return next(c)
    }
  })

  g.GET(ech.Handler[Ex, Ex]("", testhandler))

  e.Start(":1111")

}