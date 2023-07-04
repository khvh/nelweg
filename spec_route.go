package nelweg

import (
  "github.com/gofiber/fiber/v2"
  "github.com/labstack/echo/v4"
  "reflect"
)

// Route ...
type Route struct {
  EchoHandler     echo.HandlerFunc
  EchoMiddleware  []echo.MiddlewareFunc
  FiberMiddleware []fiber.Handler
  BodyType        reflect.Type
}