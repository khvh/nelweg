package nelweg

import (
  "github.com/labstack/echo/v4"
  "reflect"
)

// Route ...
type Route struct {
  handler    echo.HandlerFunc
  middleware []echo.MiddlewareFunc
  bodyType   reflect.Type
}