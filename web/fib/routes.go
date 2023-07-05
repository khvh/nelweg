package fib

import (
  "github.com/gofiber/fiber/v2"
  "github.com/khvh/nelweg"
  "github.com/khvh/nelweg/web"
  "reflect"
)

// Get ...
func Get[T any](path string, mw ...fiber.Handler) *nelweg.Spec {
  return nelweg.GetOp(path, web.MkGeneric[T](), nelweg.WithRoute(&nelweg.Route{
    FiberMiddleware: mw,
  }))
}

// Delete ...
func Delete[T any](path string, mw ...fiber.Handler) *nelweg.Spec {
  return nelweg.DeleteOp(path, web.MkGeneric[T](), nelweg.WithRoute(&nelweg.Route{
    FiberMiddleware: mw,
  }))
}

// Post ...
func Post[T, B any](path string, mw ...fiber.Handler) *nelweg.Spec {
  return nelweg.PostOp(path, web.MkGeneric[B](), web.MkGeneric[T](), nelweg.WithRoute(&nelweg.Route{
    FiberMiddleware: mw,
    BodyType:        reflect.TypeOf(web.MkGeneric[B]()),
  }))
}

// Patch ...
func Patch[T, B any](path string, mw ...fiber.Handler) *nelweg.Spec {
  return nelweg.PatchOp(path, web.MkGeneric[B](), web.MkGeneric[T](), nelweg.WithRoute(&nelweg.Route{
    FiberMiddleware: mw,
    BodyType:        reflect.TypeOf(web.MkGeneric[B]()),
  }))
}

// Put ...
func Put[T, B any](path string, mw ...fiber.Handler) *nelweg.Spec {
  return nelweg.PutOp(path, web.MkGeneric[B](), web.MkGeneric[T](), nelweg.WithRoute(&nelweg.Route{
    FiberMiddleware: mw,
    BodyType:        reflect.TypeOf(web.MkGeneric[B]()),
  }))
}

// Group ...
func Group(path, tag string, specs ...*nelweg.Spec) *nelweg.Group {
  return &nelweg.Group{
    Tag:   tag,
    Specs: specs,
    Path:  path,
  }
}