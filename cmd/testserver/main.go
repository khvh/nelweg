package main

import (
	"embed"
	"fmt"
	"net/http"

	"github.com/khvh/nelweg"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

type example struct {
	Status bool `json:"status"`
}

var errBadKey = errors.New("unknown key")

//go:embed ui
var content embed.FS

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
			nelweg.WithFrontend(content, "./cmd/testserver/ui", "node_modules"),
		).
		Group("/api/test", nelweg.Get[example]("/:id", func(c echo.Context) error {
			fmt.Println(c.Param("id"))
			return c.JSON(http.StatusOK, example{Status: true})
		}).WithTags("Examples").WithAPIAuth().With(
			nelweg.WithSummary("This path does things"),
			nelweg.WithDescription("Short description"),
		)).
		Run()
}
