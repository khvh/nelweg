package main

import (
	"net/http"

	"github.com/khvh/nelweg"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

type example struct {
	Status bool `json:"status"`
}

var errBadKey = errors.New("unknown key")

// //go:embed ui/dist
// var content embed.FS

func main() {
	nelweg.
		New(
			nelweg.WithConfig(nelweg.ServerOptions{
				Port: 1337,
				ID:   "nelweg-test",
				Env:  "dev",
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
			// nelweg.WithQueue("localhost:6379", "", queue.Queues{
			// 	"critical": 6,
			// 	"default":  3,
			// 	"low":      1,
			// }, nil),
			nelweg.WithMetrics(),
			// nelweg.WithFrontend(embed.FS{}, "ui/dist", "node_modules"),
		).
		Group("/api/test", nelweg.Get[example]("/:id", func(c echo.Context) error {
			return c.JSON(http.StatusOK, example{Status: true})
		}).WithTags("Examples").WithAPIAuth().With(
			nelweg.WithSummary("This path does things"),
			nelweg.WithDescription("Short description"),
		)).
		Run()
}
