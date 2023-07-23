package main

import (
	"fmt"
	"net/http"
	"os"

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
	o, _ := os.Getwd()
	fmt.Println(o)
	nelweg.
		New(
			nelweg.WithConfig(nelweg.ServerOptions{
				Port:           1337,
				ID:             "nelweg-test",
				Env:            "dev",
				Templates:      "cmd/testserver/views",
				RemoveTrailing: true,
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
			nelweg.WithMetrics(),
			nelweg.WithOIDC(nelweg.OIDCOptions{
				Issuer:            "http://localhost:8888/realms/haldri/protocol/openid-connect",
				AuthURI:           "auth",
				KeysURI:           "certs",
				TokenURI:          "token",
				ClientID:          "haldri-dev",
				Secret:            "8AaObfNT2lqBNk7bFtF7xWc8R5nfgjFn",
				RedirectURI:       "http://127.0.0.1:1337/api/auth/code",
				ClientRedirectURI: "http://127.0.0.1:1337/api/auth/userinfo",
			}),
			// nelweg.WithFrontend(embed.FS{}, "cmd/testserver/ui", "node_modules"),
		).
		Group("/api/test", nelweg.Get[example]("/:id", func(c echo.Context) error {
			return c.JSON(http.StatusOK, example{Status: true})
		}).WithTags("Examples").WithAPIAuth().With(
			nelweg.WithSummary("This path does things"),
			nelweg.WithDescription("Short description"),
		)).
		TemplateGroup("/blah", &nelweg.TemplateSpec{
			Method: nelweg.MethodGet,
			Path:   "",
			Handler: func(c echo.Context) error {
				return c.Render(http.StatusOK, "main", echo.Map{"title": "Page file title!!"})
			},
		}).
		Run()
}
