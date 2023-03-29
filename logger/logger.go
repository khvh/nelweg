package logger

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/afiskon/promtail-client/promtail"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type lokiWriter struct {
	client promtail.Client
}

func newLokiWriter(id, env string) *lokiWriter {
	client, err := promtail.NewClientJson(promtail.ClientConfig{
		PushURL:            "http://192.168.107.2:3100/api/prom/push",
		Labels:             "{env=\"" + env + "\",application=\"" + id + "\"}",
		BatchWait:          5 * time.Second,
		BatchEntriesNumber: 10000,
		SendLevel:          promtail.INFO,
		PrintLevel:         promtail.ERROR,
	})
	if err != nil {
		fmt.Println(err)
	}

	return &lokiWriter{
		client,
	}
}

func (l lokiWriter) Write(p []byte) (int, error) {
	l.client.Infof(string(p))
	return len(p), nil
}

// Init logger for dev or prod
func Init(level int, devMode bool, id string) {
	env := "dev"

	if !devMode {
		env = "prod"
	}

	if devMode {
		zerolog.SetGlobalLevel(zerolog.Level(level))
		// log.Logger = zerolog.New(io.MultiWriter(zerolog.ConsoleWriter{Out: os.Stderr}, newLokiWriter(id, env)))
		log.Logger = zerolog.New(io.MultiWriter(zerolog.ConsoleWriter{Out: os.Stderr}))
	} else {
		zerolog.SetGlobalLevel(zerolog.Level(level))
		log.Logger = zerolog.New(newLokiWriter(id, env))
	}
}
