package queue

import (
	"context"
	"fmt"

	"github.com/hibiken/asynq"
	"github.com/hibiken/asynqmon"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

var (
	processedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "processed_tasks_total",
			Help: "The total number of processed tasks",
		},
		[]string{"task_type"},
	)

	failedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "failed_tasks_total",
			Help: "The total number of times processing failed",
		},
		[]string{"task_type"},
	)

	inProgressGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "in_progress_tasks",
			Help: "The number of tasks currently being processed",
		},
		[]string{"task_type"},
	)
)

type logger struct {
}

func (c logger) Debug(args ...interface{}) {
	log.Trace().Str("from", "asynq").Msg(fmt.Sprint(args...))
}

func (c logger) Info(args ...interface{}) {
	log.Info().Str("from", "asynq").Msg(fmt.Sprint(args...))
}

func (c logger) Warn(args ...interface{}) {
	log.Warn().Str("from", "asynq").Msg(fmt.Sprint(args...))
}

func (c logger) Error(args ...interface{}) {
	log.Error().Str("from", "asynq").Msg(fmt.Sprint(args...))
}

func (c logger) Fatal(args ...interface{}) {
	log.Fatal().Str("from", "asynq").Msg(fmt.Sprint(args...))
}

// Queues represents queues config for Asynq
type Queues map[string]int

// Queue holds Asynq server things
type Queue struct {
	srv *asynq.Server
	mux *asynq.ServeMux
}

var queueInstance *Queue

func metrics1(next asynq.Handler) asynq.Handler {
	return asynq.HandlerFunc(func(ctx context.Context, t *asynq.Task) error {
		inProgressGauge.WithLabelValues(t.Type()).Inc()
		err := next.ProcessTask(ctx, t)
		inProgressGauge.WithLabelValues(t.Type()).Dec()
		if err != nil {
			failedCounter.WithLabelValues(t.Type()).Inc()
		}
		processedCounter.WithLabelValues(t.Type()).Inc()
		return err
	})
}

// CreateServer creates a new Asynq server
func CreateServer(redisAddress string, concurrency int, qs Queues) *Queue {
	if queueInstance == nil {
		srv := asynq.NewServer(
			asynq.RedisClientOpt{Addr: redisAddress},
			asynq.Config{
				Concurrency: concurrency,
				Queues:      qs,
				Logger:      logger{},
			},
		)

		mux := asynq.NewServeMux()
		queueInstance = &Queue{srv, mux}
	}

	return queueInstance
}

// MountMonitor mounts asynqmon
func (q *Queue) MountMonitor(redisAddress, redisPw string) (*Queue, *asynqmon.HTTPHandler) {
	mon := asynqmon.New(asynqmon.Options{
		RootPath: "/monitoring/tasks",
		RedisConnOpt: asynq.RedisClientOpt{
			Addr:     redisAddress,
			Password: redisPw,
			DB:       0,
		},
	})

	return q, mon
}

// HandlerFunc ...
type HandlerFunc struct {
	Pattern string
	FN      func(context.Context, *asynq.Task) error
}

// AddHandlerFunc adds a handler func to mux
func (q *Queue) AddHandlerFunc(pattern string, handler func(context.Context, *asynq.Task) error) *Queue {
	q.mux.HandleFunc(pattern, handler)

	return q
}

// Handler ...
type Handler struct {
	Pattern string
	FN      asynq.Handler
}

// AddHandler adds a handler to mux
func (q *Queue) AddHandler(pattern string, handler asynq.Handler) *Queue {
	q.mux.Handle(pattern, handler)

	return q
}

// Run stats the Queue
func (q *Queue) Run() *Queue {
	go func() {
		if err := q.srv.Start(q.mux); err != nil {
			log.Fatal().Err(err)
		}
	}()

	return q
}

// Stop ...
func (q *Queue) Stop() {
	q.srv.Stop()
	q.srv.Shutdown()
}

// Client ...
type Client struct {
	client *asynq.Client
}

var clientInstance *Client

// NewClient ...
func NewClient(redisAddress string) *Client {
	if clientInstance == nil {
		clientInstance = &Client{
			client: asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddress}),
		}
	}

	return clientInstance
}

// Add a new task to queue
func (c *Client) Add(task *asynq.Task, opts ...asynq.Option) *Client {
	info, err := c.client.Enqueue(task, opts...)
	if err != nil {
		log.Err(err).Send()
	}

	log.Trace().Msgf("Added task [%s] to [%s]", info.ID, info.Queue)

	return c
}
