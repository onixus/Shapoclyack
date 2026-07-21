// Command worker is the shapoclyack-recon NATS JetStream worker: it consumes
// ReconTask messages from "recon.tasks.>", runs (currently dummy) discovery,
// and publishes ReconResult messages to "recon.results.{tenant_id}".
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/onixus/shapoclyack/recon/internal/discovery"
	"github.com/onixus/shapoclyack/recon/internal/models"
)

const (
	streamTasks    = "RECON_TASKS"
	streamResults  = "RECON_RESULTS"
	subjectTasks   = "recon.tasks.>"
	subjectResults = "recon.results.>"
	consumerName   = "recon-workers"
)

func main() {
	natsURL := strings.TrimSpace(os.Getenv("NATS_URL"))
	if natsURL == "" {
		log.Fatal("NATS_URL is required")
	}

	tasksMaxAge := time.Duration(intEnv("RECON_NATS_TASKS_MAX_AGE_SECONDS", 24*3600)) * time.Second
	resultsMaxAge := time.Duration(intEnv("RECON_NATS_RESULTS_MAX_AGE_SECONDS", 7*24*3600)) * time.Second
	replicas := intEnv("RECON_NATS_STREAM_REPLICAS", 1)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	nc, err := nats.Connect(
		natsURL,
		nats.Name("shapoclyack-recon"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		log.Fatalf("connect to NATS %s: %v", natsURL, err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("init JetStream context: %v", err)
	}

	if err := ensureStream(js, &nats.StreamConfig{
		Name:      streamTasks,
		Subjects:  []string{subjectTasks},
		Retention: nats.WorkQueuePolicy,
		Storage:   nats.FileStorage,
		MaxAge:    tasksMaxAge,
		Replicas:  replicas,
	}); err != nil {
		log.Fatalf("ensure stream %s: %v", streamTasks, err)
	}
	if err := ensureStream(js, &nats.StreamConfig{
		Name:      streamResults,
		Subjects:  []string{subjectResults},
		Retention: nats.LimitsPolicy,
		Storage:   nats.FileStorage,
		MaxAge:    resultsMaxAge,
		Replicas:  replicas,
	}); err != nil {
		log.Fatalf("ensure stream %s: %v", streamResults, err)
	}

	if _, err := js.AddConsumer(streamTasks, &nats.ConsumerConfig{
		Durable:       consumerName,
		AckPolicy:     nats.AckExplicitPolicy,
		FilterSubject: subjectTasks,
		MaxDeliver:    5,
	}); err != nil && !alreadyExists(err) {
		log.Fatalf("ensure consumer %s: %v", consumerName, err)
	}

	sub, err := js.PullSubscribe(subjectTasks, consumerName, nats.BindStream(streamTasks))
	if err != nil {
		log.Fatalf("pull subscribe: %v", err)
	}

	log.Printf("shapoclyack-recon worker started (nats=%s stream=%s consumer=%s)", natsURL, streamTasks, consumerName)

fetchLoop:
	for {
		select {
		case <-ctx.Done():
			break fetchLoop
		default:
		}

		msgs, err := sub.Fetch(1, nats.MaxWait(2*time.Second))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			log.Printf("fetch error: %v", err)
			continue
		}

		for _, msg := range msgs {
			handleMessage(js, msg)
		}
	}

	log.Println("shutting down: draining NATS connection")
	if err := nc.Drain(); err != nil {
		log.Printf("drain error: %v", err)
	}
	log.Println("drained, exiting")
}

// handleMessage parses, discovers, and publishes the result for a single
// task message, then acks/naks/terms it appropriately.
func handleMessage(js nats.JetStreamContext, msg *nats.Msg) {
	var task models.ReconTask
	if err := json.Unmarshal(msg.Data, &task); err != nil {
		log.Printf("malformed task JSON, terminating message: %v", err)
		_ = msg.Term()
		return
	}

	assets, err := discovery.Run(task.Seed)
	if err != nil {
		if errors.Is(err, discovery.ErrUnhandledSeedType) {
			log.Printf("task %s: unhandled seed %+v, terminating message", task.TaskID, task.Seed)
			_ = msg.Term()
			return
		}
		log.Printf("task %s: discovery error, terminating message: %v", task.TaskID, err)
		_ = msg.Term()
		return
	}

	result := models.ReconResult{
		TaskID:           task.TaskID,
		TenantID:         task.TenantID,
		Status:           "ok",
		DiscoveredAssets: assets,
	}

	body, err := json.Marshal(result)
	if err != nil {
		log.Printf("task %s: marshal result failed, terminating message: %v", task.TaskID, err)
		_ = msg.Term()
		return
	}

	tenant := sanitizeTenant(task.TenantID)
	subject := fmt.Sprintf("recon.results.%s", tenant)
	msgID := reconMsgID(task.TaskID, task.TenantID, result.Status)

	pubMsg := &nats.Msg{
		Subject: subject,
		Data:    body,
		Header: nats.Header{
			"Nats-Msg-Id": []string{msgID},
			"tenant_id":   []string{tenant},
		},
	}

	if _, err := js.PublishMsg(pubMsg); err != nil {
		log.Printf("task %s: publish to %s failed, nak for redelivery: %v", task.TaskID, subject, err)
		_ = msg.Nak()
		return
	}

	if err := msg.Ack(); err != nil {
		log.Printf("task %s: ack failed: %v", task.TaskID, err)
	}
}

// ensureStream idempotently creates or reconciles a JetStream stream,
// tolerating races between concurrently starting worker replicas.
func ensureStream(js nats.JetStreamContext, cfg *nats.StreamConfig) error {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if _, err := js.AddStream(cfg); err == nil {
			return nil
		} else if !alreadyExists(err) {
			lastErr = err
		} else if _, uerr := js.UpdateStream(cfg); uerr == nil {
			return nil
		} else if _, ierr := js.StreamInfo(cfg.Name); ierr == nil {
			return nil
		} else {
			lastErr = ierr
		}
		time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
	}
	return fmt.Errorf("stream %s not ready after retries: %w", cfg.Name, lastErr)
}

func alreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already")
}

// sanitizeTenant mirrors api/services/nats_bus.py's ingest_results_subject:
// keep [a-zA-Z0-9_-], fall back to "default" for an empty/fully-stripped tenant.
func sanitizeTenant(tenantID string) string {
	var b strings.Builder
	for _, ch := range tenantID {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			b.WriteRune(ch)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}

// reconMsgID mirrors api/services/nats_bus.py's ingest_msg_id: a stable
// idempotency key for JetStream dedupe, derived from task identity fields.
func reconMsgID(taskID, tenantID, status string) string {
	raw := fmt.Sprintf("%s:%s:%s", taskID, tenantID, status)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)[:48]
}

func intEnv(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("invalid int for %s=%q; using default %d", name, raw, def)
		return def
	}
	return v
}
