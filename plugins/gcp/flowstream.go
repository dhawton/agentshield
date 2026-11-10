package gcp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

const (
	// Each message holds one LogEntry, so these bound buffered flow records.
	flowLogMaxOutstandingMessages = 1000
	flowLogMaxOutstandingBytes    = 64 << 20
	// Messages held during pipeline backpressure keep their lease this long.
	flowLogMaxExtension    = 10 * time.Minute
	flowLogMinRetryBackoff = time.Second
	flowLogMaxRetryBackoff = time.Minute
)

// FlowLogReceiver is the Pub/Sub StreamingPull surface the flow log stream
// uses. [*pubsub.Subscriber] implements it.
type FlowLogReceiver interface {
	Receive(context.Context, func(context.Context, *pubsub.Message)) error
}

// NewFlowLogSubscriber returns a subscriber for subscription, a
// subscription ID in the client's project or a full
// projects/<project>/subscriptions/<id> name, with bounded flow control.
func NewFlowLogSubscriber(client *pubsub.Client, subscription string) (*pubsub.Subscriber, error) {
	subscription = strings.TrimSpace(subscription)
	if !validSubscription(subscription) {
		return nil, fmt.Errorf("invalid GCP Pub/Sub subscription %q", subscription)
	}
	subscriber := client.Subscriber(subscription)
	subscriber.ReceiveSettings.MaxOutstandingMessages = flowLogMaxOutstandingMessages
	subscriber.ReceiveSettings.MaxOutstandingBytes = flowLogMaxOutstandingBytes
	subscriber.ReceiveSettings.MaxExtension = flowLogMaxExtension
	return subscriber, nil
}

// validSubscription accepts a Pub/Sub subscription ID or full name.
func validSubscription(value string) bool {
	id := value
	if strings.Contains(value, "/") {
		parts := strings.Split(value, "/")
		if len(parts) != 4 || parts[0] != "projects" || !validProjectID(parts[1]) || parts[2] != "subscriptions" {
			return false
		}
		id = parts[3]
	}
	if len(id) < 3 || len(id) > 255 || strings.HasPrefix(id, "goog") || id[0] < 'A' || (id[0] > 'Z' && id[0] < 'a') || id[0] > 'z' {
		return false
	}
	for _, character := range id {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && !strings.ContainsRune("-_.~+%", character) {
			return false
		}
	}
	return true
}

// TelemetryStreams registers the optional VPC Flow Log Pub/Sub stream owned
// by this source. The host supplies only the shared event ingestor.
func (p *Plugin) TelemetryStreams(ingestor telemetry.EventIngestor) ([]discovery.TelemetryStream, error) {
	if p.config.FlowLogs == nil {
		return nil, nil
	}
	if ingestor == nil {
		return nil, errors.New("GCP VPC Flow Log stream requires a telemetry ingestor")
	}
	stream := &flowLogStream{
		projection: ProjectionContext{ProjectNumber: p.config.ProjectNumber, SourceID: p.config.SourceID},
		receiver:   p.config.FlowLogs, ingestor: ingestor,
	}
	return []discovery.TelemetryStream{{Name: "gcp-vpc-flow-logs", Run: stream.run}}, nil
}

type flowLogStream struct {
	projection ProjectionContext
	receiver   FlowLogReceiver
	ingestor   telemetry.EventIngestor
	rejected   atomic.Uint64
}

// run receives until ctx ends. Receive already retries transient errors, so
// an error here (missing subscription, denied permission) is logged and
// retried with backoff instead of stopping the process.
func (stream *flowLogStream) run(ctx context.Context) error {
	backoff := flowLogMinRetryBackoff
	for {
		started := time.Now()
		err := stream.receiver.Receive(ctx, stream.handle)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(started) > flowLogMaxRetryBackoff {
			backoff = flowLogMinRetryBackoff
		}
		log.Printf("GCP VPC Flow Log subscription stopped; retrying in %s: %v", backoff, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(2*backoff, flowLogMaxRetryBackoff)
	}
}

// handle acks a message only after the pipeline accepts its event. While the
// pipeline queue is full it holds the message, and the client keeps its lease
// and stops pulling once flow control is full. Shutdown nacks for prompt
// redelivery. A record that can never be normalized or accepted is acked so
// it cannot block the subscription.
func (stream *flowLogStream) handle(ctx context.Context, message *pubsub.Message) {
	event, err := NormalizeVPCFlowLog(stream.projection, message.Data)
	if errors.Is(err, errNotFlowLog) {
		message.Ack()
		return
	}
	if err == nil {
		err = telemetry.IngestWaiting(ctx, stream.ingestor, event)
		if err == nil {
			message.Ack()
			return
		}
		if ctx.Err() != nil || errors.Is(err, telemetry.ErrPipelineClosed) {
			message.Nack()
			return
		}
	}
	// Log the first and then every 1000th, without the payload.
	if count := stream.rejected.Add(1); count == 1 || count%1000 == 0 {
		log.Printf("GCP VPC Flow Log message %s rejected (%d total): %v", message.ID, count, err)
	}
	message.Ack()
}
