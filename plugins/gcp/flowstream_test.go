package gcp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/pubsub/v2"
	pb "cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"cloud.google.com/go/pubsub/v2/pstest"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	testFlowTopic        = "projects/example-project/topics/flows"
	testFlowSubscription = "projects/example-project/subscriptions/flows"
)

func TestFlowLogStreamAcksOnlyAfterIngest(t *testing.T) {
	server, subscriber := newFlowLogTestSubscription(t)
	ingestor := &gatedIngestor{}
	stream := startFlowLogStream(t, subscriber, ingestor)
	good := server.Publish(testFlowTopic, mustJSON(t, flowLogEntryFixture("SRC")), nil)
	malformed := server.Publish(testFlowTopic, []byte(`{"logName":"projects/p/logs/compute.googleapis.com%2Fvpc_flows"}`), nil)
	other := flowLogEntryFixture("SRC")
	other["logName"] = "projects/p/logs/syslog"
	unrelated := server.Publish(testFlowTopic, mustJSON(t, other), nil)
	for _, id := range []string{good, malformed, unrelated} {
		waitForMessage(t, server, id, func(message *pstest.Message) bool { return message.Acks == 1 })
	}
	events := ingestor.accepted()
	if len(events) != 1 || events[0].Operation != "egress" || events[0].SourceID != testFlowSourceID {
		t.Fatalf("ingested events = %#v", events)
	}
	if stream.rejected.Load() != 1 {
		t.Fatalf("rejected = %d, want 1", stream.rejected.Load())
	}
}

func TestFlowLogStreamHoldsMessagesUnderBackpressure(t *testing.T) {
	server, subscriber := newFlowLogTestSubscription(t)
	ingestor := &gatedIngestor{err: telemetry.ErrPipelineOverloaded}
	startFlowLogStream(t, subscriber, ingestor)
	id := server.Publish(testFlowTopic, mustJSON(t, flowLogEntryFixture("DEST")), nil)
	waitForMessage(t, server, id, func(*pstest.Message) bool { return ingestor.attempts() >= 3 })
	if message := server.Message(id); message.Acks != 0 || hasNack(message) {
		t.Fatalf("message settled under backpressure: acks = %d, modacks = %#v", message.Acks, message.Modacks)
	}
	ingestor.setErr(nil)
	waitForMessage(t, server, id, func(message *pstest.Message) bool { return message.Acks == 1 })
	if message := server.Message(id); message.Deliveries != 1 || len(ingestor.accepted()) != 1 {
		t.Fatalf("deliveries = %d, accepted = %d", message.Deliveries, len(ingestor.accepted()))
	}
}

func TestFlowLogStreamNacksWhenPipelineCloses(t *testing.T) {
	server, subscriber := newFlowLogTestSubscription(t)
	ingestor := &gatedIngestor{err: telemetry.ErrPipelineClosed}
	startFlowLogStream(t, subscriber, ingestor)
	id := server.Publish(testFlowTopic, mustJSON(t, flowLogEntryFixture("SRC")), nil)
	waitForMessage(t, server, id, hasNack)
	if message := server.Message(id); message.Acks != 0 || len(ingestor.accepted()) != 0 {
		t.Fatalf("closed pipeline acked: acks = %d", message.Acks)
	}
	ingestor.setErr(nil)
	waitForMessage(t, server, id, func(message *pstest.Message) bool { return message.Acks == 1 && message.Deliveries >= 2 })
}

func TestTelemetryStreamsRequiresSubscription(t *testing.T) {
	plugin, err := New(testConfig(emptyCompute{}, 0))
	if err != nil {
		t.Fatal(err)
	}
	if streams, err := plugin.TelemetryStreams(&gatedIngestor{}); err != nil || len(streams) != 0 {
		t.Fatalf("streams without subscription = %#v, %v", streams, err)
	}
	config := testConfig(emptyCompute{}, 0)
	config.FlowLogs = &pubsub.Subscriber{}
	plugin, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	streams, err := plugin.TelemetryStreams(&gatedIngestor{})
	if err != nil || len(streams) != 1 || streams[0].Name != "gcp-vpc-flow-logs" || streams[0].Run == nil {
		t.Fatalf("streams = %#v, %v", streams, err)
	}
	if _, err := plugin.TelemetryStreams(nil); err == nil {
		t.Fatal("nil ingestor was accepted")
	}
}

func TestNewFlowLogSubscriberBoundsFlowControl(t *testing.T) {
	client, err := pubsub.NewClient(t.Context(), "example-project", option.WithoutAuthentication(), option.WithEndpoint("localhost:1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	subscriber, err := NewFlowLogSubscriber(client, " flows ")
	if err != nil {
		t.Fatal(err)
	}
	settings := subscriber.ReceiveSettings
	if subscriber.String() != testFlowSubscription || settings.MaxOutstandingMessages != flowLogMaxOutstandingMessages ||
		settings.MaxOutstandingBytes != flowLogMaxOutstandingBytes || settings.MaxExtension != flowLogMaxExtension {
		t.Fatalf("subscriber %s settings = %#v", subscriber, settings)
	}
	for _, name := range []string{"", "ab", "1flows", "goog-flows", "flows/x", "projects/p/topics/flows", "projects/Bad/subscriptions/flows", "flo ws"} {
		if _, err := NewFlowLogSubscriber(client, name); err == nil {
			t.Errorf("subscription %q was accepted", name)
		}
	}
	if _, err := NewFlowLogSubscriber(client, "projects/host-project/subscriptions/agentshield-flowlogs-sub"); err != nil {
		t.Errorf("full subscription name: %v", err)
	}
}

func newFlowLogTestSubscription(t *testing.T) (*pstest.Server, *pubsub.Subscriber) {
	t.Helper()
	server := pstest.NewServer()
	t.Cleanup(func() { _ = server.Close() })
	connection, err := grpc.NewClient(server.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client, err := pubsub.NewClient(t.Context(), "example-project", option.WithGRPCConn(connection))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.TopicAdminClient.CreateTopic(t.Context(), &pb.Topic{Name: testFlowTopic}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SubscriptionAdminClient.CreateSubscription(t.Context(), &pb.Subscription{
		Name: testFlowSubscription, Topic: testFlowTopic, AckDeadlineSeconds: 10,
	}); err != nil {
		t.Fatal(err)
	}
	subscriber, err := NewFlowLogSubscriber(client, "flows")
	if err != nil {
		t.Fatal(err)
	}
	return server, subscriber
}

func startFlowLogStream(t *testing.T, receiver FlowLogReceiver, ingestor telemetry.EventIngestor) *flowLogStream {
	t.Helper()
	stream := &flowLogStream{projection: ProjectionContext{ProjectNumber: testProjectNumber, SourceID: testFlowSourceID}, receiver: receiver, ingestor: ingestor}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- stream.run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("stream returned %v, want context.Canceled", err)
		}
	})
	return stream
}

func waitForMessage(t *testing.T, server *pstest.Server, id string, done func(*pstest.Message) bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if message := server.Message(id); message != nil && done(message) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("message %s did not reach the expected state: %#v", id, server.Message(id))
}

func hasNack(message *pstest.Message) bool {
	for _, modack := range message.Modacks {
		if modack.AckDeadline == 0 {
			return true
		}
	}
	return false
}

// gatedIngestor returns err until it is cleared, then records events.
type gatedIngestor struct {
	mu     sync.Mutex
	err    error
	tries  int
	events []telemetry.Event
}

func (ingestor *gatedIngestor) Ingest(_ context.Context, events ...telemetry.Event) error {
	ingestor.mu.Lock()
	defer ingestor.mu.Unlock()
	ingestor.tries++
	if ingestor.err != nil {
		return ingestor.err
	}
	ingestor.events = append(ingestor.events, events...)
	return nil
}

func (ingestor *gatedIngestor) setErr(err error) {
	ingestor.mu.Lock()
	defer ingestor.mu.Unlock()
	ingestor.err = err
}

func (ingestor *gatedIngestor) attempts() int {
	ingestor.mu.Lock()
	defer ingestor.mu.Unlock()
	return ingestor.tries
}

func (ingestor *gatedIngestor) accepted() []telemetry.Event {
	ingestor.mu.Lock()
	defer ingestor.mu.Unlock()
	return append([]telemetry.Event(nil), ingestor.events...)
}
