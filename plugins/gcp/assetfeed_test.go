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
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	testAssetTopic        = "projects/example-project/topics/assets"
	testAssetSubscription = "projects/example-project/subscriptions/assets"
	testInstanceAsset     = "compute.googleapis.com/Instance"
	testFirewallAsset     = "compute.googleapis.com/Firewall"
	testSubnetworkAsset   = "compute.googleapis.com/Subnetwork"
)

func TestAssetFilter(t *testing.T) {
	regional := assetFilter{projectID: "example-project", projectNumber: testProjectNumber, region: "us-east1"}
	for _, test := range []struct {
		name     string
		filter   assetFilter
		data     string
		relevant bool
		err      bool
	}{
		{name: "instance", filter: regional, data: assetJSON(testInstanceAsset, "//compute.googleapis.com/projects/example-project/zones/us-east1-b/instances/vm"), relevant: true},
		{name: "instance by project number", filter: regional, data: assetJSON(testInstanceAsset, "//compute.googleapis.com/projects/"+testProjectNumber+"/zones/us-east1-b/instances/vm"), relevant: true},
		{name: "firewall ignores region", filter: regional, data: assetJSON(testFirewallAsset, "//compute.googleapis.com/projects/example-project/global/firewalls/allow"), relevant: true},
		{name: "subnetwork", filter: regional, data: assetJSON(testSubnetworkAsset, "//compute.googleapis.com/projects/example-project/regions/us-east1/subnetworks/default"), relevant: true},
		{name: "deleted instance", filter: regional, data: `{"asset":{"name":"//compute.googleapis.com/projects/example-project/zones/us-east1-c/instances/vm","assetType":"compute.googleapis.com/Instance"},"deleted":true,"priorAssetState":"PRESENT"}`, relevant: true},
		{name: "instance in other region", filter: regional, data: assetJSON(testInstanceAsset, "//compute.googleapis.com/projects/example-project/zones/europe-west1-b/instances/vm")},
		{name: "subnetwork in other region", filter: regional, data: assetJSON(testSubnetworkAsset, "//compute.googleapis.com/projects/example-project/regions/europe-west1/subnetworks/default")},
		{name: "any region without filter", filter: assetFilter{projectID: "example-project", projectNumber: testProjectNumber}, data: assetJSON(testSubnetworkAsset, "//compute.googleapis.com/projects/example-project/regions/europe-west1/subnetworks/default"), relevant: true},
		{name: "other project", filter: regional, data: assetJSON(testFirewallAsset, "//compute.googleapis.com/projects/other-project/global/firewalls/allow")},
		{name: "network", filter: regional, data: assetJSON("compute.googleapis.com/Network", "//compute.googleapis.com/projects/example-project/global/networks/default")},
		{name: "other service", filter: regional, data: assetJSON("storage.googleapis.com/Bucket", "//storage.googleapis.com/bucket")},
		{name: "undecodable", filter: regional, data: `not json`, err: true},
		{name: "missing type", filter: regional, data: `{"asset":{"name":"//compute.googleapis.com/projects/example-project/global/firewalls/allow"}}`, err: true},
		{name: "missing asset", filter: regional, data: `{"window":{"startTime":"2026-11-17T00:00:00Z"}}`, err: true},
		{name: "wrong service prefix", filter: regional, data: assetJSON(testFirewallAsset, "//storage.googleapis.com/projects/example-project/global/firewalls/allow"), err: true},
		{name: "short instance name", filter: regional, data: assetJSON(testInstanceAsset, "//compute.googleapis.com/projects/example-project/zones/us-east1-b"), err: true},
		{name: "empty segment", filter: regional, data: assetJSON(testSubnetworkAsset, "//compute.googleapis.com/projects/example-project/regions//subnetworks/default"), err: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			relevant, err := test.filter.relevant([]byte(test.data))
			if relevant != test.relevant || (err != nil) != test.err {
				t.Fatalf("relevant = %v, %v; want %v, error %v", relevant, err, test.relevant, test.err)
			}
		})
	}
}

func TestNewAssetFeedSubscriberBoundsFlowControl(t *testing.T) {
	client, err := pubsub.NewClient(t.Context(), "example-project", option.WithoutAuthentication(), option.WithEndpoint("localhost:1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	subscriber, err := NewAssetFeedSubscriber(client, " assets ")
	if err != nil {
		t.Fatal(err)
	}
	settings := subscriber.ReceiveSettings
	if subscriber.String() != testAssetSubscription || settings.MaxOutstandingMessages != assetFeedMaxOutstandingMessages ||
		settings.MaxOutstandingBytes != assetFeedMaxOutstandingBytes || settings.MaxExtension != assetFeedMaxExtension {
		t.Fatalf("subscriber %s settings = %#v", subscriber, settings)
	}
	for _, name := range []string{"", "ab", "1assets", "goog-assets", "assets/x", "projects/p/topics/assets", "projects/Bad/subscriptions/assets", "ass ets"} {
		if _, err := NewAssetFeedSubscriber(client, name); err == nil {
			t.Errorf("subscription %q was accepted", name)
		}
	}
	if _, err := NewAssetFeedSubscriber(client, "projects/host-project/subscriptions/agentshield-assets"); err != nil {
		t.Errorf("full subscription name: %v", err)
	}
}

func TestPluginAcksAssetFeedChangeAfterCommit(t *testing.T) {
	client := &gatedCompute{gate: make(chan struct{}), entered: make(chan struct{}, 1)}
	server, runtime, _ := startAssetFeedPlugin(t, client, "")
	id := server.Publish(testAssetTopic, []byte(assetJSON(testFirewallAsset, "//compute.googleapis.com/projects/example-project/global/firewalls/allow")), nil)
	select {
	case <-client.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("asset feed change did not trigger a reconcile")
	}
	time.Sleep(100 * time.Millisecond)
	if message := server.Message(id); message.Acks != 0 {
		t.Fatalf("message acked before the reconcile committed: %#v", message)
	}
	close(client.gate)
	waitForAssetMessage(t, server, id, func(message *pstest.Message) bool { return message.Acks == 1 })
	if replacements := runtime.replacementCount(); replacements != 2 {
		t.Fatalf("replacements = %d, want 2", replacements)
	}
}

func TestPluginHoldsAssetFeedChangeUntilReconcileCommits(t *testing.T) {
	client := &gatedCompute{}
	server, runtime, _ := startAssetFeedPlugin(t, client, "")
	client.setFail(true)
	held := server.Publish(testAssetTopic, []byte(assetJSON(testFirewallAsset, "//compute.googleapis.com/projects/example-project/global/firewalls/allow")), nil)
	eventually(t, func() bool { return runtime.replacementCount() == 2 })
	time.Sleep(100 * time.Millisecond)
	if message := server.Message(held); message.Acks != 0 || assetFeedNacked(message) {
		t.Fatalf("message settled after a failed reconcile: acks = %d, modacks = %#v", message.Acks, message.Modacks)
	}
	client.setFail(false)
	next := server.Publish(testAssetTopic, []byte(assetJSON(testFirewallAsset, "//compute.googleapis.com/projects/example-project/global/firewalls/deny")), nil)
	for _, id := range []string{held, next} {
		waitForAssetMessage(t, server, id, func(message *pstest.Message) bool { return message.Acks == 1 })
	}
	if message := server.Message(held); message.Deliveries != 1 {
		t.Fatalf("held message deliveries = %d, want 1", message.Deliveries)
	}
}

func TestPluginCoalescesAssetFeedBurst(t *testing.T) {
	client := &gatedCompute{}
	server, runtime, _ := startAssetFeedPlugin(t, client, "")
	var ids []string
	for range 5 {
		ids = append(ids, server.Publish(testAssetTopic, []byte(assetJSON(testInstanceAsset, "//compute.googleapis.com/projects/example-project/zones/us-east1-b/instances/vm")), nil))
	}
	for _, id := range ids {
		waitForAssetMessage(t, server, id, func(message *pstest.Message) bool { return message.Acks == 1 })
	}
	if calls, replacements := client.callCount(), runtime.replacementCount(); calls != 2 || replacements != 2 {
		t.Fatalf("compute calls = %d, replacements = %d; want one reconcile after the initial one", calls, replacements)
	}
}

func TestPluginAcksMalformedAndIrrelevantAssetFeedMessages(t *testing.T) {
	client := &gatedCompute{}
	server, runtime, plugin := startAssetFeedPlugin(t, client, "us-east1")
	var ids []string
	for _, data := range []string{
		`not json`,
		`{"asset":{"assetType":"compute.googleapis.com/Instance"}}`,
		assetJSON("compute.googleapis.com/Network", "//compute.googleapis.com/projects/example-project/global/networks/default"),
		assetJSON(testFirewallAsset, "//compute.googleapis.com/projects/other-project/global/firewalls/allow"),
		assetJSON(testInstanceAsset, "//compute.googleapis.com/projects/example-project/zones/europe-west1-b/instances/vm"),
		assetJSON(testSubnetworkAsset, "//compute.googleapis.com/projects/example-project/regions/europe-west1/subnetworks/default"),
	} {
		ids = append(ids, server.Publish(testAssetTopic, []byte(data), nil))
	}
	for _, id := range ids {
		waitForAssetMessage(t, server, id, func(message *pstest.Message) bool { return message.Acks == 1 })
	}
	time.Sleep(2 * assetFeedCoalesceWindow)
	if discarded, ignored := plugin.feed.discarded.Load(), plugin.feed.ignored.Load(); discarded != 2 || ignored != 4 {
		t.Fatalf("discarded = %d, ignored = %d; want 2 and 4", discarded, ignored)
	}
	if calls, replacements := client.callCount(), runtime.replacementCount(); calls != 1 || replacements != 1 {
		t.Fatalf("compute calls = %d, replacements = %d; want only the initial reconcile", calls, replacements)
	}
}

func TestPluginStopsWhenAssetFeedFails(t *testing.T) {
	config := testConfig(emptyCompute{}, time.Hour)
	config.AssetFeed = failingReceiver{}
	plugin, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = plugin.Run(t.Context(), &recordingRuntime{})
	if err == nil || !errors.Is(err, errSubscriptionMissing) {
		t.Fatalf("Run error = %v, want the subscription error", err)
	}
}

// startAssetFeedPlugin runs a plugin whose asset feed reads a fake Pub/Sub
// subscription, and stops it at cleanup.
func startAssetFeedPlugin(t *testing.T, client ComputeAPI, region string) (*pstest.Server, *recordingRuntime, *Plugin) {
	t.Helper()
	window := assetFeedCoalesceWindow
	assetFeedCoalesceWindow = 300 * time.Millisecond
	t.Cleanup(func() { assetFeedCoalesceWindow = window })
	server := pstest.NewServer()
	t.Cleanup(func() { _ = server.Close() })
	connection, err := grpc.NewClient(server.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	pubsubClient, err := pubsub.NewClient(t.Context(), "example-project", option.WithGRPCConn(connection))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pubsubClient.TopicAdminClient.CreateTopic(t.Context(), &pb.Topic{Name: testAssetTopic}); err != nil {
		t.Fatal(err)
	}
	if _, err := pubsubClient.SubscriptionAdminClient.CreateSubscription(t.Context(), &pb.Subscription{
		Name: testAssetSubscription, Topic: testAssetTopic, AckDeadlineSeconds: 10,
	}); err != nil {
		t.Fatal(err)
	}
	subscriber, err := NewAssetFeedSubscriber(pubsubClient, "assets")
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig(client, time.Hour)
	config.Region = region
	config.AssetFeed = subscriber
	plugin, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &recordingRuntime{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- plugin.Run(ctx, runtime) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	})
	eventually(t, func() bool { return runtime.replacementCount() == 1 })
	return server, runtime, plugin
}

func assetJSON(assetType, name string) string {
	return `{"asset":{"name":"` + name + `","assetType":"` + assetType + `","resource":{"version":"v1"}},"window":{"startTime":"2026-11-17T00:00:00Z"},"priorAssetState":"PRESENT"}`
}

func waitForAssetMessage(t *testing.T, server *pstest.Server, id string, done func(*pstest.Message) bool) {
	t.Helper()
	eventually(t, func() bool {
		message := server.Message(id)
		return message != nil && done(message)
	})
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before the deadline")
}

func assetFeedNacked(message *pstest.Message) bool {
	for _, modack := range message.Modacks {
		if modack.AckDeadline == 0 {
			return true
		}
	}
	return false
}

// gatedCompute counts firewall lists, can fail them, and with a gate blocks
// every list after the first until the gate closes.
type gatedCompute struct {
	emptyCompute
	mu      sync.Mutex
	calls   int
	fail    bool
	gate    chan struct{}
	entered chan struct{}
}

func (c *gatedCompute) ListFirewalls(ctx context.Context, _ PageRequest) (*compute.FirewallList, error) {
	c.mu.Lock()
	c.calls++
	calls, fail := c.calls, c.fail
	c.mu.Unlock()
	if c.gate != nil && calls > 1 {
		c.entered <- struct{}{}
		select {
		case <-c.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if fail {
		return nil, errors.New("Compute unavailable")
	}
	return &compute.FirewallList{}, nil
}

func (c *gatedCompute) setFail(fail bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail = fail
}

func (c *gatedCompute) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

var errSubscriptionMissing = errors.New("subscription not found")

type failingReceiver struct{}

func (failingReceiver) Receive(context.Context, func(context.Context, *pubsub.Message)) error {
	return errSubscriptionMissing
}
