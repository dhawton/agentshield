package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"cloud.google.com/go/pubsub/v2"
)

const (
	assetFeedMaxOutstandingMessages = 1000
	assetFeedMaxOutstandingBytes    = 64 << 20
	// Messages wait for a committed reconcile, at worst the next poll.
	assetFeedMaxExtension = 10 * time.Minute
	computeAssetPrefix    = "//compute.googleapis.com/"
)

// assetFeedCoalesceWindow gathers a burst of changes into one reconcile.
var assetFeedCoalesceWindow = 5 * time.Second

// AssetFeedReceiver is the Pub/Sub StreamingPull surface the asset feed
// uses. [*pubsub.Subscriber] implements it.
type AssetFeedReceiver interface {
	Receive(context.Context, func(context.Context, *pubsub.Message)) error
}

// NewAssetFeedSubscriber returns a subscriber for subscription, a
// subscription ID in the client's project or a full
// projects/<project>/subscriptions/<id> name, with bounded flow control.
func NewAssetFeedSubscriber(client *pubsub.Client, subscription string) (*pubsub.Subscriber, error) {
	subscription = strings.TrimSpace(subscription)
	if !validSubscription(subscription) {
		return nil, fmt.Errorf("invalid GCP Pub/Sub subscription %q", subscription)
	}
	subscriber := client.Subscriber(subscription)
	subscriber.ReceiveSettings.MaxOutstandingMessages = assetFeedMaxOutstandingMessages
	subscriber.ReceiveSettings.MaxOutstandingBytes = assetFeedMaxOutstandingBytes
	subscriber.ReceiveSettings.MaxExtension = assetFeedMaxExtension
	return subscriber, nil
}

// assetFeed turns Cloud Asset Inventory feed messages into reconcile
// triggers. Messages are hints, not state: a missing or duplicate message
// only changes latency, because the poll reads the current state.
type assetFeed struct {
	receiver AssetFeedReceiver
	filter   assetFilter
	changes  chan *pubsub.Message
	// discarded counts malformed messages acked without reconciling.
	discarded atomic.Uint64
	// ignored counts other asset types, projects, and regions.
	ignored atomic.Uint64
}

func newAssetFeed(receiver AssetFeedReceiver, filter assetFilter) *assetFeed {
	return &assetFeed{receiver: receiver, filter: filter, changes: make(chan *pubsub.Message)}
}

// run receives until ctx ends. Receive retries transient errors itself, so
// an error here, such as a missing subscription or denied permission, stops
// the plugin as an AWS queue error does.
func (feed *assetFeed) run(ctx context.Context, failures chan<- error) {
	err := feed.receiver.Receive(ctx, feed.handle)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("subscription stopped")
	}
	select {
	case failures <- fmt.Errorf("receive GCP asset feed: %w", err):
	case <-ctx.Done():
	}
}

// handle acks malformed and irrelevant messages at once and passes relevant
// ones to the plugin, which acks them after a committed reconcile. A
// malformed message can never become valid, so it is acked rather than
// redelivered forever.
func (feed *assetFeed) handle(ctx context.Context, message *pubsub.Message) {
	relevant, err := feed.filter.relevant(message.Data)
	if err != nil {
		// The body is never logged.
		total := feed.discarded.Add(1)
		slog.WarnContext(ctx, "discarding malformed GCP asset feed message", "message_id", message.ID, "reason", err.Error(), "discarded_total", total)
		message.Ack()
		return
	}
	if !relevant {
		feed.ignored.Add(1)
		message.Ack()
		return
	}
	select {
	case feed.changes <- message:
	case <-ctx.Done():
		message.Nack()
	}
}

// assetFilter matches the resources one source captures.
type assetFilter struct {
	projectID     string
	projectNumber string
	region        string
}

// relevant reports whether a TemporalAsset names an instance, firewall, or
// subnetwork this source captures. Networks are not captured; deleting one
// first deletes its firewalls and subnetworks, which do arrive. It returns
// an error only for a message that can never be read.
func (f assetFilter) relevant(data []byte) (bool, error) {
	var message struct {
		Asset struct {
			Name      string `json:"name"`
			AssetType string `json:"assetType"`
		} `json:"asset"`
	}
	if err := json.Unmarshal(data, &message); err != nil {
		// The decode error can quote the body.
		return false, errors.New("undecodable JSON")
	}
	name, assetType := message.Asset.Name, message.Asset.AssetType
	if name == "" || assetType == "" {
		return false, errors.New("missing asset name or type")
	}
	var scope, collection string
	switch assetType {
	case "compute.googleapis.com/Instance":
		scope, collection = "zones", "instances"
	case "compute.googleapis.com/Firewall":
		scope, collection = "global", "firewalls"
	case "compute.googleapis.com/Subnetwork":
		scope, collection = "regions", "subnetworks"
	default:
		return false, nil
	}
	path, found := strings.CutPrefix(name, computeAssetPrefix)
	// projects/<p>/global/firewalls/<n> or projects/<p>/<scope>/<location>/<collection>/<n>
	parts := strings.Split(path, "/")
	size := 6
	if scope == "global" {
		size = 5
	}
	if !found || len(parts) != size || parts[0] != "projects" || parts[2] != scope || parts[size-2] != collection || slices.Contains(parts, "") {
		return false, fmt.Errorf("unexpected %s name", assetType)
	}
	if parts[1] != f.projectID && parts[1] != f.projectNumber {
		return false, nil
	}
	switch {
	case f.region == "" || scope == "global":
		return true, nil
	case scope == "zones":
		return zoneRegion(parts[3]) == f.region, nil
	default:
		return parts[3] == f.region, nil
	}
}
