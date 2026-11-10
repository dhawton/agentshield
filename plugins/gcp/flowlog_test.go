package gcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const testFlowSourceID = "gcp/" + testProjectNumber

func TestNormalizeVPCFlowLogDirectionAndStableIdentity(t *testing.T) {
	scope := ProjectionContext{ProjectNumber: testProjectNumber, SourceID: testFlowSourceID}
	tests := []struct {
		reporter      string
		wantOperation string
	}{
		{reporter: "SRC", wantOperation: "egress"},
		{reporter: "DEST", wantOperation: "ingress"},
	}
	for _, test := range tests {
		t.Run(test.reporter, func(t *testing.T) {
			entry := flowLogEntryFixture(test.reporter)
			event, err := NormalizeVPCFlowLog(scope, mustJSON(t, entry))
			if err != nil {
				t.Fatal(err)
			}
			wantAuthority := "gcp/example-host/default"
			if event.Subject.AuthorityID != wantAuthority || event.Object.AuthorityID != wantAuthority ||
				event.Subject.ImmutableKey != "ip/10.76.0.5" || event.Object.ImmutableKey != "ip/10.76.1.9" {
				t.Fatalf("endpoints = %#v -> %#v", event.Subject, event.Object)
			}
			if event.PluginID != PluginID || event.SourceID != testFlowSourceID || event.Kind != "network-flow" ||
				event.Operation != test.wantOperation || event.Outcome != "allowed" || event.Count != 12 || event.Coverage != "gcp-vpc-flow-log" {
				t.Fatalf("event = %#v", event)
			}
			if event.ObservedAt != time.Date(2026, 11, 10, 12, 1, 0, 0, time.UTC) {
				t.Fatalf("observed at = %s", event.ObservedAt)
			}
			wantProperties := map[string]string{
				"protocol": "tcp", "source-port": "40000", "destination-port": "8080", "destination-ip-class": "private",
				"reporter": strings.ToLower(test.reporter), "sampled": "true", "bytes-sent": "3400",
			}
			if len(event.Properties) != len(wantProperties) {
				t.Fatalf("properties = %#v", event.Properties)
			}
			for key, value := range wantProperties {
				if event.Properties[key] != value {
					t.Fatalf("property %s = %q, want %q", key, event.Properties[key], value)
				}
			}
			if _, found := event.RollupProperties["source-port"]; found || event.RollupProperties["destination-port"] != "8080" {
				t.Fatalf("rollup properties = %#v", event.RollupProperties)
			}
			// Redelivery with another key order, number encoding, and
			// timestamp offset keeps the ID.
			entry["timestamp"] = "2026-11-10T07:01:05.123-05:00"
			entry["jsonPayload"].(map[string]any)["connection"].(map[string]any)["src_port"] = "40000"
			retry, err := NormalizeVPCFlowLog(scope, []byte("\n  "+string(mustJSON(t, entry))))
			if err != nil {
				t.Fatal(err)
			}
			if retry.EventID != event.EventID || len(event.EvidenceIDs) != 1 || event.EvidenceIDs[0] != event.EventID {
				t.Fatalf("retry identity changed: %q != %q", retry.EventID, event.EventID)
			}
			other := flowLogEntryFixture(test.reporter)
			other["insertId"] = "other"
			if different, err := NormalizeVPCFlowLog(scope, mustJSON(t, other)); err != nil || different.EventID == event.EventID {
				t.Fatalf("distinct insertId reused ID %q: %v", different.EventID, err)
			}
		})
	}
}

func TestNormalizeVPCFlowLogMapsDroppedEgress(t *testing.T) {
	entry := flowLogEntryFixture("SRC")
	payload := entry["jsonPayload"].(map[string]any)
	payload["disposition"] = "DROPPED"
	payload["drop_reason"] = "FIREWALL_DENY"
	payload["connection"].(map[string]any)["dest_ip"] = "8.8.8.8"
	event, err := NormalizeVPCFlowLog(ProjectionContext{SourceID: testFlowSourceID}, mustJSON(t, entry))
	if err != nil {
		t.Fatal(err)
	}
	if event.Outcome != "denied" || event.Properties["drop-reason"] != "FIREWALL_DENY" ||
		event.Properties["destination-ip-class"] != "public" || event.Object.ImmutableKey != "ip/8.8.8.8" {
		t.Fatalf("event = %#v", event)
	}
}

func TestNormalizeVPCFlowLogSkipsOtherLogs(t *testing.T) {
	entry := flowLogEntryFixture("SRC")
	entry["logName"] = "projects/example-host/logs/compute.googleapis.com%2Ffirewall"
	if _, err := NormalizeVPCFlowLog(ProjectionContext{SourceID: testFlowSourceID}, mustJSON(t, entry)); !errors.Is(err, errNotFlowLog) {
		t.Fatalf("error = %v, want errNotFlowLog", err)
	}
}

func TestNormalizeVPCFlowLogRejectsMalformedRecord(t *testing.T) {
	tests := map[string]func(entry, payload, connection map[string]any){
		"missing connection": func(_, payload, _ map[string]any) { delete(payload, "connection") },
		"missing insert ID":  func(entry, _, _ map[string]any) { delete(entry, "insertId") },
		"bad timestamp":      func(entry, _, _ map[string]any) { entry["timestamp"] = "yesterday" },
		"bad source address": func(_, _, connection map[string]any) { connection["src_ip"] = "pod-a" },
		"port out of range":  func(_, _, connection map[string]any) { connection["dest_port"] = 70000 },
		"missing protocol":   func(_, _, connection map[string]any) { delete(connection, "protocol") },
		"zero packets":       func(_, payload, _ map[string]any) { payload["packets_sent"] = "0" },
		"negative packets":   func(_, payload, _ map[string]any) { payload["packets_sent"] = "-3" },
		"end before start":   func(_, payload, _ map[string]any) { payload["end_time"] = "2026-11-10T11:00:00Z" },
		"unknown reporter":   func(_, payload, _ map[string]any) { payload["reporter"] = "SIDEWAYS" },
		"missing reporter VPC": func(_, payload, _ map[string]any) {
			delete(payload, "src_vpc")
			delete(payload, "dest_vpc")
		},
		"invalid network name": func(_, payload, _ map[string]any) {
			payload["src_vpc"].(map[string]any)["vpc_name"] = "Default/x"
			payload["dest_vpc"].(map[string]any)["vpc_name"] = "Default/x"
		},
		"unknown disposition": func(_, payload, _ map[string]any) { payload["disposition"] = "MAYBE" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			entry := flowLogEntryFixture("SRC")
			payload := entry["jsonPayload"].(map[string]any)
			connection, _ := payload["connection"].(map[string]any)
			mutate(entry, payload, connection)
			if _, err := NormalizeVPCFlowLog(ProjectionContext{SourceID: testFlowSourceID}, mustJSON(t, entry)); err == nil || errors.Is(err, errNotFlowLog) {
				t.Fatalf("malformed record error = %v", err)
			}
		})
	}
	if _, err := NormalizeVPCFlowLog(ProjectionContext{SourceID: testFlowSourceID}, []byte("{")); err == nil {
		t.Fatal("truncated JSON was accepted")
	}
	if _, err := NormalizeVPCFlowLog(ProjectionContext{SourceID: testFlowSourceID}, []byte(strings.Repeat(" ", maxFlowLogEntrySize+1))); err == nil {
		t.Fatal("oversized entry was accepted")
	}
	if _, err := NormalizeVPCFlowLog(ProjectionContext{}, mustJSON(t, flowLogEntryFixture("SRC"))); err == nil {
		t.Fatal("missing source ID was accepted")
	}
}

// flowLogEntryFixture is shaped like an entry a Logging sink publishes: int64
// counters are strings and int32 ports and protocol are numbers.
func flowLogEntryFixture(reporter string) map[string]any {
	vpc := func() map[string]any {
		return map[string]any{"project_id": "example-host", "vpc_name": "default", "subnetwork_name": "default", "subnetwork_region": "us-east1"}
	}
	instance := func(name string) map[string]any {
		return map[string]any{"project_id": "example-project", "region": "us-east1", "zone": "us-east1-b", "vm_name": name}
	}
	return map[string]any{
		"insertId":  "1a2b3c",
		"logName":   "projects/example-host/logs/compute.googleapis.com%2Fvpc_flows",
		"timestamp": "2026-11-10T12:01:05.123Z",
		"resource":  map[string]any{"type": "gce_subnetwork", "labels": map[string]any{"project_id": "example-host", "subnetwork_name": "default"}},
		"jsonPayload": map[string]any{
			"connection": map[string]any{"src_ip": "10.76.0.5", "dest_ip": "10.76.1.9", "src_port": 40000, "dest_port": 8080, "protocol": 6},
			"reporter":   reporter, "packets_sent": "12", "bytes_sent": "3400",
			"start_time": "2026-11-10T12:00:00Z", "end_time": "2026-11-10T12:01:00Z",
			"src_instance": instance("node-a"), "dest_instance": instance("node-b"), "src_vpc": vpc(), "dest_vpc": vpc(),
			"src_gke_details": map[string]any{"cluster": map[string]any{"cluster_name": "test", "cluster_location": "us-east1-b"}},
		},
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
