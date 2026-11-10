package gcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

const (
	vpcFlowLogSuffix    = "/logs/compute.googleapis.com%2Fvpc_flows"
	maxFlowLogEntrySize = 256 << 10
)

// errNotFlowLog marks a log entry that is not a VPC Flow Log, such as one a
// broader sink filter let through. Receivers skip it.
var errNotFlowLog = errors.New("log entry is not a GCP VPC Flow Log")

// flowLogEntry is the subset of a Cloud Logging LogEntry that carries a VPC
// Flow Log record.
type flowLogEntry struct {
	LogName   string          `json:"logName"`
	InsertID  string          `json:"insertId"`
	Timestamp string          `json:"timestamp"`
	Payload   *flowLogPayload `json:"jsonPayload"`
}

type flowLogPayload struct {
	Connection *struct {
		SourceIP        string   `json:"src_ip"`
		DestinationIP   string   `json:"dest_ip"`
		SourcePort      jsonUint `json:"src_port"`
		DestinationPort jsonUint `json:"dest_port"`
		Protocol        jsonUint `json:"protocol"`
	} `json:"connection"`
	Reporter       string      `json:"reporter"`
	PacketsSent    jsonUint    `json:"packets_sent"`
	BytesSent      jsonUint    `json:"bytes_sent"`
	StartTime      string      `json:"start_time"`
	EndTime        string      `json:"end_time"`
	Disposition    string      `json:"disposition"`
	DropReason     string      `json:"drop_reason"`
	SourceVPC      *flowLogVPC `json:"src_vpc"`
	DestinationVPC *flowLogVPC `json:"dest_vpc"`
}

type flowLogVPC struct {
	ProjectID string `json:"project_id"`
	VPCName   string `json:"vpc_name"`
}

// jsonUint accepts a JSON number or a decimal string, because proto3 JSON
// encodes int64 fields as strings and int32 fields as numbers.
type jsonUint struct {
	value uint64
	set   bool
}

func (number *jsonUint) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	text := strings.Trim(string(data), `"`)
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid unsigned integer %q", text)
	}
	number.value, number.set = value, true
	return nil
}

// NormalizeVPCFlowLog maps one Cloud Logging LogEntry JSON holding a VPC Flow
// Log record to a telemetry event between network-destination claims for the
// source and destination addresses. Both claims use the reporting side's
// network realm gcp/<host-project-id>/<network>, which the inventory and
// --kubernetes-network-id share, so rollup resolution binds them to network
// interfaces or Pods. Records reported by the source are egress and records
// reported by the destination are ingress. Flow logs are sampled, so the
// packet count is an estimate and absence of a flow proves nothing. The event
// ID digests the source ID, insertId, and timestamp, so Pub/Sub redelivery is
// idempotent.
func NormalizeVPCFlowLog(scope ProjectionContext, data []byte) (telemetry.Event, error) {
	scope.SourceID = strings.TrimSpace(scope.SourceID)
	if scope.SourceID == "" {
		return telemetry.Event{}, errors.New("GCP VPC Flow Log normalization requires a source ID")
	}
	if len(data) > maxFlowLogEntrySize {
		return telemetry.Event{}, fmt.Errorf("GCP VPC Flow Log entry exceeds %d bytes", maxFlowLogEntrySize)
	}
	var entry flowLogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return telemetry.Event{}, fmt.Errorf("decode GCP log entry: %w", err)
	}
	if !strings.HasSuffix(entry.LogName, vpcFlowLogSuffix) {
		return telemetry.Event{}, errNotFlowLog
	}
	record := entry.Payload
	if record == nil || record.Connection == nil {
		return telemetry.Event{}, errors.New("GCP VPC Flow Log requires a connection")
	}
	insertID := strings.TrimSpace(entry.InsertID)
	timestamp, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
	if insertID == "" || err != nil {
		return telemetry.Event{}, errors.New("GCP VPC Flow Log requires insertId and an RFC 3339 timestamp")
	}
	sourceAddress, err := netip.ParseAddr(record.Connection.SourceIP)
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("invalid GCP VPC Flow Log source address: %w", err)
	}
	destinationAddress, err := netip.ParseAddr(record.Connection.DestinationIP)
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("invalid GCP VPC Flow Log destination address: %w", err)
	}
	connection := record.Connection
	if connection.SourcePort.value > 65535 || connection.DestinationPort.value > 65535 || !connection.Protocol.set || connection.Protocol.value > 255 {
		return telemetry.Event{}, errors.New("GCP VPC Flow Log requires a protocol and valid ports")
	}
	if record.PacketsSent.value == 0 {
		return telemetry.Event{}, errors.New("GCP VPC Flow Log packet count must be positive")
	}
	start, err := time.Parse(time.RFC3339Nano, record.StartTime)
	if err != nil {
		return telemetry.Event{}, errors.New("GCP VPC Flow Log requires an RFC 3339 start time")
	}
	end, err := time.Parse(time.RFC3339Nano, record.EndTime)
	if err != nil || end.Before(start) {
		return telemetry.Event{}, errors.New("GCP VPC Flow Log end time must not precede its start time")
	}
	var direction string
	var reporterVPC *flowLogVPC
	switch record.Reporter {
	case "SRC", "SRC_GATEWAY":
		direction, reporterVPC = "egress", record.SourceVPC
	case "DEST", "DEST_GATEWAY":
		direction, reporterVPC = "ingress", record.DestinationVPC
	default:
		return telemetry.Event{}, fmt.Errorf("unsupported GCP VPC Flow Log reporter %q", record.Reporter)
	}
	if reporterVPC == nil || !validProjectID(reporterVPC.ProjectID) || !validGCPName(reporterVPC.VPCName) {
		return telemetry.Event{}, errors.New("GCP VPC Flow Log requires the reporting side's VPC project and network")
	}
	// Ingress firewall drops are never logged; only egress drops are.
	outcome := "allowed"
	switch record.Disposition {
	case "", "ALLOWED":
	case "DROPPED":
		outcome = "denied"
	default:
		return telemetry.Event{}, fmt.Errorf("unsupported GCP VPC Flow Log disposition %q", record.Disposition)
	}
	authority := networkAuthority(reporterVPC.ProjectID, reporterVPC.VPCName)
	subject, err := graph.NetworkDestinationClaim(authority, "ip/"+sourceAddress.Unmap().String())
	if err != nil {
		return telemetry.Event{}, err
	}
	object, err := graph.NetworkDestinationClaim(authority, "ip/"+destinationAddress.Unmap().String())
	if err != nil {
		return telemetry.Event{}, err
	}
	destinationClass, err := telemetry.ClassifyDestinationIP(destinationAddress.String())
	if err != nil {
		return telemetry.Event{}, err
	}
	properties := map[string]string{
		"protocol":             flowProtocol(connection.Protocol.value),
		"source-port":          strconv.FormatUint(connection.SourcePort.value, 10),
		"destination-port":     strconv.FormatUint(connection.DestinationPort.value, 10),
		"destination-ip-class": destinationClass,
		"reporter":             strings.ToLower(record.Reporter),
		"sampled":              "true",
	}
	if record.BytesSent.set {
		properties["bytes-sent"] = strconv.FormatUint(record.BytesSent.value, 10)
	}
	if reason := strings.TrimSpace(record.DropReason); reason != "" && len(reason) <= 128 {
		properties["drop-reason"] = reason
	}
	digest := sha256.Sum256([]byte(scope.SourceID + "\x00" + insertID + "\x00" + timestamp.UTC().Format(time.RFC3339Nano)))
	eventID := "gcp-vpc-flow:" + scope.SourceID + ":sha256:" + hex.EncodeToString(digest[:])
	return telemetry.Event{
		EventID: eventID, PluginID: PluginID, SourceID: scope.SourceID,
		ObservedAt: end.UTC(), Kind: telemetry.EventKindNetworkFlow, Subject: subject, Object: object,
		Operation: direction, Outcome: outcome, Coverage: "gcp-vpc-flow-log", Count: record.PacketsSent.value,
		Properties: properties, RollupProperties: map[string]string{
			"protocol": properties["protocol"], "destination-port": properties["destination-port"],
			"destination-ip-class": destinationClass,
		},
		EvidenceIDs: []string{eventID},
	}, nil
}

// validProjectID accepts project IDs, including legacy domain-scoped ones
// such as example.com:project.
func validProjectID(value string) bool {
	if value == "" || len(value) > 100 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && !strings.ContainsRune("-.:", character) {
			return false
		}
	}
	return true
}

func flowProtocol(number uint64) string {
	switch number {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return strconv.FormatUint(number, 10)
	}
}
