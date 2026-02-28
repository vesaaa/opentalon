// Package agent implements the OpenTalon agent daemon.
// It periodically collects metrics and reports them to the server data-plane (port 1616).
// Every outbound HTTP request carries: Authorization: Bearer <token>
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/vesaa/opentalon/internal/config"
	"github.com/vesaa/opentalon/internal/models"
)

// RegisterPayload is sent once at startup to create/update the device record.
type RegisterPayload struct {
	Hostname    string             `json:"hostname"`
	IP          string             `json:"ip"`
	OS          string             `json:"os"`
	GatewayIP   string             `json:"gateway_ip"`
	Group       string             `json:"group"`
	NetworkMode models.NetworkMode `json:"network_mode"`
	ParentID    *uint              `json:"parent_id,omitempty"`
	AgentVer    string             `json:"agent_ver"`
}

// MetricsPayload wraps a Snapshot for HTTP transport.
type MetricsPayload struct {
	Hostname       string  `json:"hostname"`
	IP             string  `json:"ip"`
	GatewayIP      string  `json:"gateway_ip"`
	CPUUsage       float64 `json:"cpu_usage"`
	MemUsage       float64 `json:"mem_usage"`
	DiskUsage      float64 `json:"disk_usage"`
	RxBytes        int64   `json:"rx_bytes"`
	TxBytes        int64   `json:"tx_bytes"`
	TCPConnections int     `json:"tcp_connections"`
	UDPConnections int     `json:"udp_connections"`
}

const agentVersion = "v0.1.0"

// Run starts the agent main loop. It registers with the server data-plane, then
// periodically collects and posts metrics.
//
// cfg.AgentJoinAddr is the data-plane address, e.g. "192.168.1.1:1616".
// cfg.AgentOutboundToken is sent in every request as "Authorization: Bearer <token>".
func Run(cfg *config.Config) error {
	base := fmt.Sprintf("http://%s", cfg.AgentJoinAddr)
	collector := NewCollector()
	token := cfg.AgentOutboundToken

	// Warmup: seed bandwidth baseline before first real report.
	_, _ = collector.Collect()
	time.Sleep(time.Duration(cfg.AgentInterval) * time.Millisecond * 100)

	// ── Initial registration ────────────────────────────────────────────────
	snap, err := collector.Collect()
	if err != nil {
		return fmt.Errorf("initial collect: %w", err)
	}

	var parentID *uint
	if cfg.AgentParentID != 0 {
		id := cfg.AgentParentID
		parentID = &id
	}

	reg := RegisterPayload{
		Hostname:    snap.Hostname,
		IP:          snap.LocalIP,
		OS:          snap.OS,
		GatewayIP:   snap.GatewayIP,
		Group:       cfg.AgentGroup,
		NetworkMode: models.NetworkMode(cfg.AgentNetworkMode),
		ParentID:    parentID,
		AgentVer:    agentVersion,
	}

	if err := postJSON(base+"/api/devices/register", token, reg); err != nil {
		fmt.Printf("[agent] registration warning: %v\n", err)
	} else {
		fmt.Printf("[agent] registered as %s (%s) → server %s\n", snap.Hostname, snap.LocalIP, base)
	}

	// ── Periodic reporting loop ─────────────────────────────────────────────
	ticker := time.NewTicker(time.Duration(cfg.AgentInterval) * time.Second)
	defer ticker.Stop()

	fmt.Printf("[agent] reporting every %ds. Press Ctrl+C to stop.\n", cfg.AgentInterval)
	for range ticker.C {
		snap, err := collector.Collect()
		if err != nil {
			fmt.Printf("[agent] collect error: %v\n", err)
			continue
		}

		payload := MetricsPayload{
			Hostname:       snap.Hostname,
			IP:             snap.LocalIP,
			GatewayIP:      snap.GatewayIP,
			CPUUsage:       snap.CPUUsage,
			MemUsage:       snap.MemUsage,
			DiskUsage:      snap.DiskUsage,
			RxBytes:        snap.RxBytes,
			TxBytes:        snap.TxBytes,
			TCPConnections: snap.TCPConnections,
			UDPConnections: snap.UDPConnections,
		}

		if err := postJSON(base+"/api/metrics", token, payload); err != nil {
			fmt.Printf("[agent] report error: %v\n", err)
		}
	}
	return nil
}

// postJSON sends v as JSON via HTTP POST with the Bearer token in the Authorization header.
// This ensures every data-plane request is authenticated.
func postJSON(url, bearerToken string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("server rejected token (401) — check --token or agent_token in config")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}
