// Package agent implements the OpenTalon agent daemon.
// It periodically collects metrics and reports them to the server data-plane (port 1616).
// Every outbound HTTP request carries: Authorization: Bearer <token>
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/vesaa/opentalon/internal/config"
	"github.com/vesaa/opentalon/internal/models"
	"github.com/vesaa/opentalon/internal/scanner"
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
	// LANIPs / WANIPs mirror Snapshot.LANIPs / Snapshot.WANIPs，方便 Server 做更精细的拓扑推导与展示。
	LANIPs []string `json:"lan_ips,omitempty"`
	WANIPs []string `json:"wan_ips,omitempty"`
}

// MetricsPayload wraps a Snapshot for HTTP transport.
type MetricsPayload struct {
	Hostname       string  `json:"hostname"`
	IP             string  `json:"ip"`
	GatewayIP      string  `json:"gateway_ip"`
	CPUUsage       float64 `json:"cpu_usage"`
	MemUsage       float64 `json:"mem_usage"`
	MemTotal       uint64  `json:"mem_total"`
	DiskUsage      float64 `json:"disk_usage"`
	RxBytes        int64   `json:"rx_bytes"`
	TxBytes        int64   `json:"tx_bytes"`
	TCPConnections int     `json:"tcp_connections"`
	UDPConnections int     `json:"udp_connections"`
}

// agentVersion is set at build time via -ldflags "-X github.com/vesaa/opentalon/internal/agent.agentVersion=...".
var agentVersion = "dev"

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
		LANIPs:      snap.LANIPs,
		WANIPs:      snap.WANIPs,
	}

	if err := postJSON(base+"/api/devices/register", token, reg, cfg.AgentDebugHTTP); err != nil {
		fmt.Printf("[agent] registration warning: %v\n", err)
	} else {
		fmt.Printf("[agent] registered as %s (%s) → server %s\n", snap.Hostname, snap.LocalIP, base)
	}

	// helper: send one metrics snapshot to server
	reportOnce := func() {
		snap, err := collector.Collect()
		if err != nil {
			fmt.Printf("[agent] collect error: %v\n", err)
			return
		}

		payload := MetricsPayload{
			Hostname:       snap.Hostname,
			IP:             snap.LocalIP,
			GatewayIP:      snap.GatewayIP,
			CPUUsage:       snap.CPUUsage,
			MemUsage:       snap.MemUsage,
			MemTotal:       snap.MemTotal,
			DiskUsage:      snap.DiskUsage,
			RxBytes:        snap.RxBytes,
			TxBytes:        snap.TxBytes,
			TCPConnections: snap.TCPConnections,
			UDPConnections: snap.UDPConnections,
		}

		var metricsResp struct {
			OK       bool `json:"ok"`
			ScanTask bool `json:"scan_task"`
		}
		if err := postJSONResp(base+"/api/metrics", token, payload, &metricsResp, cfg.AgentDebugHTTP); err != nil {
			fmt.Printf("[agent] report error: %v\n", err)
			return
		}
		if metricsResp.ScanTask && cfg.DiscoveryEnabled {
			go runScan(base, token, snap.LocalIP, cfg.AgentDebugHTTP)
		}
	}

	// Send first metrics immediately after registration so Web UI can show data
	reportOnce()

	// ── Periodic reporting loop ─────────────────────────────────────────────
	ticker := time.NewTicker(time.Duration(cfg.AgentInterval) * time.Second)
	defer ticker.Stop()

	fmt.Printf("[agent] reporting every %ds. Press Ctrl+C to stop.\n", cfg.AgentInterval)
	for range ticker.C {
		reportOnce()
	}
	return nil
}

// postJSON sends v as JSON via HTTP POST with Bearer token authentication.
func postJSON(url, bearerToken string, v any, debug bool) error {
	return postJSONResp(url, bearerToken, v, nil, debug)
}

// postJSONResp sends v as JSON POST and optionally decodes the response body into out.
func postJSONResp(url, bearerToken string, v any, out any, debug bool) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}

	if debug {
		fmt.Printf("[agent] POST %s\n", url)
		fmt.Printf("[agent]   payload: %s\n", string(body))
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

	if debug {
		fmt.Printf("[agent]   status: %d\n", resp.StatusCode)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("server rejected token (401) — check --token or agent_token in config")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			// non-fatal: response body decode failure doesn't break reporting
			_ = err
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return nil
}

// runScan performs an ARP scan of all local subnets and reports results to the server.
func runScan(base, token, localIP string, debug bool) {
	results, err := scanner.ScanLocalSubnets(localIP)
	if err != nil {
		if debug {
			fmt.Printf("[agent] scan error: %v\n", err)
		}
		return
	}
	if len(results) == 0 {
		return
	}
	type reportPayload struct {
		ScannerIP string               `json:"scanner_ip"`
		Devices   []scanner.ScanResult `json:"devices"`
	}
	payload := reportPayload{ScannerIP: localIP, Devices: results}
	if err := postJSON(base+"/api/discovered/report", token, payload, debug); err != nil {
		if debug {
			fmt.Printf("[agent] scan report error: %v\n", err)
		}
	} else if debug {
		fmt.Printf("[agent] scan reported %d devices\n", len(results))
	}
}
