// Package models defines GORM data models for OpenTalon.
package models

import (
	"time"

	"gorm.io/gorm"
)

// Metrics stores a point-in-time snapshot of a device's performance data.
// The server keeps the latest N snapshots per device for sparklines, etc.
type Metrics struct {
	gorm.Model

	DeviceID uint `gorm:"index;not null" json:"device_id"`

	// ── Compute ──────────────────────────────────────────────────────────────
	CPUUsage  float64 `json:"cpu_usage"`   // percent 0-100
	MemUsage  float64 `json:"mem_usage"`   // percent 0-100
	DiskUsage float64 `json:"disk_usage"`  // percent 0-100 (largest mount)

	// ── Network bandwidth (bytes per second, computed from delta) ───────────
	RxBytes int64 `json:"rx_bytes"` // current ingress bps
	TxBytes int64 `json:"tx_bytes"` // current egress bps

	// ── Connections ──────────────────────────────────────────────────────────
	TCPConnections int `json:"tcp_connections"`
	UDPConnections int `json:"udp_connections"`

	// ── Topology context (reported by agent) ─────────────────────────────────
	GatewayIP string    `json:"gateway_ip"` // default gateway at time of report
	LocalIP   string    `json:"local_ip"`   // primary local IP
	ReportedAt time.Time `json:"reported_at"`
}
