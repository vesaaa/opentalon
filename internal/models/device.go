// Package models defines GORM data models for OpenTalon.
package models

import (
	"time"

	"gorm.io/gorm"
)

// NetworkMode represents the network topology mode of a device.
type NetworkMode string

const (
	NetworkModeBridged NetworkMode = "Bridged"
	NetworkModeNAT     NetworkMode = "NAT"
	NetworkModeUnknown NetworkMode = "Unknown"
)

// Device represents a managed node in the OpenTalon topology.
// ParentID links virtual machines / containers to their PVE host or router.
// When GatewayIP is reported by the agent, the server auto-resolves ParentID
// by finding the device whose IP matches the reported GatewayIP.
type Device struct {
	gorm.Model

	// Identity
	Hostname string `gorm:"index;not null" json:"hostname"`
	// Remark is an optional human-friendly display name / note set from Web UI.
	Remark   string `gorm:"index" json:"remark"`
	IP       string `gorm:"uniqueIndex;not null" json:"ip"`
	OS       string `json:"os"`

	// Topology
	// ParentID: nil = root node (e.g. main router); otherwise points to parent Device.ID
	ParentID *uint       `gorm:"index" json:"parent_id,omitempty"`
	Parent   *Device     `gorm:"foreignKey:ParentID" json:"-"`
	Children []*Device   `gorm:"foreignKey:ParentID" json:"children,omitempty"`

	// GatewayIP reported by agent; server uses this to auto-wire parent links.
	GatewayIP string `gorm:"index" json:"gateway_ip"`

	// Classification
	NetworkMode NetworkMode `gorm:"default:'Bridged'" json:"network_mode"`
	Group       string      `gorm:"index;default:'default'" json:"group"`

	// Lifecycle
	LastSeen  time.Time `json:"last_seen"`
	AgentVer  string    `json:"agent_ver"`
	IsOnline  bool      `gorm:"default:false" json:"is_online"`
}

// DeviceTree is the DTO used by the API to return the full topology.
type DeviceTree struct {
	ID          uint          `json:"id"`
	Hostname    string        `json:"hostname"`
	Remark      string        `json:"remark"`
	IP          string        `json:"ip"`
	OS          string        `json:"os"`
	GatewayIP   string        `json:"gateway_ip"`
	NetworkMode NetworkMode   `json:"network_mode"`
	Group       string        `json:"group"`
	IsOnline    bool          `json:"is_online"`
	LastSeen    time.Time     `json:"last_seen"`
	ParentID    *uint         `json:"parent_id,omitempty"`
	Children    []*DeviceTree `json:"children,omitempty"`
}
