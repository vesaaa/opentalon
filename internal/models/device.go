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

	// LANIPs stores all private IPv4 addresses (RFC1918) observed on this node,
	// serialized as a comma-separated string. Used for multi-segment topology
	// inference when a device has multiple intranet interfaces (e.g. 192.168.x
	// and 10.x).
	LANIPs string `json:"lan_ips"`
	// WANIPs stores public / non-RFC1918 IPv4 addresses, also comma-separated,
	// used primarily for display (e.g. router's WAN IP).
	WANIPs string `json:"wan_ips"`

	// GatewayIP reported by agent; server uses this to auto-wire parent links.
	GatewayIP string `gorm:"index" json:"gateway_ip"`

	// Classification
	NetworkMode NetworkMode `gorm:"default:'Bridged'" json:"network_mode"`
	Group       string      `gorm:"index;default:'default'" json:"group"`

	// Lifecycle
	LastSeen time.Time `json:"last_seen"`
	AgentVer string    `json:"agent_ver"`
	IsOnline bool      `gorm:"default:false" json:"is_online"`

	// TopologyDirty 标记该设备是否需要批量重算父子关系。
	// true  表示需要根据 GatewayIP 重新挂父节点
	// false 表示当前 GatewayIP 已经处理过（不论是否找到父节点）
	TopologyDirty bool `gorm:"index;default:false" json:"-"`
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
	// Status 是 UI 使用的高层状态：
	//   - "online"  : 有 metrics 且最近一次上报在心跳窗口内
	//   - "offline" : 有 metrics 但超过心跳窗口未上报
	//   - "unknown" : 尚无任何 metrics 记录（只注册过设备）
	Status   string        `json:"status"`
	LastSeen time.Time     `json:"last_seen"`
	ParentID *uint         `json:"parent_id,omitempty"`
	Children []*DeviceTree `json:"children,omitempty"`
}
