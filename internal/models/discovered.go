package models

import (
	"time"

	"gorm.io/gorm"
)

// DiscoveredDevice represents a host found by ARP scan that has not yet been
// managed by an OpenTalon agent. Operators can "adopt" these devices by
// assigning them a group or parent device.
//
// Fields are declared explicitly (instead of embedding gorm.Model) so that
// the primary key serialises as lowercase "id" in JSON responses, which is
// what the Vue frontend expects.
type DiscoveredDevice struct {
	ID        uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time      `json:"-"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	IP        string    `gorm:"uniqueIndex;not null" json:"ip"`
	MAC       string    `json:"mac"`
	Hostname  string    `json:"hostname"`
	Vendor    string    `json:"vendor"`     // OUI manufacturer name
	OSHint    string    `json:"os_hint"`    // "Windows" / "Linux" / "Network" (TTL-based)
	ScannerIP string    `json:"scanner_ip"` // which device/server discovered this host
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
