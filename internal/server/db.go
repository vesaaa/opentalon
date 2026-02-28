// Package server manages the OpenTalon database layer.
// It initializes GORM with SQLite (default) or MySQL, and handles
// parent-node auto-wiring based on reported GatewayIP.
package server

import (
	"fmt"
	"log"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/vesaa/opentalon/internal/config"
	"github.com/vesaa/opentalon/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB opens the database and runs AutoMigrate.
func InitDB(cfg *config.Config) error {
	var dialector gorm.Dialector
	switch cfg.DBDriver {
	case "sqlite", "":
		dialector = sqlite.Open(cfg.DBPath)
	default:
		return fmt.Errorf("unsupported db_driver %q (use 'sqlite' or 'mysql')", cfg.DBDriver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}

	if err := db.AutoMigrate(&models.Device{}, &models.Metrics{}); err != nil {
		return fmt.Errorf("auto-migrate: %w", err)
	}

	DB = db
	log.Printf("[db] opened %s/%s", cfg.DBDriver, cfg.DBPath)
	return nil
}

// UpsertDevice creates or updates a device record by IP.
// After saving, it calls wireParent to auto-resolve the parent node.
func UpsertDevice(payload RegisterPayload) (*models.Device, error) {
	var dev models.Device
	result := DB.Where("ip = ?", payload.IP).First(&dev)

	if result.Error == gorm.ErrRecordNotFound {
		dev = models.Device{
			Hostname:    payload.Hostname,
			IP:          payload.IP,
			OS:          payload.OS,
			GatewayIP:   payload.GatewayIP,
			Group:       payload.Group,
			NetworkMode: payload.NetworkMode,
			ParentID:    payload.ParentID,
			AgentVer:    payload.AgentVer,
		}
		if err := DB.Create(&dev).Error; err != nil {
			return nil, err
		}
	} else if result.Error != nil {
		return nil, result.Error
	} else {
		// Update mutable fields
		DB.Model(&dev).Updates(map[string]any{
			"hostname":     payload.Hostname,
			"os":           payload.OS,
			"gateway_ip":   payload.GatewayIP,
			"group":        payload.Group,
			"network_mode": payload.NetworkMode,
			"agent_ver":    payload.AgentVer,
			"is_online":    true,
			"last_seen":    time.Now(),
		})
		// Only update ParentID if explicitly provided by agent
		if payload.ParentID != nil {
			DB.Model(&dev).Update("parent_id", payload.ParentID)
		}
	}

	// Auto-wire topology by GatewayIP (only if parent not explicitly set)
	if dev.ParentID == nil && dev.GatewayIP != "" {
		wireParent(&dev)
	}

	DB.Model(&dev).Updates(map[string]any{
		"is_online": true,
		"last_seen": time.Now(),
	})

	return &dev, nil
}

// wireParent finds the device whose IP matches dev.GatewayIP and sets dev.ParentID.
// This enables automatic topology inference from the default gateway alone.
func wireParent(dev *models.Device) {
	var parent models.Device
	if err := DB.Where("ip = ?", dev.GatewayIP).First(&parent).Error; err != nil {
		return // parent not (yet) registered; will be resolved on next upsert
	}
	if parent.ID == dev.ID {
		return // self-reference guard
	}
	DB.Model(dev).Update("parent_id", parent.ID)
	dev.ParentID = &parent.ID
	log.Printf("[db] wired %s → parent %s (id=%d)", dev.IP, parent.IP, parent.ID)
}

// SaveMetrics persists a metrics snapshot and marks the device online.
func SaveMetrics(deviceID uint, m *models.Metrics) error {
	m.DeviceID = deviceID
	m.ReportedAt = time.Now()
	if err := DB.Create(m).Error; err != nil {
		return err
	}
	DB.Model(&models.Device{}).Where("id = ?", deviceID).Updates(map[string]any{
		"is_online": true,
		"last_seen": time.Now(),
	})
	return nil
}

// GetDeviceTree returns all devices as a nested tree.
func GetDeviceTree() ([]*models.DeviceTree, error) {
	var devices []models.Device
	if err := DB.Find(&devices).Error; err != nil {
		return nil, err
	}

	// Build lookup map
	nodeMap := make(map[uint]*models.DeviceTree, len(devices))
	for _, d := range devices {
		d := d
		nodeMap[d.ID] = &models.DeviceTree{
			ID:          d.ID,
			Hostname:    d.Hostname,
			IP:          d.IP,
			OS:          d.OS,
			GatewayIP:   d.GatewayIP,
			NetworkMode: d.NetworkMode,
			Group:       d.Group,
			IsOnline:    d.IsOnline,
			LastSeen:    d.LastSeen,
			ParentID:    d.ParentID,
		}
	}

	// Wire parent → children
	var roots []*models.DeviceTree
	for _, node := range nodeMap {
		if node.ParentID == nil {
			roots = append(roots, node)
		} else {
			if parent, ok := nodeMap[*node.ParentID]; ok {
				parent.Children = append(parent.Children, node)
			} else {
				roots = append(roots, node) // orphan → promote to root
			}
		}
	}
	return roots, nil
}

// GetLatestMetrics returns the most recent Metrics row for a device.
func GetLatestMetrics(deviceID uint) (*models.Metrics, error) {
	var m models.Metrics
	err := DB.Where("device_id = ?", deviceID).Order("reported_at desc").First(&m).Error
	return &m, err
}

// RegisterPayload mirrors agent.RegisterPayload to avoid circular imports.
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
