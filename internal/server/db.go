// Package server manages the OpenTalon database layer.
// It initializes GORM with SQLite (default) or MySQL, and handles
// parent-node auto-wiring based on reported GatewayIP.
package server

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/vesaa/opentalon/internal/config"
	"github.com/vesaa/opentalon/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB
var topoMu sync.Mutex

// latestMetrics caches the most recent metrics per device in memory so that
// control-plane API 可以在 SQLite 出现异常或延迟时仍然返回最近一次上报的数据。
var latestMetrics sync.Map // map[uint]*models.Metrics

// heartbeatTimeout defines how long a device can stay silent before being
// considered offline. 此处使用较短的 30s，方便本地/小规模环境快速感知离线状态。
const heartbeatTimeout = 30 * time.Second

// InitDB opens the database and runs AutoMigrate.
func InitDB(cfg *config.Config) error {
	var dialector gorm.Dialector
	switch cfg.DBDriver {
	case "sqlite", "":
		dialector = sqlite.Open(cfg.DBPath)
	default:
		return fmt.Errorf("unsupported db_driver %q (use 'sqlite' or 'mysql')", cfg.DBDriver)
	}

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second, // Slow SQL threshold
			LogLevel:                  logger.Warn, // Log level
			IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
			Colorful:                  true,        // Disable color
		},
	)

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: newLogger,
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
			Remark:      "", // managed from Web UI; agent never overwrites it
			IP:          payload.IP,
			OS:          payload.OS,
			GatewayIP:   payload.GatewayIP,
			Group:       payload.Group,
			NetworkMode: payload.NetworkMode,
			ParentID:    payload.ParentID,
			AgentVer:    payload.AgentVer,
			IsOnline:    true,
			LastSeen:    time.Now(),
			LANIPs:      strings.Join(payload.LANIPs, ","),
			WANIPs:      strings.Join(payload.WANIPs, ","),
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
			"lan_ips":      strings.Join(payload.LANIPs, ","),
			"wan_ips":      strings.Join(payload.WANIPs, ","),
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
// 优先通过对方的主 IP 精确匹配；若不存在，则再尝试通过 LANIPs 做“完整 IP token 匹配”，
// 用于多网段/多内网地址场景，避免把 192.168.1.22 误当作 192.168.1.2 的父节点。
func wireParent(dev *models.Device) {
	var parent models.Device
	// 1) 精确匹配主 IP
	if err := DB.Where("ip = ?", dev.GatewayIP).First(&parent).Error; err != nil {
		// 2) 若没有主 IP 匹配，再尝试在 LANIPs 中做“完整 token 匹配”
		// LANIPs 以逗号分隔，例如 "192.168.1.2,10.0.0.1"；我们只在某个 token
		// 与网关 IP 完全相等时才认为是父节点，防止 192.168.1.22 命中 LIKE '%192.168.1.2%'。
		gw := dev.GatewayIP
		if err := DB.
			Where(`lan_ips = ? OR lan_ips LIKE ? OR lan_ips LIKE ? OR lan_ips LIKE ?`,
				gw, gw+",%", "%,"+gw, "%,"+gw+",%").
			First(&parent).Error; err != nil {
			return // parent not (yet) registered; will be resolved on next upsert
		}
	}
	if parent.ID == dev.ID {
		return // self-reference guard
	}
	DB.Model(dev).Update("parent_id", parent.ID)
	dev.ParentID = &parent.ID
}

// SaveMetrics persists a metrics snapshot and marks the device online.
// To avoid unbounded growth in SQLite, we keep only a sliding window of the
// most recent N snapshots per device, which is sufficient for real-time
// dashboards and sparklines while remaining lightweight.
func SaveMetrics(deviceID uint, m *models.Metrics) error {
	m.DeviceID = deviceID
	m.ReportedAt = time.Now()
	if err := DB.Create(m).Error; err != nil {
		return err
	}
	// 更新内存缓存，供控制面快速读取最新一次上报。
	copy := *m
	latestMetrics.Store(deviceID, &copy)
	// Retain only the latest N rows per device (e.g., ~10 minutes @ 5s interval).
	const maxSnapshotsPerDevice = 120
	// Delete all but the newest N by reported_at.
	DB.
		Where("device_id = ?", deviceID).
		Order("reported_at desc").
		Offset(maxSnapshotsPerDevice).
		Delete(&models.Metrics{})

	DB.Model(&models.Device{}).Where("id = ?", deviceID).Updates(map[string]any{
		"is_online": true,
		"last_seen": time.Now(),
	})
	return nil
}

// rebuildDirtyTopologyLocked 批量处理所有 TopologyDirty=true 的设备。
// 调用方必须已经持有 topoMu。
func rebuildDirtyTopologyLocked() {
	var dirty []models.Device
	if err := DB.Where("topology_dirty = ?", true).Find(&dirty).Error; err != nil {
		return
	}

	for i := range dirty {
		d := &dirty[i]

		// 记录调用前的 ParentID，用于判断本次是否有挂上父节点。
		beforeParent := d.ParentID

		if d.GatewayIP != "" {
			wireParent(d)
		} else {
			DB.Model(d).Update("parent_id", nil)
			d.ParentID = nil
		}

		// 如果没有网关，或者这次 ParentID 发生变化，则认为本次已处理完成，清除脏标记。
		// 对于有网关但仍未找到父节点的设备，保持 TopologyDirty=true，等待下次批处理（例如父节点稍后才注册）。
		if d.GatewayIP == "" || d.ParentID != beforeParent {
			DB.Model(d).Update("topology_dirty", false)
		}
	}
}

// MaybeWireParentByGateway 在 metrics 上报路径上触发拓扑重算。
// 它会：1) 标记当前设备为 TopologyDirty
//      2) 在全局锁下批量处理所有 TopologyDirty=true 的设备。
func MaybeWireParentByGateway(dev *models.Device, gateway string) {
	if dev == nil || gateway == "" {
		return
	}

	topoMu.Lock()
	defer topoMu.Unlock()

	// 标记当前设备为待处理，并按需更新网关 IP。
	updates := map[string]any{
		"topology_dirty": true,
	}
	if gateway != dev.GatewayIP {
		updates["gateway_ip"] = gateway
		dev.GatewayIP = gateway
	}
	DB.Model(dev).Updates(updates)

	// 批量处理所有 TopologyDirty=true 的设备。
	rebuildDirtyTopologyLocked()
}

// GetDeviceTree returns all devices as a nested tree.
func GetDeviceTree() ([]*models.DeviceTree, error) {
	var devices []models.Device
	if err := DB.Find(&devices).Error; err != nil {
		return nil, err
	}

	// Preload which devices have at least one metrics row.
	var metricDeviceIDs []uint
	if err := DB.Model(&models.Metrics{}).Distinct("device_id").Pluck("device_id", &metricDeviceIDs).Error; err != nil {
		return nil, err
	}
	metricsSet := make(map[uint]bool, len(metricDeviceIDs))
	for _, id := range metricDeviceIDs {
		metricsSet[id] = true
	}

	// Build lookup map
	nodeMap := make(map[uint]*models.DeviceTree, len(devices))
	now := time.Now()

	for _, d := range devices {
		d := d

		hasMetrics := metricsSet[d.ID]

		// 先根据 IsOnline + LastSeen 推导“实时在线”状态，再结合是否有 metrics 区分 offline / unknown。
		online := d.IsOnline
		if !d.LastSeen.IsZero() && now.Sub(d.LastSeen) > heartbeatTimeout {
			online = false
		}
		status := "unknown"
		if online {
			status = "online"
		} else if hasMetrics {
			status = "offline"
		}

		nodeMap[d.ID] = &models.DeviceTree{
			ID:          d.ID,
			Hostname:    d.Hostname,
			Remark:      d.Remark,
			IP:          d.IP,
			OS:          d.OS,
			GatewayIP:   d.GatewayIP,
			NetworkMode: d.NetworkMode,
			Group:       d.Group,
			IsOnline:    online,
			Status:      status,
			LastSeen:    d.LastSeen,
			ParentID:    d.ParentID,
		}

		// Persist any online → offline / unknown transition so other queries see it.
		if d.IsOnline && !online {
			DB.Model(&models.Device{}).Where("id = ?", d.ID).Update("is_online", false)
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
// 首选通过 DeviceID 查询；如果没有记录，则退化为按 LocalIP 匹配设备 IP，
// 兼容历史或异常情况下 DeviceID 不一致的 metrics 行。
func GetLatestMetrics(deviceID uint) (*models.Metrics, error) {
	// 优先使用内存缓存，保证“刚上报完立刻点开抽屉”时一定有数据。
	if v, ok := latestMetrics.Load(deviceID); ok {
		if mm, ok2 := v.(*models.Metrics); ok2 {
			return mm, nil
		}
	}

	var m models.Metrics
	err := DB.Where("device_id = ?", deviceID).
		Order("reported_at desc").
		First(&m).Error
	if err == gorm.ErrRecordNotFound {
		var dev models.Device
		if e2 := DB.First(&dev, deviceID).Error; e2 != nil {
			return nil, err
		}
		err = DB.Where("local_ip = ?", dev.IP).
			Order("reported_at desc").
			First(&m).Error
	}
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
	LANIPs      []string           `json:"lan_ips,omitempty"`
	WANIPs      []string           `json:"wan_ips,omitempty"`
}
