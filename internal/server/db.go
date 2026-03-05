// Package server manages the OpenTalon database layer.
// It initializes GORM with SQLite (default) or MySQL, and handles
// parent-node auto-wiring based on reported GatewayIP.
package server

import (
	"fmt"
	"log"
	"math/rand"
	"net"
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

// latestMetrics caches the most recent metrics per device in memory.
var latestMetrics sync.Map // map[uint]*models.Metrics

// electedScanners maps subnet CIDR (e.g. "192.168.1.0/24") → elected device IP.
// The elected device receives scan_task=true in the next metrics response.
var electedScanners sync.Map // map[string]string  subnet→ip

// discoveryEnabled controls whether ARP scanning is active (set from Config at startup).
var discoveryEnabled = true

// SetDiscoveryEnabled propagates the config flag into the db package.
func SetDiscoveryEnabled(v bool) { discoveryEnabled = v }

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

	if err := db.AutoMigrate(&models.Device{}, &models.Metrics{}, &models.DiscoveredDevice{}); err != nil {
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

// ─── Scanner election ─────────────────────────────────────────────────────────

// ElectScanners recalculates which device should perform ARP scans for each
// local subnet, and stores results in electedScanners.
//
// Election rules:
//  1. Only root nodes (ParentID=nil) are candidates.
//  2. Per subnet (grouped by GatewayIP), if one root → it wins.
//  3. Multiple roots in same subnet → the one with highest MemTotal wins.
//  4. MemTotal tie or unknown → random selection.
func ElectScanners() {
	if !discoveryEnabled {
		return
	}
	var devices []models.Device
	if err := DB.Where("is_online = ? AND parent_id IS NULL", true).Find(&devices).Error; err != nil {
		return
	}

	// Group root devices by subnet (using /24 approximation from GatewayIP).
	type candidate struct {
		ip       string
		memTotal uint64
	}
	bySubnet := make(map[string][]candidate)
	for _, d := range devices {
		subnet := subnetKey(d.IP)
		if subnet == "" {
			continue
		}
		var memTotal uint64
		if v, ok := latestMetrics.Load(d.ID); ok {
			if m, ok2 := v.(*models.Metrics); ok2 {
				memTotal = m.MemTotal
			}
		}
		bySubnet[subnet] = append(bySubnet[subnet], candidate{ip: d.IP, memTotal: memTotal})
	}

	for subnet, cands := range bySubnet {
		if len(cands) == 0 {
			continue
		}
		winner := cands[0]
		for _, c := range cands[1:] {
			if c.memTotal > winner.memTotal {
				winner = c
			} else if c.memTotal == winner.memTotal {
				// Tie-break: random to avoid always favouring the first registered device.
				if rand.Intn(2) == 0 { //nolint:gosec
					winner = c
				}
			}
		}
		electedScanners.Store(subnet, winner.ip)
	}
}

// IsElectedScanner returns true if the given IP is the elected scanner for its subnet.
func IsElectedScanner(ip string) bool {
	if !discoveryEnabled {
		return false
	}
	subnet := subnetKey(ip)
	if subnet == "" {
		return false
	}
	v, ok := electedScanners.Load(subnet)
	if !ok {
		return false
	}
	return v.(string) == ip
}

// subnetKey returns a /24 subnet string for the given IP, e.g. "192.168.1".
// Used as a grouping key for scanner election.
func subnetKey(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", ip4[0], ip4[1], ip4[2])
}

// ─── DiscoveredDevice CRUD ────────────────────────────────────────────────────

// UpsertDiscovered inserts or updates a discovered device record.
func UpsertDiscovered(ip, mac, hostname, vendor, osHint, scannerIP string) {
	now := time.Now()
	var d models.DiscoveredDevice
	if err := DB.Where("ip = ?", ip).First(&d).Error; err == gorm.ErrRecordNotFound {
		d = models.DiscoveredDevice{
			IP:        ip,
			MAC:       mac,
			Hostname:  hostname,
			Vendor:    vendor,
			OSHint:    osHint,
			ScannerIP: scannerIP,
			FirstSeen: now,
			LastSeen:  now,
		}
		DB.Create(&d)
	} else if err == nil {
		DB.Model(&d).Updates(map[string]any{
			"mac":        mac,
			"hostname":   hostname,
			"vendor":     vendor,
			"os_hint":    osHint,
			"scanner_ip": scannerIP,
			"last_seen":  now,
		})
	}
}

// GetDiscoveredDevices returns all discovered (non-adopted) devices.
func GetDiscoveredDevices() ([]models.DiscoveredDevice, error) {
	var list []models.DiscoveredDevice
	err := DB.Order("last_seen desc").Find(&list).Error
	return list, err
}

// AdoptDiscoveredDevices moves selected discovered devices into the managed devices table.
// group and parentID are optional; supply zero/empty to skip.
func AdoptDiscoveredDevices(ids []uint, group string, parentID *uint) error {
	var discovered []models.DiscoveredDevice
	if err := DB.Where("id IN ?", ids).Find(&discovered).Error; err != nil {
		return err
	}
	for _, d := range discovered {
		reg := RegisterPayload{
			Hostname:    d.Hostname,
			IP:          d.IP,
			Group:       group,
			NetworkMode: models.NetworkModeBridged,
			AgentVer:    "discovered",
			ParentID:    parentID,
		}
		if reg.Hostname == "" {
			reg.Hostname = d.IP
		}
		if reg.Group == "" {
			reg.Group = "discovered"
		}
		if _, err := UpsertDevice(reg); err != nil {
			return fmt.Errorf("adopting %s: %w", d.IP, err)
		}
		// Remove from discovered list now that it's managed.
		DB.Unscoped().Delete(&models.DiscoveredDevice{}, d.ID)
	}
	return nil
}

// ── Scan state ───────────────────────────────────────────────────────────────

// ScanStateInfo is returned by GetScanState.
type ScanStateInfo struct {
	Running    bool      `json:"running"`
	ScannerIP  string    `json:"scanner_ip"`
	LastScanAt time.Time `json:"last_scan_at,omitempty"` // zero if never scanned
	LastFound  int       `json:"last_found"`             // devices found in last scan
}

var scanMu sync.Mutex
var activeScanState ScanStateInfo
var activeScanCancel func()  // non-nil while a server-side goroutine scan is running
var pendingServerScan = false // flag consumed by main.go background loop

// RequestServerScan queues a server-side ARP scan (main.go background goroutine picks it up).
func RequestServerScan() {
	scanMu.Lock()
	pendingServerScan = true
	scanMu.Unlock()
}

// TakeServerScan atomically reads and clears the pending scan flag.
func TakeServerScan() bool {
	scanMu.Lock()
	defer scanMu.Unlock()
	v := pendingServerScan
	pendingServerScan = false
	return v
}

// SetScanActive marks a scan as running. cancelFn may be nil for agent-driven scans.
// autoStopSec: if > 0, automatically mark done after that many seconds (safety net).
func SetScanActive(scannerIP string, cancelFn func(), autoStopSec int) {
	scanMu.Lock()
	activeScanState = ScanStateInfo{Running: true, ScannerIP: scannerIP}
	activeScanCancel = cancelFn
	scanMu.Unlock()
	if autoStopSec > 0 {
		time.AfterFunc(time.Duration(autoStopSec)*time.Second, func() {
			scanMu.Lock()
			// Only clear if it's still the same scan (same scanner IP).
			if activeScanState.ScannerIP == scannerIP {
				activeScanState.Running = false
				activeScanCancel = nil
			}
			scanMu.Unlock()
		})
	}
}

// SetScanDone marks the current scan as finished.
func SetScanDone() {
	scanMu.Lock()
	activeScanState.Running = false
	activeScanState.LastScanAt = time.Now()
	activeScanCancel = nil
	scanMu.Unlock()
}

// SetScanDoneWithCount marks scan as finished and records how many new devices were found.
func SetScanDoneWithCount(found int) {
	scanMu.Lock()
	activeScanState.Running = false
	activeScanState.LastScanAt = time.Now()
	activeScanState.LastFound = found
	activeScanCancel = nil
	scanMu.Unlock()
}

// CancelActiveScan stops the running scan (if cancellable) and marks it done.
func CancelActiveScan() {
	scanMu.Lock()
	fn := activeScanCancel
	activeScanState.Running = false
	activeScanCancel = nil
	scanMu.Unlock()
	if fn != nil {
		fn()
	}
}

// GetScanState returns a snapshot of the current scan state.
func GetScanState() ScanStateInfo {
	scanMu.Lock()
	defer scanMu.Unlock()
	return activeScanState
}

// HasOnlineClients returns true if at least one device is currently online.
func HasOnlineClients() bool {
	var count int64
	DB.Model(&models.Device{}).Where("is_online = ?", true).Count(&count)
	return count > 0
}

// GetAnyElectedScannerIP returns one of the currently elected scanner IPs, or "" if none.
func GetAnyElectedScannerIP() string {
	var ip string
	electedScanners.Range(func(_, v interface{}) bool {
		ip = v.(string)
		return false // stop after first
	})
	return ip
}
