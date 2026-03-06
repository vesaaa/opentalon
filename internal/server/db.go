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
	"path/filepath"
	"sort"
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
// When db_path is relative (e.g. "opentalon.db"), it is resolved relative to the
// executable's directory so the same DB file is used regardless of working directory.
func InitDB(cfg *config.Config) error {
	dbPath := cfg.DBPath
	if cfg.DBDriver == "sqlite" || cfg.DBDriver == "" {
		if dbPath == "" {
			dbPath = "opentalon.db"
		}
		if !filepath.IsAbs(dbPath) {
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolving executable path: %w", err)
			}
			dbPath = filepath.Join(filepath.Dir(exe), dbPath)
		}
	}
	var dialector gorm.Dialector
	switch cfg.DBDriver {
	case "sqlite", "":
		dialector = sqlite.Open(dbPath)
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
	log.Printf("[db] opened %s/%s", cfg.DBDriver, dbPath)
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
			MAC:         d.MAC,
			GatewayIP:   d.GatewayIP,
			NetworkMode: d.NetworkMode,
			Group:       d.Group,
			IsOnline:    online,
			Status:      status,
			LastSeen:    d.LastSeen,
			AgentVer:    d.AgentVer,
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
	// 为了让前端拓扑布局稳定（同一批设备不会因为返回顺序不同而“换位置”），
	// 在返回前对根节点及每一层 children 做一次稳定排序。
	sortDeviceTree(roots)
	return roots, nil
}

// sortDeviceTree 按 group、hostname、ip 的顺序对节点进行稳定排序，并递归其 children。
func sortDeviceTree(nodes []*models.DeviceTree) {
	sort.Slice(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		return a.IP < b.IP
	})
	for _, n := range nodes {
		if len(n.Children) > 0 {
			sortDeviceTree(n.Children)
		}
	}
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
		// 如果扫描阶段没有反向解析到主机名，但已经识别出厂商，则使用厂商名作为默认“设备名”，
		// 这样在“已发现设备”和后续纳管后的节点上都有一个比 IP 更友好的名称。
		if hostname == "" && vendor != "" {
			hostname = vendor
		}
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
		if hostname == "" && vendor != "" && d.Hostname == "" {
			// 仅在历史记录也没有主机名时，回填厂商名为 Hostname，避免覆盖用户手工改过的名字。
			hostname = vendor
		}
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
			// 首选用 OUI 推断出的厂商名作为默认名称，其次退回到 IP。
			if d.Vendor != "" {
				reg.Hostname = d.Vendor
			} else {
				reg.Hostname = d.IP
			}
		}
		if reg.Group == "" {
			reg.Group = "discovered"
		}
		dev, err := UpsertDevice(reg)
		if err != nil {
			return fmt.Errorf("adopting %s: %w", d.IP, err)
		}
		// 把扫描阶段得到的 MAC 地址写入正式设备记录，方便后续在抽屉中展示和做细颗粒度识别。
		if d.MAC != "" {
			DB.Model(dev).Update("mac", d.MAC)
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
	// TaskIssued 表示当前这轮扫描任务中，是否已经向被选中的扫描器下发过一次 scan_task。
	// 为了避免“有扫描资格的设备在一次触发中重复上报”，我们保证：
	//   - 每次 SetScanActive 时，ScanState 会重新初始化（TaskIssued=false）；
	//   - 在 metrics 上报路径上，只有在 TaskIssued=false 时才返回 scan_task=true，
	//     并立即将 TaskIssued 置为 true。
	// 这样可以确保“同一轮触发中，每个被选中的扫描器最多只会收到一次扫描任务”。
	TaskIssued bool `json:"-"`
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
	activeScanState = ScanStateInfo{
		Running:   true,
		ScannerIP: scannerIP,
		// 保留上一轮的统计信息，便于在 UI 中看到最近一次扫描结果。
		LastScanAt: activeScanState.LastScanAt,
		LastFound:  activeScanState.LastFound,
		TaskIssued: false,
	}
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

// ShouldAssignScanTask decides whether the given IP 应该在当前这轮扫描中收到一次 scan_task=true。
// 规则：
//   1) 设备必须是当前选中的扫描器（IsElectedScanner(ip)）。
//   2) 必须存在一轮“正在进行中的扫描任务”（Running=true 且 ScannerIP 不为空）。
//   3) 当前 ScannerIP 必须与该设备 IP 匹配。
//   4) 同一轮任务中，只会返回一次 true（通过 TaskIssued 标记）。
func ShouldAssignScanTask(ip string) bool {
	if !IsElectedScanner(ip) {
		return false
	}
	scanMu.Lock()
	defer scanMu.Unlock()
	if !activeScanState.Running {
		return false
	}
	if activeScanState.ScannerIP == "" || activeScanState.ScannerIP != ip {
		return false
	}
	if activeScanState.TaskIssued {
		return false
	}
	activeScanState.TaskIssued = true
	return true
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

// ── On-demand port probe ───────────────────────────────────────────────────────

// DeviceProbeResult describes the result of a lightweight TCP port probe.
// It is used by the Web UI 抽屉里的“手动探测”按钮，为尚未安装 Agent 的设备
// 提供一个粗粒度的 OS / 角色判断。
type DeviceProbeResult struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Open22    bool   `json:"open_22"`    // 22/tcp 通常代表 SSH（Linux/Unix）
	Open3389  bool   `json:"open_3389"`  // 3389/tcp 通常代表 RDP（Windows）
	OSHint    string `json:"os_hint"`    // 例如 "Linux (port 22 open)" / "Windows (port 3389 open)"
	FromAgent bool   `json:"from_agent"` // true 表示当前 OS 字段来源于 Agent，而非端口指纹
}

// ProbeDeviceByID runs a short TCP port probe against a device's IP.
// 规则：
//   - 仅在 AgentVer 为空或为 "discovered" 时，才会根据结果回写 Device.OS；
//   - 如果后续安装了 Agent，则 Agent 上报的 OS 会覆盖这里的探测结果。
func ProbeDeviceByID(id uint) (*DeviceProbeResult, error) {
	var dev models.Device
	if err := DB.First(&dev, id).Error; err != nil {
		return nil, err
	}
	if dev.IP == "" {
		return nil, fmt.Errorf("device has empty IP")
	}

	timeout := 700 * time.Millisecond
	open22 := isPortOpen(dev.IP, 22, timeout)
	open3389 := isPortOpen(dev.IP, 3389, timeout)

	osHint := dev.OS
	fromAgent := dev.AgentVer != "" && dev.AgentVer != "discovered"

	// 仅在尚未安装 Agent 时，根据端口开放情况推导一个粗粒度 OS。
	if !fromAgent {
		switch {
		case open3389:
			osHint = "Windows (port 3389 open)"
		case open22:
			osHint = "Linux (port 22 open)"
		}
		if osHint != dev.OS {
			DB.Model(&dev).Update("os", osHint)
		}
	}

	return &DeviceProbeResult{
		IP:        dev.IP,
		MAC:       dev.MAC,
		Open22:    open22,
		Open3389:  open3389,
		OSHint:    osHint,
		FromAgent: fromAgent,
	}, nil
}

// isPortOpen 尝试在给定超时时间内建立 TCP 连接，返回是否成功建立连接。
func isPortOpen(ip string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
