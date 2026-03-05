// Package server provides the OpenTalon Gin-based REST API.
// Routes are split into two groups:
//   - Control-plane (port 6677): JWT-protected; serves the Web UI and admin API.
//   - Data-plane   (port 1616): Bearer-token-protected; receives agent reports.
package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vesaa/opentalon/internal/models"
	"github.com/vesaa/opentalon/internal/scanner"
)

// adminCredentials are set at startup from config.
var adminUser, adminPass string

// SetAdminCredentials stores credentials for /api/login.
func SetAdminCredentials(user, pass string) {
	adminUser = user
	adminPass = pass
}

// RegisterControlRoutes wires up the control-plane API on the given engine.
func RegisterControlRoutes(r *gin.Engine) {
	api := r.Group("/api")

	// Public endpoints
	api.POST("/login", handleLogin)
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().UTC()})
	})

	// JWT-protected endpoints
	auth := api.Group("/", JWTMiddleware())
	{
		auth.GET("/devices/tree", handleDeviceTree)
		auth.GET("/devices/:id/metrics", handleDeviceMetrics)
		auth.DELETE("/devices/:id", handleDeviceDelete)
		auth.PATCH("/devices/:id", handleDeviceUpdate)

		// LAN discovery
		auth.GET("/discovered", handleGetDiscovered)
		auth.POST("/discovered/adopt", handleAdoptDiscovered)
		auth.POST("/scan/trigger", handleScanTrigger)
		auth.POST("/scan/stop", handleScanStop)
		auth.GET("/scan/status", handleScanStatus)
	}
}

// RegisterDataRoutes wires up the data-plane API on the given engine.
func RegisterDataRoutes(r *gin.Engine) {
	api := r.Group("/api", AgentTokenMiddleware())
	{
		api.POST("/devices/register", handleDeviceRegister)
		api.POST("/metrics", handleMetricsIngest)
		api.POST("/discovered/report", handleDiscoveredReport)
	}

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func handleLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password required"})
		return
	}
	if body.Username != adminUser || body.Password != adminPass {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	token, err := GenerateJWT(body.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "expires_in": 86400, "type": "Bearer"})
}

func handleDeviceTree(c *gin.Context) {
	tree, err := GetDeviceTree()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tree})
}

func handleDeviceDelete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := DB.Unscoped().Delete(&models.Device{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

func handleDeviceUpdate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var body struct {
		Group  *string `json:"group"`
		Remark *string `json:"remark"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updates := make(map[string]any)
	if body.Group != nil {
		updates["group"] = *body.Group
	}
	if body.Remark != nil {
		updates["remark"] = *body.Remark
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}
	if err := DB.Model(&models.Device{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var dev models.Device
	if err := DB.First(&dev, id).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"updated": id})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":       dev.ID,
		"hostname": dev.Hostname,
		"remark":   dev.Remark,
		"group":    dev.Group,
	})
}

func handleDeviceRegister(c *gin.Context) {
	var payload RegisterPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	dev, err := UpsertDevice(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": dev.ID, "hostname": dev.Hostname})
}

// handleMetricsIngest accepts a metrics report and responds with scan_task when
// this agent is the elected LAN scanner for its subnet.
func handleMetricsIngest(c *gin.Context) {
	var payload struct {
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
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var dev models.Device
	if err := DB.Where("ip = ?", payload.IP).First(&dev).Error; err != nil {
		reg := RegisterPayload{
			Hostname:    payload.Hostname,
			IP:          payload.IP,
			GatewayIP:   payload.GatewayIP,
			Group:       "auto",
			NetworkMode: models.NetworkModeBridged,
			AgentVer:    "unknown",
		}
		d, err2 := UpsertDevice(reg)
		if err2 != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "device lookup failed"})
			return
		}
		dev = *d
	}

	MaybeWireParentByGateway(&dev, payload.GatewayIP)

	m := &models.Metrics{
		CPUUsage:       payload.CPUUsage,
		MemUsage:       payload.MemUsage,
		MemTotal:       payload.MemTotal,
		DiskUsage:      payload.DiskUsage,
		RxBytes:        payload.RxBytes,
		TxBytes:        payload.TxBytes,
		TCPConnections: payload.TCPConnections,
		UDPConnections: payload.UDPConnections,
		GatewayIP:      payload.GatewayIP,
		LocalIP:        payload.IP,
	}
	if err := SaveMetrics(dev.ID, m); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ElectScanners()

	scanTask := IsElectedScanner(payload.IP)
	if scanTask {
		// Notify scan state so the UI can show the animation.
		// Auto-timeout in 120s in case the agent never reports back.
		SetScanActive(payload.IP, nil, 120)
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":        true,
		"scan_task": scanTask,
	})
}

// handleDiscoveredReport receives ARP scan results from an elected agent (data-plane).
func handleDiscoveredReport(c *gin.Context) {
	var payload struct {
		ScannerIP string               `json:"scanner_ip"`
		Devices   []scanner.ScanResult `json:"devices"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var managedIPs []string
	DB.Model(&models.Device{}).Pluck("ip", &managedIPs)
	managed := make(map[string]struct{}, len(managedIPs))
	for _, ip := range managedIPs {
		managed[ip] = struct{}{}
	}
	count := 0
	for _, d := range payload.Devices {
		if _, ok := managed[d.IP]; ok {
			continue
		}
		UpsertDiscovered(d.IP, d.MAC, d.Hostname, d.Vendor, d.OSHint, payload.ScannerIP)
		count++
	}
	// Agent finished its scan — mark scan state as done with result count.
	SetScanDoneWithCount(count)
	c.JSON(http.StatusOK, gin.H{"ok": true, "upserted": count})
}

// handleGetDiscovered returns the discovered-but-unmanaged device list (control-plane).
func handleGetDiscovered(c *gin.Context) {
	list, err := GetDiscoveredDevices()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": list})
}

// handleAdoptDiscovered moves selected discovered devices into managed devices.
func handleAdoptDiscovered(c *gin.Context) {
	var body struct {
		IDs      []uint `json:"ids" binding:"required"`
		Group    string `json:"group"`
		ParentID *uint  `json:"parent_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := AdoptDiscoveredDevices(body.IDs, body.Group, body.ParentID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "adopted": len(body.IDs)})
}

// handleScanTrigger requests an immediate ARP scan.
// If no clients are online, the server performs the scan itself; otherwise
// it re-elects scanners so the elected agent picks up scan_task=true on next heartbeat.
// In both cases, SetScanActive is called immediately so the UI animation starts right away.
func handleScanTrigger(c *gin.Context) {
	if !HasOnlineClients() {
		// No online agents → server scans.
		// SetScanActive with "server" placeholder; runServerScan() will overwrite with real IP.
		SetScanActive("server", nil, 180)
		RequestServerScan()
		c.JSON(http.StatusOK, gin.H{"ok": true, "mode": "server"})
		return
	}
	// Online agents exist → refresh election; elected agent picks up scan_task on next heartbeat.
	ElectScanners()
	scannerIP := GetAnyElectedScannerIP()
	if scannerIP == "" {
		scannerIP = "agent"
	}
	// SetScanActive immediately so UI shows animation while waiting for agent heartbeat (≤30s).
	SetScanActive(scannerIP, nil, 120)
	c.JSON(http.StatusOK, gin.H{"ok": true, "mode": "agent", "scanner_ip": scannerIP})
}

// handleScanStop cancels any currently running scan.
func handleScanStop(c *gin.Context) {
	CancelActiveScan()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// handleScanStatus returns the current scan state (running / scanner_ip).
func handleScanStatus(c *gin.Context) {
	c.JSON(http.StatusOK, GetScanState())
}

// handleDeviceMetrics returns the latest metrics for a device (control-plane).
func handleDeviceMetrics(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	m, err := GetLatestMetrics(uint(id))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"data": nil})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": m})
}
