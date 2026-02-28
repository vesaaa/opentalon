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
)

// adminCredentials are set at startup from config.
// v0.2+ will replace this with DB-backed user management.
var adminUser, adminPass string

// SetAdminCredentials stores credentials for /api/login.
func SetAdminCredentials(user, pass string) {
	adminUser = user
	adminPass = pass
}

// RegisterControlRoutes wires up the control-plane API on the given engine.
// Call this on the engine bound to port 6677.
//
//	Public:   POST /api/login
//	Protected (JWT): all other /api/* routes + topology
func RegisterControlRoutes(r *gin.Engine) {
	api := r.Group("/api")

	// ── Public endpoints ──────────────────────────────────────────────────────
	api.POST("/login", handleLogin)

	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().UTC()})
	})

	// ── JWT-protected endpoints ───────────────────────────────────────────────
	auth := api.Group("/", JWTMiddleware())
	{
		// Topology
		auth.GET("/devices/tree", handleDeviceTree)
		auth.GET("/devices/:id/metrics", handleDeviceMetrics)

		// Device management (initiated by operator, not agent)
		auth.DELETE("/devices/:id", handleDeviceDelete)
	}
}

// RegisterDataRoutes wires up the data-plane API on the given engine.
// Call this on the engine bound to port 1616.
// All routes require a valid Bearer agent token.
func RegisterDataRoutes(r *gin.Engine) {
	api := r.Group("/api", AgentTokenMiddleware())
	{
		api.POST("/devices/register", handleDeviceRegister)
		api.POST("/metrics", handleMetricsIngest)
	}

	// Data-plane health (no auth — used by load-balancers / k8s probes)
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// handleLogin accepts username + password and returns a signed JWT.
//
//	POST /api/login
//	Body: { "username": "admin", "password": "admin" }
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

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_in": 86400, // seconds
		"type":       "Bearer",
	})
}

// handleDeviceTree returns the full topology as a nested JSON tree.
func handleDeviceTree(c *gin.Context) {
	tree, err := GetDeviceTree()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tree})
}

// handleDeviceDelete removes a device record by ID.
func handleDeviceDelete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := DB.Delete(&models.Device{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

// handleDeviceRegister accepts registration from agents (data-plane only).
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

// handleMetricsIngest accepts a metrics report from an agent (data-plane only).
func handleMetricsIngest(c *gin.Context) {
	var payload struct {
		Hostname       string  `json:"hostname"`
		IP             string  `json:"ip"`
		GatewayIP      string  `json:"gateway_ip"`
		CPUUsage       float64 `json:"cpu_usage"`
		MemUsage       float64 `json:"mem_usage"`
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

	// Resolve device by IP (auto-register unknown agents)
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

	m := &models.Metrics{
		CPUUsage:       payload.CPUUsage,
		MemUsage:       payload.MemUsage,
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
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// handleDeviceMetrics returns the latest metrics for a device (control-plane).
func handleDeviceMetrics(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	m, err := GetLatestMetrics(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no metrics found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": m})
}
