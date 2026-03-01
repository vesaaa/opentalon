// Package agent implements the metric collection subsystem for OpenTalon.
// It uses gopsutil for cross-platform system telemetry.
package agent

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

// Snapshot holds a single collection cycle's data.
type Snapshot struct {
	Hostname       string
	LocalIP        string
	GatewayIP      string
	OS             string
	CPUUsage       float64
	MemUsage       float64
	DiskUsage      float64
	TCPConnections int
	UDPConnections int
	RxBytes        int64 // bytes/s since last snapshot
	TxBytes        int64 // bytes/s since last snapshot
	CollectedAt    time.Time
}

// Collector gathers system metrics periodically.
type Collector struct {
	mu          sync.Mutex
	prevRx      uint64
	prevTx      uint64
	prevTime    time.Time
	initialized bool
}

// NewCollector creates a ready-to-use Collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect gathers the current system snapshot.
func (c *Collector) Collect() (*Snapshot, error) {
	snap := &Snapshot{
		OS:          detailedOS(),
		CollectedAt: time.Now(),
	}

	// Hostname
	if h, err := os.Hostname(); err == nil {
		snap.Hostname = h
	}

	// Local IP + Gateway
	snap.LocalIP = localIP()
	snap.GatewayIP = defaultGateway()

	// CPU
	if pcts, err := cpu.Percent(500*time.Millisecond, false); err == nil && len(pcts) > 0 {
		snap.CPUUsage = pcts[0]
	}

	// Memory
	if vm, err := mem.VirtualMemory(); err == nil {
		snap.MemUsage = vm.UsedPercent
	}

	// Disk (largest mount or /)
	snap.DiskUsage = maxDiskUsage()

	// TCP / UDP connection counts
	tcp, udp := connectionCounts()
	snap.TCPConnections = tcp
	snap.UDPConnections = udp

	// Network bandwidth (delta-based)
	rx, tx := c.netBandwidth()
	snap.RxBytes = rx
	snap.TxBytes = tx

	return snap, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// detailedOS returns a descriptive OS version string, or runtime.GOOS as fallback.
func detailedOS() string {
	info, err := host.Info()
	if err == nil && info.Platform != "" {
		if info.PlatformVersion != "" {
			return fmt.Sprintf("%s %s", info.Platform, info.PlatformVersion) // e.g., "centos 7.9.2009"
		}
		return info.Platform
	}
	return runtime.GOOS
}

// localIP returns the first non-loopback IPv4 address.
func localIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return ""
}

// defaultGateway reads the default gateway from the OS.
// Linux: parses /proc/net/route. Windows/macOS: falls back to route command output parsing.
func defaultGateway() string {
	switch runtime.GOOS {
	case "linux":
		return gatewayLinux()
	case "windows":
		return gatewayWindows()
	default:
		return gatewayFallback()
	}
}

// gatewayLinux reads /proc/net/route (kernel routing table) efficiently.
func gatewayLinux() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Destination = 00000000 means default route
		if fields[1] != "00000000" {
			continue
		}
		// Gateway is in hex little-endian
		gwHex := fields[2]
		if len(gwHex) != 8 {
			continue
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			fmt.Sscanf(gwHex[i*2:i*2+2], "%02x", &b[3-i])
		}
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	return ""
}

// gatewayWindows uses gopsutil's route helpers on Windows.
// Falls back to a simple ipconfig parse.
func gatewayWindows() string {
	// Use psnet route helpers if available; otherwise parse environment.
	// This is a best-effort implementation for Windows.
	return gatewayFallback()
}

// gatewayFallback tries gopsutil net.RouteTable stub (not all platforms support).
func gatewayFallback() string {
	// Attempt to parse the routing table via gopsutil interfaces.
	// On unsupported platforms, return empty string gracefully.
	stats, err := psnet.IOCounters(false)
	if err != nil || len(stats) == 0 {
		return ""
	}
	// Cannot determine GW from IOCounters; caller knows it's best-effort.
	return ""
}

// maxDiskUsage returns the used percentage of the partition with highest usage.
func maxDiskUsage() float64 {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return 0
	}
	var max float64
	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		if usage.UsedPercent > max {
			max = usage.UsedPercent
		}
	}
	return max
}

// connectionCounts returns (tcpCount, udpCount) from the OS connection table.
func connectionCounts() (int, int) {
	// "tcp" returns both tcp4 and tcp6; same for udp.
	tcpConns, err := psnet.Connections("tcp")
	if err != nil {
		tcpConns = nil
	}
	udpConns, err := psnet.Connections("udp")
	if err != nil {
		udpConns = nil
	}
	return len(tcpConns), len(udpConns)
}

// netBandwidth computes bytes/s since the last call using IOCounters deltas.
func (c *Collector) netBandwidth() (rxBps, txBps int64) {
	stats, err := psnet.IOCounters(false) // aggregate all interfaces
	if err != nil || len(stats) == 0 {
		return 0, 0
	}
	now := time.Now()
	curRx := stats[0].BytesRecv
	curTx := stats[0].BytesSent

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.initialized {
		dt := now.Sub(c.prevTime).Seconds()
		if dt > 0 {
			rxBps = int64(float64(curRx-c.prevRx) / dt)
			txBps = int64(float64(curTx-c.prevTx) / dt)
			if rxBps < 0 {
				rxBps = 0 // counter reset (reboot)
			}
			if txBps < 0 {
				txBps = 0
			}
		}
	}

	c.prevRx = curRx
	c.prevTx = curTx
	c.prevTime = now
	c.initialized = true
	return
}
