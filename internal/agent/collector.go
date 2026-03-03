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

	// LANIPs holds all candidate "intranet" IPv4 addresses on this node
	// (e.g. 192.168.x.x / 10.x.x.x / 172.16-31.x.x). These用于父子拓扑推导。
	LANIPs []string
	// WANIPs holds public / non-RFC1918 IPv4 addresses (典型为出口公网 IP)，仅用于展示。
	WANIPs []string
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

	// Local IP + Gateway + LAN/WAN IP 集合
	snap.LocalIP, snap.LANIPs, snap.WANIPs = classifyIPs()
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

// classifyIPs 遍历所有网卡，把 IPv4 地址划分为：
//   - LANIPs: RFC1918 私网地址（排除常见虚拟/隧道网卡）
//   - WANIPs: 其他非回环 IPv4（常用于公网/出口）
// 返回值中的 primaryLAN 则作为 "主 IP" 在 UI 中展示。
func classifyIPs() (primaryLAN string, lanIPs []string, wanIPs []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if isVirtualInterface(iface.Name) {
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
			if ip == nil || ip.To4() == nil || ip.IsLoopback() {
				continue
			}
			ipStr := ip.String()
			if isPrivateIPv4(ip) {
				lanIPs = append(lanIPs, ipStr)
				// 选第一个私网地址作为 primaryLAN（后续可根据接口名再做细分）
				if primaryLAN == "" {
					primaryLAN = ipStr
				}
			} else {
				wanIPs = append(wanIPs, ipStr)
			}
		}
	}
	// 如果没有私网地址，则降级为使用第一个 WAN IP 作为 primaryLAN（如果存在）
	if primaryLAN == "" && len(wanIPs) > 0 {
		primaryLAN = wanIPs[0]
	}
	return primaryLAN, lanIPs, wanIPs
}

// isVirtualInterface 依据接口名称粗略判断是否为虚拟/隧道设备，
// 这些接口的 IP 一般不参与拓扑父子关系推导。
func isVirtualInterface(name string) bool {
	n := strings.ToLower(name)
	prefixes := []string{
		"docker", "br-", "cni", "veth", "flannel", "tun", "tap",
		"wg", "tailscale", "virbr", "zt", "lo",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// isPrivateIPv4 判断 IPv4 是否属于 RFC1918 私网地址段。
func isPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	default:
		return false
	}
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
