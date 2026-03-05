// Package scanner implements LAN ARP discovery.
// Strategy:
//  1. Enumerate host IPs in local subnets derived from network interfaces.
//  2. Send lightweight UDP probes to each IP concurrently; this causes the OS
//     kernel to emit ARP requests and populate the ARP table.
//  3. Read the system ARP table (Linux: /proc/net/arp; others: arp -a).
//  4. Perform reverse DNS lookups and OUI vendor resolution for each result.
package scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ScanResult holds discovered host information.
type ScanResult struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	OSHint   string `json:"os_hint"`
}

// ScanLocalSubnets detects local subnets from network interfaces and scans each one.
// localIP is the agent's primary IP; subnets that don't contain it are also scanned.
func ScanLocalSubnets(localIP string) ([]ScanResult, error) {
	cidrs := localCIDRs()
	seen := make(map[string]struct{})
	var all []ScanResult
	for _, cidr := range cidrs {
		results, err := ScanSubnet(cidr)
		if err != nil {
			continue
		}
		for _, r := range results {
			if _, dup := seen[r.IP]; dup {
				continue
			}
			// exclude the scanner itself
			if r.IP == localIP {
				continue
			}
			seen[r.IP] = struct{}{}
			all = append(all, r)
		}
	}
	return all, nil
}

// ScanSubnet performs an ARP scan on the given CIDR range.
func ScanSubnet(cidr string) ([]ScanResult, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %q: %w", cidr, err)
	}

	hosts := hostsInNet(ipNet)
	if len(hosts) == 0 {
		return nil, nil
	}

	// Probe hosts concurrently to populate kernel ARP table.
	probeAll(hosts)

	// Read ARP table from OS.
	arpTable := readARPTable()

	// Build results for IPs that are in our subnet and have ARP entries.
	var results []ScanResult
	for ip, mac := range arpTable {
		if !ipNet.Contains(net.ParseIP(ip)) {
			continue
		}
		hostname := reverseHostname(ip)
		vendor := lookupVendor(mac)
		results = append(results, ScanResult{
			IP:       ip,
			MAC:      mac,
			Hostname: hostname,
			Vendor:   vendor,
		})
	}
	return results, nil
}

// ─── Network helpers ──────────────────────────────────────────────────────────

// localCIDRs returns all RFC1918 CIDR strings derived from local interfaces.
func localCIDRs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var cidrs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if isVirtualIface(iface.Name) {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if !isPrivate(ip) {
				continue
			}
			// Limit to subnets ≤ /16 (≤ 65536 hosts) to avoid runaway scans.
			ones, bits := ipNet.Mask.Size()
			if bits == 32 && ones < 16 {
				continue
			}
			network := &net.IPNet{IP: ip.Mask(ipNet.Mask), Mask: ipNet.Mask}
			cidrs = append(cidrs, network.String())
		}
	}
	return cidrs
}

func isVirtualIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"docker", "br-", "cni", "veth", "flannel", "tun", "tap", "wg", "tailscale", "virbr", "zt", "lo"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func isPrivate(ip net.IP) bool {
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
	}
	return false
}

// hostsInNet enumerates all usable host addresses (excludes network + broadcast).
func hostsInNet(network *net.IPNet) []string {
	ip := network.IP.To4()
	if ip == nil {
		return nil
	}
	base := binary.BigEndian.Uint32(ip)
	mask := binary.BigEndian.Uint32([]byte(network.Mask))
	start := (base & mask) + 1
	end := (base | ^mask) - 1 // exclude broadcast
	if end < start {
		return nil
	}
	// Cap at 1022 hosts (/22) per scan to avoid overloading small networks.
	max := end - start + 1
	if max > 1022 {
		max = 1022
	}
	hosts := make([]string, 0, max)
	for i := uint32(0); i < max; i++ {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, start+i)
		hosts = append(hosts, net.IP(b).String())
	}
	return hosts
}

// ─── Probe ────────────────────────────────────────────────────────────────────

// probeAll sends a UDP datagram to port 65533 of each IP to trigger ARP resolution.
// The packets are intentionally sent to a closed port; we only care that the kernel
// issues an ARP request, populating the ARP cache.
func probeAll(hosts []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, h := range hosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			conn, err := net.DialTimeout("udp", ip+":65533", 300*time.Millisecond)
			if err == nil {
				// Actually write 1 byte so the kernel issues an ARP request.
				// Just dialing (connect) is not enough on Windows/macOS.
				_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
				_, _ = conn.Write([]byte{0})
				conn.Close()
			}
		}(h)
	}
	wg.Wait()
	// Give the kernel time to receive and process ARP replies.
	time.Sleep(1500 * time.Millisecond)
}

// ─── ARP table ────────────────────────────────────────────────────────────────

// readARPTable returns a map of IP → MAC from the OS ARP cache.
func readARPTable() map[string]string {
	switch runtime.GOOS {
	case "linux":
		return readARPLinux()
	case "windows":
		return readARPWindows()
	default:
		return readARPCommand()
	}
}

// readARPLinux reads /proc/net/arp directly (fast, no subprocess).
func readARPLinux() map[string]string {
	result := make(map[string]string)
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return readARPCommand()
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		mac := strings.ToUpper(fields[3])
		if mac == "00:00:00:00:00:00" || mac == "" {
			continue
		}
		result[ip] = mac
	}
	return result
}

// arpLineRe matches IP + MAC from arp -a output across all platforms.
// Uses \D+? (non-greedy non-digit sequence) between IP and MAC so that it handles:
//   - Windows:   "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic"
//   - macOS:     "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 [ether]"
//   - Linux arp: "gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
var arpLineRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\D+?([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})`)

// readARPWindows reads the Windows neighbor cache via PowerShell Get-NetNeighbor
// (Windows 8+), which gives structured CSV output. Falls back to arp -a.
func readARPWindows() map[string]string {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Csv -NoTypeInformation").Output()
	if err == nil && len(out) > 0 {
		if result := parseGetNetNeighbor(string(out)); len(result) > 0 {
			return result
		}
	}
	return readARPCommand()
}

// parseGetNetNeighbor parses CSV output from PowerShell Get-NetNeighbor.
// Expected CSV columns: "IPAddress","LinkLayerAddress","State"
func parseGetNetNeighbor(output string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(output, "\n")
	for _, line := range lines[1:] { // skip CSV header
		line = strings.TrimSpace(line)
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}
		ip := strings.Trim(parts[0], `"`)
		mac := strings.ToUpper(strings.Trim(parts[1], `"`))
		state := strings.Trim(parts[2], `"`)
		if ip == "" || mac == "" || mac == "FF-FF-FF-FF-FF-FF" || mac == "00-00-00-00-00-00" {
			continue
		}
		// Only include entries that indicate the host was recently reachable.
		switch state {
		case "Reachable", "Stale", "Delay", "Probe":
		default:
			continue
		}
		mac = strings.ReplaceAll(mac, "-", ":")
		result[ip] = mac
	}
	return result
}

// readARPCommand parses `arp -a` output (cross-platform fallback).
func readARPCommand() map[string]string {
	result := make(map[string]string)
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(out), "\n") {
		m := arpLineRe.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		ip := m[1]
		mac := strings.ToUpper(strings.ReplaceAll(m[2], "-", ":"))
		if mac == "00:00:00:00:00:00" {
			continue
		}
		result[ip] = mac
	}
	return result
}

// ─── DNS ─────────────────────────────────────────────────────────────────────

// reverseHostname does a PTR lookup with a short timeout.
func reverseHostname(ip string) string {
	ch := make(chan string, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			ch <- ""
			return
		}
		ch <- strings.TrimSuffix(names[0], ".")
	}()
	select {
	case name := <-ch:
		return name
	case <-time.After(500 * time.Millisecond):
		return ""
	}
}

// ─── OUI vendor lookup ────────────────────────────────────────────────────────

// lookupVendor returns the manufacturer name for a MAC address using a
// hardcoded table of the most common OUI prefixes.
func lookupVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(mac[:8]) // "XX:XX:XX"
	if v, ok := ouiTable[prefix]; ok {
		return v
	}
	return ""
}

// ouiTable maps the first 3 octets (uppercase, colon-separated) to vendor names.
// Generated from the IEEE OUI registry; covers the most frequently seen prefixes.
var ouiTable = map[string]string{
	// Apple
	"00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
	"00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple", "00:17:F2": "Apple",
	"00:19:E3": "Apple", "00:1B:63": "Apple", "00:1C:B3": "Apple", "00:1D:4F": "Apple",
	"00:1E:52": "Apple", "00:1E:C2": "Apple", "00:1F:5B": "Apple", "00:1F:F3": "Apple",
	"00:21:E9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple", "00:23:32": "Apple",
	"00:23:DF": "Apple", "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
	"00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple", "00:26:B0": "Apple",
	"00:26:BB": "Apple", "00:30:65": "Apple", "00:3E:E1": "Apple", "00:50:E4": "Apple",
	"00:56:CD": "Apple", "00:61:71": "Apple", "00:6D:52": "Apple", "00:88:65": "Apple",
	"04:0C:CE": "Apple", "04:15:52": "Apple", "04:26:65": "Apple", "04:48:9A": "Apple",
	"04:52:F3": "Apple", "04:54:53": "Apple", "04:69:F8": "Apple", "04:D3:CF": "Apple",
	"04:F1:3E": "Apple", "08:00:07": "Apple", "08:6D:41": "Apple", "08:70:45": "Apple",
	"0C:30:21": "Apple", "0C:3E:9F": "Apple", "0C:74:C2": "Apple", "0C:77:1A": "Apple",
	"10:1C:0C": "Apple", "10:40:F3": "Apple", "10:93:E9": "Apple", "10:9A:DD": "Apple",
	"14:20:5E": "Apple", "14:5A:05": "Apple", "14:7D:DA": "Apple", "14:8F:C6": "Apple",
	"18:20:32": "Apple", "18:65:90": "Apple", "18:AF:61": "Apple", "18:E7:F4": "Apple",
	"1C:1A:C0": "Apple", "1C:36:BB": "Apple", "1C:5C:F2": "Apple", "1C:9E:46": "Apple",
	"20:3C:AE": "Apple", "20:78:F0": "Apple", "20:7D:74": "Apple", "20:A2:E4": "Apple",
	"20:AB:37": "Apple", "24:A0:74": "Apple", "24:AB:81": "Apple", "24:E3:14": "Apple",
	"28:37:37": "Apple", "28:6A:B8": "Apple", "28:A0:2B": "Apple", "28:CF:DA": "Apple",
	"28:CF:E9": "Apple", "28:E0:2C": "Apple", "28:E1:4C": "Apple", "2C:BE:08": "Apple",
	"2C:F0:A2": "Apple", "34:08:BC": "Apple", "34:15:9E": "Apple", "34:36:3B": "Apple",
	"38:0F:4A": "Apple", "38:53:9C": "Apple", "38:66:F0": "Apple", "3C:07:54": "Apple",
	"3C:15:C2": "Apple", "40:30:04": "Apple", "40:3C:FC": "Apple", "40:6C:8F": "Apple",
	"40:A6:D9": "Apple", "40:B3:95": "Apple", "40:CB:C0": "Apple", "40:D3:2D": "Apple",
	"44:00:10": "Apple", "44:2A:60": "Apple", "44:FB:42": "Apple", "48:43:7C": "Apple",
	"48:74:6E": "Apple", "48:BF:6B": "Apple", "4C:32:75": "Apple", "4C:57:CA": "Apple",
	"4C:74:BF": "Apple", "4C:8D:79": "Apple", "50:32:37": "Apple", "50:7A:55": "Apple",
	"50:EA:D6": "Apple", "54:26:96": "Apple", "54:4E:90": "Apple", "54:72:4F": "Apple",
	"54:99:63": "Apple", "54:AE:27": "Apple", "54:E4:3A": "Apple", "58:1F:AA": "Apple",
	"58:55:CA": "Apple", "58:7F:57": "Apple", "5C:59:48": "Apple", "5C:97:F3": "Apple",
	"5C:F9:38": "Apple", "60:03:08": "Apple", "60:33:4B": "Apple", "60:69:44": "Apple",
	"60:9A:C1": "Apple", "60:C5:47": "Apple", "60:D9:C7": "Apple", "60:F4:45": "Apple",
	"60:F8:1D": "Apple", "64:20:0C": "Apple", "64:76:BA": "Apple", "64:A5:C3": "Apple",
	"64:B9:E8": "Apple", "68:9C:70": "Apple", "68:A8:6D": "Apple", "68:D9:3C": "Apple",
	"6C:40:08": "Apple", "6C:70:9F": "Apple", "6C:72:E7": "Apple", "70:14:A6": "Apple",
	"70:3E:AC": "Apple", "70:56:81": "Apple", "70:73:CB": "Apple", "70:CD:60": "Apple",
	"70:DE:E2": "Apple", "70:EC:E4": "Apple", "74:1B:B2": "Apple", "74:8D:08": "Apple",
	"78:31:C1": "Apple", "78:4F:43": "Apple", "78:6C:1C": "Apple", "78:7B:8A": "Apple",
	"78:CA:39": "Apple", "7C:04:D0": "Apple", "7C:6D:62": "Apple", "7C:C3:A1": "Apple",
	"7C:D1:C3": "Apple", "80:00:6E": "Apple", "80:49:71": "Apple", "80:82:23": "Apple",
	"80:92:9F": "Apple", "80:BE:05": "Apple", "84:29:99": "Apple", "84:38:35": "Apple",
	"84:78:8B": "Apple", "84:85:06": "Apple", "84:FC:FE": "Apple", "88:1F:A1": "Apple",
	"88:53:2E": "Apple", "88:CB:87": "Apple", "88:E8:7F": "Apple", "8C:2D:AA": "Apple",
	"8C:7B:9D": "Apple", "8C:7C:92": "Apple", "8C:85:90": "Apple", "8C:8E:F2": "Apple",
	"8C:FA:BA": "Apple", "90:27:E4": "Apple", "90:60:F1": "Apple", "90:72:40": "Apple",
	"90:84:0D": "Apple", "90:8D:6C": "Apple", "90:B0:ED": "Apple", "90:B2:1F": "Apple",
	"90:B9:31": "Apple", "90:FD:61": "Apple", "94:94:26": "Apple", "94:BF:2D": "Apple",
	"94:E9:6A": "Apple", "98:01:A7": "Apple", "98:03:D8": "Apple", "98:10:E8": "Apple",
	"98:5A:EB": "Apple", "98:FE:94": "Apple", "9C:04:EB": "Apple", "9C:20:7B": "Apple",
	"9C:35:EB": "Apple", "9C:84:BF": "Apple", "9C:F3:87": "Apple", "A0:11:FA": "Apple",
	"A0:4E:A7": "Apple", "A0:99:9B": "Apple", "A0:D7:95": "Apple", "A4:5E:60": "Apple",
	"A4:67:06": "Apple", "A4:B1:97": "Apple", "A4:C3:61": "Apple", "A4:D1:8C": "Apple",
	"A4:F1:E8": "Apple", "A8:20:66": "Apple", "A8:5B:78": "Apple", "A8:60:B6": "Apple",
	"A8:86:DD": "Apple", "A8:96:8A": "Apple", "A8:BB:CF": "Apple", "AC:29:3A": "Apple",
	"AC:3C:0B": "Apple", "AC:61:EA": "Apple", "AC:87:A3": "Apple", "AC:BC:32": "Apple",
	"AC:CF:5C": "Apple", "AC:E4:B5": "Apple", "B0:65:BD": "Apple", "B0:9F:BA": "Apple",
	"B4:18:D1": "Apple", "B4:4B:D2": "Apple", "B4:8B:19": "Apple", "B4:F0:AB": "Apple",
	"B8:09:8A": "Apple", "B8:17:C2": "Apple", "B8:41:A4": "Apple", "B8:44:D9": "Apple",
	"B8:53:AC": "Apple", "B8:78:2E": "Apple", "B8:C1:11": "Apple", "BC:3B:AF": "Apple",
	"BC:4C:C4": "Apple", "BC:52:B7": "Apple", "BC:67:1C": "Apple", "C0:9F:42": "Apple",
	"C4:2C:03": "Apple", "C4:61:8B": "Apple", "C4:B3:01": "Apple", "C8:2A:14": "Apple",
	"C8:33:4B": "Apple", "C8:69:CD": "Apple", "C8:6F:1D": "Apple", "C8:85:50": "Apple",
	"C8:BC:C8": "Apple", "C8:D0:83": "Apple", "CC:08:8D": "Apple", "CC:20:E8": "Apple",
	"CC:25:EF": "Apple", "CC:44:63": "Apple", "D0:03:4B": "Apple", "D0:23:DB": "Apple",
	"D0:25:98": "Apple", "D0:4F:7E": "Apple", "D0:81:7A": "Apple", "D0:A6:37": "Apple",
	"D4:61:9D": "Apple", "D4:9A:20": "Apple", "D4:DC:CD": "Apple", "D4:F4:6F": "Apple",
	"D8:00:4D": "Apple", "D8:1D:72": "Apple", "D8:30:62": "Apple", "D8:96:95": "Apple",
	"D8:A2:5E": "Apple", "D8:BB:C1": "Apple", "D8:CF:9C": "Apple", "DC:2B:2A": "Apple",
	"DC:9B:9C": "Apple", "E0:5F:45": "Apple", "E0:66:78": "Apple", "E0:AC:CB": "Apple",
	"E0:B5:2D": "Apple", "E0:C7:67": "Apple", "E0:F8:47": "Apple", "E4:25:E7": "Apple",
	"E4:8B:7F": "Apple", "E4:9A:79": "Apple", "E4:CE:8F": "Apple", "E4:E4:AB": "Apple",
	"E8:04:0B": "Apple", "E8:06:88": "Apple", "E8:80:2E": "Apple", "EC:35:86": "Apple",
	"EC:85:2F": "Apple", "F0:98:9D": "Apple", "F0:B4:79": "Apple", "F0:CB:A1": "Apple",
	"F0:D1:A9": "Apple", "F0:DB:E2": "Apple", "F0:DC:E2": "Apple", "F0:F6:1C": "Apple",
	"F4:0F:24": "Apple", "F4:1B:A1": "Apple", "F4:37:B7": "Apple", "F4:5C:89": "Apple",
	"F4:F1:5A": "Apple", "F8:1E:DF": "Apple", "F8:27:93": "Apple", "F8:2D:7C": "Apple",
	"F8:62:14": "Apple", "F8:6D:35": "Apple", "FC:25:3F": "Apple", "FC:E9:98": "Apple",
	// Samsung
	"00:07:AB": "Samsung", "00:12:47": "Samsung", "00:12:FB": "Samsung", "00:13:77": "Samsung",
	"00:15:99": "Samsung", "00:16:32": "Samsung", "00:16:6B": "Samsung", "00:16:6C": "Samsung",
	"00:17:C9": "Samsung", "00:17:D5": "Samsung", "00:18:AF": "Samsung", "00:1A:8A": "Samsung",
	"00:1B:98": "Samsung", "00:1C:43": "Samsung", "00:1D:25": "Samsung", "00:1E:7D": "Samsung",
	"00:1F:CC": "Samsung", "00:21:D1": "Samsung", "00:21:D2": "Samsung", "00:23:39": "Samsung",
	"00:23:C2": "Samsung", "00:24:54": "Samsung", "00:24:90": "Samsung", "00:24:E9": "Samsung",
	"00:25:38": "Samsung", "00:26:5F": "Samsung", "00:26:37": "Samsung", "00:E3:B2": "Samsung",
	"04:18:D6": "Samsung", "04:1B:BA": "Samsung", "04:FE:31": "Samsung", "08:08:C2": "Samsung",
	"08:37:3D": "Samsung", "08:3D:88": "Samsung", "08:FC:88": "Samsung", "0C:14:20": "Samsung",
	"0C:89:10": "Samsung", "10:1D:C0": "Samsung", "10:3B:59": "Samsung", "10:67:6D": "Samsung",
	"14:49:E0": "Samsung", "14:89:FD": "Samsung", "18:22:7E": "Samsung", "18:26:49": "Samsung",
	"1C:62:B8": "Samsung", "1C:66:AA": "Samsung", "20:13:E0": "Samsung", "20:64:32": "Samsung",
	"24:4B:81": "Samsung", "28:27:BF": "Samsung", "2C:0E:3D": "Samsung", "2C:AE:2B": "Samsung",
	"30:96:FB": "Samsung", "34:23:87": "Samsung", "34:AA:8B": "Samsung", "38:01:97": "Samsung",
	"38:2D:D1": "Samsung", "3C:62:00": "Samsung", "40:0E:85": "Samsung", "44:65:0D": "Samsung",
	"48:13:7E": "Samsung", "48:5A:3F": "Samsung", "4C:3C:16": "Samsung", "50:01:BB": "Samsung",
	"50:32:75": "Samsung", "50:A4:C8": "Samsung", "50:CC:F8": "Samsung", "54:40:AD": "Samsung",
	"54:88:0E": "Samsung", "58:C3:8B": "Samsung", "5C:0A:5B": "Samsung", "5C:3C:27": "Samsung",
	"60:A1:0A": "Samsung", "60:D0:A9": "Samsung", "64:77:91": "Samsung", "68:EB:C5": "Samsung",
	"6C:2F:2C": "Samsung", "70:F9:27": "Samsung", "74:45:8A": "Samsung", "78:25:AD": "Samsung",
	"7C:61:93": "Samsung", "80:57:19": "Samsung", "84:25:DB": "Samsung", "84:51:81": "Samsung",
	"88:32:9B": "Samsung", "88:9B:39": "Samsung", "8C:77:12": "Samsung", "90:18:7C": "Samsung",
	"94:01:C2": "Samsung", "98:52:B1": "Samsung", "98:D6:BB": "Samsung", "9C:65:B0": "Samsung",
	"A0:82:1F": "Samsung", "A8:7C:01": "Samsung", "AC:5F:3E": "Samsung", "B0:47:BF": "Samsung",
	"B0:EC:71": "Samsung", "B4:07:F9": "Samsung", "B4:3A:28": "Samsung", "B4:EF:FA": "Samsung",
	"B8:5E:7B": "Samsung", "BC:14:85": "Samsung", "BC:20:A4": "Samsung", "BC:72:B1": "Samsung",
	"C0:BD:D1": "Samsung", "C4:42:02": "Samsung", "C8:14:79": "Samsung", "CC:07:AB": "Samsung",
	"D0:17:6A": "Samsung", "D0:22:BE": "Samsung", "D4:87:D8": "Samsung", "D8:57:EF": "Samsung",
	"E4:12:1D": "Samsung", "E4:40:E2": "Samsung", "E8:50:8B": "Samsung", "EC:9B:F3": "Samsung",
	"F0:25:B7": "Samsung", "F4:09:D8": "Samsung", "F8:04:2E": "Samsung", "FC:A1:3E": "Samsung",
	// Huawei
	"00:18:82": "Huawei", "00:1E:10": "Huawei", "00:25:9E": "Huawei", "00:46:4B": "Huawei",
	"04:02:1F": "Huawei", "04:BD:70": "Huawei", "04:C0:6F": "Huawei", "04:F9:38": "Huawei",
	"08:00:87": "Huawei", "08:19:A6": "Huawei", "08:9B:4B": "Huawei", "0C:37:DC": "Huawei",
	"0C:96:BF": "Huawei", "10:1B:54": "Huawei", "10:47:80": "Huawei", "10:C6:1F": "Huawei",
	"14:B9:68": "Huawei", "20:08:ED": "Huawei", "20:0B:C7": "Huawei", "20:F3:A3": "Huawei",
	"24:09:95": "Huawei", "24:DB:AC": "Huawei", "28:3C:E4": "Huawei", "28:6E:D4": "Huawei",
	"2C:9D:1E": "Huawei", "30:D1:7E": "Huawei", "34:6B:D3": "Huawei", "34:A8:4E": "Huawei",
	"38:37:8B": "Huawei", "3C:47:11": "Huawei", "40:4D:8E": "Huawei", "40:CB:A8": "Huawei",
	"44:55:B1": "Huawei", "48:AD:08": "Huawei", "4C:1F:CC": "Huawei", "4C:54:99": "Huawei",
	"50:9F:27": "Huawei", "54:51:1B": "Huawei", "58:2A:F7": "Huawei", "5C:C3:07": "Huawei",
	"5C:EB:68": "Huawei", "60:DE:44": "Huawei", "60:E7:01": "Huawei", "68:13:24": "Huawei",
	"68:89:75": "Huawei", "68:CC:6E": "Huawei", "70:7B:E8": "Huawei", "70:A8:E3": "Huawei",
	"74:A0:2F": "Huawei", "78:1D:BA": "Huawei", "7C:11:CB": "Huawei", "80:38:FD": "Huawei",
	"80:71:7A": "Huawei", "80:D0:9B": "Huawei", "84:A8:E4": "Huawei", "88:3F:D3": "Huawei",
	"88:E3:AB": "Huawei", "8C:0D:76": "Huawei", "90:17:AC": "Huawei", "94:04:9C": "Huawei",
	"94:DB:DA": "Huawei", "98:D8:63": "Huawei", "9C:74:1A": "Huawei", "A4:50:46": "Huawei",
	"A8:CA:7B": "Huawei", "AC:44:F2": "Huawei", "AC:61:75": "Huawei", "B4:15:13": "Huawei",
	"B8:08:D7": "Huawei", "BC:76:70": "Huawei", "C4:07:2F": "Huawei", "C4:8E:8F": "Huawei",
	"C8:51:95": "Huawei", "CC:53:B5": "Huawei", "CC:96:A0": "Huawei", "D0:7A:B5": "Huawei",
	"D4:6A:A8": "Huawei", "D4:6E:5C": "Huawei", "DC:D2:FC": "Huawei", "E0:19:1D": "Huawei",
	"E0:24:7F": "Huawei", "E4:68:A3": "Huawei", "E8:08:8B": "Huawei", "E8:CD:2D": "Huawei",
	"EC:23:3D": "Huawei", "F0:1C:13": "Huawei", "F4:4C:7F": "Huawei", "F8:4E:73": "Huawei",
	// Cisco
	"00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco", "00:01:63": "Cisco",
	"00:01:64": "Cisco", "00:01:96": "Cisco", "00:01:97": "Cisco", "00:01:C7": "Cisco",
	"00:02:16": "Cisco", "00:02:17": "Cisco", "00:02:3D": "Cisco", "00:02:4A": "Cisco",
	"00:02:4B": "Cisco", "00:02:7D": "Cisco", "00:02:7E": "Cisco", "00:02:B9": "Cisco",
	"00:03:6B": "Cisco", "00:03:6C": "Cisco", "00:03:9F": "Cisco", "00:03:A0": "Cisco",
	"00:03:E3": "Cisco", "00:03:E4": "Cisco", "00:03:FD": "Cisco", "00:03:FE": "Cisco",
	"00:04:27": "Cisco", "00:04:28": "Cisco", "00:04:4D": "Cisco", "00:04:6D": "Cisco",
	"00:04:C0": "Cisco", "00:04:DD": "Cisco", "00:05:32": "Cisco", "00:05:33": "Cisco",
	"00:05:5E": "Cisco", "00:05:73": "Cisco", "00:05:74": "Cisco", "00:05:9A": "Cisco",
	"00:06:28": "Cisco", "00:06:C1": "Cisco", "00:06:D6": "Cisco", "00:06:D7": "Cisco",
	"00:06:F6": "Cisco", "00:07:0D": "Cisco", "00:07:0E": "Cisco", "00:07:4F": "Cisco",
	"00:07:50": "Cisco", "00:07:84": "Cisco", "00:07:85": "Cisco", "00:07:B3": "Cisco",
	"00:07:EB": "Cisco", "00:08:20": "Cisco", "00:08:21": "Cisco", "00:08:30": "Cisco",
	"00:08:7C": "Cisco", "00:08:A3": "Cisco", "00:09:12": "Cisco", "00:09:43": "Cisco",
	"00:09:B7": "Cisco", "00:0A:41": "Cisco", "00:0A:42": "Cisco", "00:0A:8A": "Cisco",
	"00:0A:B7": "Cisco", "00:0A:B8": "Cisco", "00:0B:45": "Cisco", "00:0B:46": "Cisco",
	"00:0B:5F": "Cisco", "00:0B:60": "Cisco", "00:0B:FC": "Cisco", "00:0B:FD": "Cisco",
	"00:0C:30": "Cisco", "00:0C:85": "Cisco", "00:0C:86": "Cisco", "00:0C:CE": "Cisco",
	"00:0D:28": "Cisco", "00:0D:29": "Cisco", "00:0D:65": "Cisco", "00:0D:BC": "Cisco",
	"00:0E:08": "Cisco", "00:0E:38": "Cisco", "00:0E:39": "Cisco", "00:0E:83": "Cisco",
	"00:0E:D6": "Cisco", "00:0F:23": "Cisco", "00:0F:24": "Cisco", "00:0F:8F": "Cisco",
	"00:0F:90": "Cisco", "00:0F:F7": "Cisco", "00:0F:F8": "Cisco", "00:10:07": "Cisco",
	"00:10:0B": "Cisco", "00:10:11": "Cisco", "00:10:14": "Cisco", "00:10:1F": "Cisco",
	"00:10:29": "Cisco", "00:10:2F": "Cisco", "00:10:4B": "Cisco", "00:10:54": "Cisco",
	"00:10:79": "Cisco", "00:10:7B": "Cisco", "00:10:A6": "Cisco", "00:10:F6": "Cisco",
	"00:11:20": "Cisco", "00:11:21": "Cisco", "00:11:5C": "Cisco", "00:11:92": "Cisco",
	"00:11:93": "Cisco", "00:11:BB": "Cisco", "00:12:00": "Cisco", "00:12:01": "Cisco",
	"00:12:43": "Cisco", "00:12:44": "Cisco", "00:12:7F": "Cisco", "00:12:80": "Cisco",
	"00:12:D9": "Cisco", "00:13:1A": "Cisco", "00:13:60": "Cisco", "00:13:5F": "Cisco",
	"00:13:7F": "Cisco", "00:13:C3": "Cisco", "00:14:1B": "Cisco", "00:14:1C": "Cisco",
	"00:14:69": "Cisco", "00:14:6A": "Cisco", "00:14:A9": "Cisco", "00:14:BF": "Cisco",
	"00:14:F1": "Cisco", "00:14:F2": "Cisco", "00:15:2B": "Cisco", "00:15:2C": "Cisco",
	"00:15:62": "Cisco", "00:15:63": "Cisco", "00:15:C6": "Cisco", "00:15:C7": "Cisco",
	"00:15:F9": "Cisco", "00:16:46": "Cisco", "00:16:47": "Cisco", "00:16:9C": "Cisco",
	"00:16:9D": "Cisco", "00:16:C7": "Cisco", "00:16:C8": "Cisco", "00:17:0E": "Cisco",
	"00:17:0F": "Cisco", "00:17:59": "Cisco", "00:17:5A": "Cisco", "00:17:94": "Cisco",
	"00:17:95": "Cisco", "00:17:DF": "Cisco", "00:17:E0": "Cisco", "00:18:0F": "Cisco",
	"00:18:73": "Cisco", "00:18:74": "Cisco", "00:18:B9": "Cisco", "00:18:BA": "Cisco",
	"00:19:06": "Cisco", "00:19:07": "Cisco", "00:19:2F": "Cisco", "00:19:30": "Cisco",
	"00:19:55": "Cisco", "00:19:56": "Cisco", "00:19:AA": "Cisco", "00:19:AB": "Cisco",
	"00:1A:2F": "Cisco", "00:1A:30": "Cisco", "00:1A:6C": "Cisco", "00:1A:6D": "Cisco",
	"00:1A:A1": "Cisco", "00:1A:A2": "Cisco", "00:1A:E2": "Cisco", "00:1A:E3": "Cisco",
	"00:1B:2A": "Cisco", "00:1B:2B": "Cisco", "00:1B:54": "Cisco", "00:1B:67": "Cisco",
	"00:1B:D4": "Cisco", "00:1B:D5": "Cisco", "00:1C:0E": "Cisco", "00:1C:0F": "Cisco",
	"00:1C:57": "Cisco", "00:1C:58": "Cisco", "00:1C:B0": "Cisco", "00:1C:B1": "Cisco",
	"00:1C:F6": "Cisco", "00:1C:F9": "Cisco", "00:1D:45": "Cisco", "00:1D:46": "Cisco",
	"00:1D:70": "Cisco", "00:1D:71": "Cisco", "00:1D:A1": "Cisco", "00:1D:A2": "Cisco",
	"00:1E:13": "Cisco", "00:1E:14": "Cisco", "00:1E:49": "Cisco", "00:1E:4A": "Cisco",
	"00:1E:79": "Cisco", "00:1E:7A": "Cisco", "00:1E:BD": "Cisco", "00:1E:BE": "Cisco",
	"00:1E:E5": "Cisco", "00:1E:E6": "Cisco", "00:1F:26": "Cisco", "00:1F:27": "Cisco",
	"00:1F:6C": "Cisco", "00:1F:6D": "Cisco", "00:1F:9D": "Cisco", "00:1F:9E": "Cisco",
	"00:1F:C9": "Cisco", "00:1F:CA": "Cisco", "00:20:35": "Cisco", "00:21:1B": "Cisco",
	"00:21:1C": "Cisco", "00:21:55": "Cisco", "00:21:56": "Cisco", "00:21:A0": "Cisco",
	"00:21:A1": "Cisco", "00:22:0C": "Cisco", "00:22:0D": "Cisco", "00:22:55": "Cisco",
	"00:22:56": "Cisco", "00:22:90": "Cisco", "00:22:91": "Cisco", "00:22:BD": "Cisco",
	"00:22:BE": "Cisco", "00:23:04": "Cisco", "00:23:05": "Cisco", "00:23:33": "Cisco",
	"00:23:34": "Cisco", "00:23:5E": "Cisco", "00:23:5F": "Cisco", "00:23:AB": "Cisco",
	"00:23:AC": "Cisco", "00:23:BE": "Cisco", "00:23:BF": "Cisco", "00:23:EA": "Cisco",
	"00:23:EB": "Cisco", "00:24:13": "Cisco", "00:24:14": "Cisco", "00:24:97": "Cisco",
	"00:24:98": "Cisco", "00:24:C3": "Cisco", "00:24:C4": "Cisco", "00:25:2E": "Cisco",
	"00:25:2F": "Cisco", "00:25:45": "Cisco", "00:25:46": "Cisco", "00:25:83": "Cisco",
	"00:25:84": "Cisco", "00:25:B4": "Cisco", "00:25:B5": "Cisco", "00:26:0A": "Cisco",
	"00:26:0B": "Cisco", "00:26:52": "Cisco", "00:26:53": "Cisco", "00:26:99": "Cisco",
	"00:26:CA": "Cisco", "00:26:CB": "Cisco", "00:27:0D": "Cisco", "00:27:0E": "Cisco",
	"00:30:19": "Cisco", "00:30:24": "Cisco", "00:30:40": "Cisco", "00:30:71": "Cisco",
	"00:30:78": "Cisco", "00:30:80": "Cisco", "00:30:85": "Cisco", "00:30:94": "Cisco",
	"00:30:96": "Cisco", "00:30:A3": "Cisco", "00:30:F2": "Cisco", "00:40:0B": "Cisco",
	"00:50:0F": "Cisco", "00:50:2A": "Cisco", "00:60:47": "Cisco", "00:60:5C": "Cisco",
	"00:60:70": "Cisco", "00:60:83": "Cisco", "00:D0:BA": "Cisco", "00:E0:1E": "Cisco",
	"00:E0:A3": "Cisco", "00:E0:F9": "Cisco", "58:AC:78": "Cisco", "58:BC:27": "Cisco",
	"5C:FC:66": "Cisco", "60:8D:26": "Cisco", "64:00:F1": "Cisco", "64:EE:B7": "Cisco",
	"68:BC:0C": "Cisco", "6C:41:6A": "Cisco", "70:01:B5": "Cisco", "70:6D:15": "Cisco",
	"74:86:7A": "Cisco", "78:DA:6E": "Cisco", "7C:69:F6": "Cisco", "84:78:AC": "Cisco",
	"84:B8:02": "Cisco", "88:43:E1": "Cisco", "8C:60:4F": "Cisco", "90:21:55": "Cisco",
	"94:D4:69": "Cisco", "98:90:96": "Cisco", "A0:EC:F9": "Cisco", "A4:56:30": "Cisco",
	"A8:9D:21": "Cisco", "AC:7E:8A": "Cisco", "B0:AA:77": "Cisco", "B4:14:89": "Cisco",
	"B8:38:61": "Cisco", "BC:16:65": "Cisco", "C0:62:6B": "Cisco", "C4:7D:4F": "Cisco",
	"C8:00:84": "Cisco", "CC:46:D6": "Cisco", "D4:8C:B5": "Cisco", "D8:24:BD": "Cisco",
	"DC:7B:94": "Cisco", "E0:2F:6D": "Cisco", "E4:90:7E": "Cisco", "E8:B7:48": "Cisco",
	"EC:30:91": "Cisco", "F0:29:29": "Cisco", "F4:CF:A2": "Cisco", "F8:72:EA": "Cisco",
	// Intel (NIC)
	"00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel", "00:07:E9": "Intel",
	"00:08:02": "Intel", "00:0C:F1": "Intel", "00:0E:0C": "Intel", "00:0E:35": "Intel",
	"00:12:F0": "Intel", "00:13:02": "Intel", "00:13:20": "Intel", "00:13:E8": "Intel",
	"00:15:00": "Intel", "00:15:17": "Intel", "00:16:76": "Intel", "00:16:EA": "Intel",
	"00:16:EB": "Intel", "00:18:DE": "Intel", "00:19:D1": "Intel", "00:19:D2": "Intel",
	"00:1B:21": "Intel", "00:1C:C0": "Intel", "00:1D:E0": "Intel", "00:1E:64": "Intel",
	"00:1E:65": "Intel", "00:1F:3B": "Intel", "00:21:6A": "Intel", "00:21:6B": "Intel",
	"00:22:FA": "Intel", "00:23:14": "Intel", "00:24:D7": "Intel", "00:27:10": "Intel",
	"18:67:B0": "Intel", "20:89:84": "Intel", "24:77:03": "Intel", "28:D2:44": "Intel",
	"34:02:86": "Intel", "34:13:E8": "Intel", "38:2C:4A": "Intel", "40:25:C2": "Intel",
	"40:B0:34": "Intel", "44:85:00": "Intel", "48:51:B7": "Intel", "4C:EB:42": "Intel",
	"54:27:1E": "Intel", "58:91:CF": "Intel", "5C:51:4F": "Intel", "60:67:20": "Intel",
	"64:00:6A": "Intel", "64:51:06": "Intel", "68:05:CA": "Intel", "6C:88:14": "Intel",
	"70:5A:0F": "Intel", "74:E5:43": "Intel", "78:92:9C": "Intel", "7C:7A:91": "Intel",
	"80:19:34": "Intel", "84:3A:4B": "Intel", "88:53:95": "Intel", "8C:EC:4B": "Intel",
	"8C:F5:A3": "Intel", "90:E2:BA": "Intel", "94:65:9C": "Intel", "98:4F:EE": "Intel",
	"A0:36:9F": "Intel", "A0:88:B4": "Intel", "A4:4E:31": "Intel", "A4:C3:F0": "Intel",
	"A8:6B:AD": "Intel", "AC:72:89": "Intel", "B0:A4:60": "Intel", "B0:C0:90": "Intel",
	"B4:96:91": "Intel", "C4:D9:87": "Intel", "CC:2F:71": "Intel",
	"CC:3D:82": "Intel", "D0:50:99": "Intel", "D0:57:7B": "Intel", "D0:6E:35": "Intel",
	"D4:BE:D9": "Intel", "D8:FC:93": "Intel", "DC:53:60": "Intel", "E4:B3:18": "Intel",
	"E8:94:F6": "Intel", "EC:08:6B": "Intel", "F4:06:69": "Intel", "F8:63:3F": "Intel",
	// Xiaomi
	"00:9E:C8": "Xiaomi", "04:CF:8C": "Xiaomi", "08:21:EF": "Xiaomi", "0C:1D:AF": "Xiaomi",
	"10:2A:B3": "Xiaomi", "18:59:36": "Xiaomi", "20:82:C0": "Xiaomi", "28:6C:07": "Xiaomi",
	"2C:4D:54": "Xiaomi", "34:80:B3": "Xiaomi", "38:A4:ED": "Xiaomi", "3C:BD:3E": "Xiaomi",
	"50:64:2B": "Xiaomi", "58:44:98": "Xiaomi", "5C:E8:EB": "Xiaomi", "60:AB:67": "Xiaomi",
	"64:09:80": "Xiaomi", "64:B4:73": "Xiaomi", "68:DF:DD": "Xiaomi", "6C:5C:3D": "Xiaomi",
	"74:23:44": "Xiaomi", "78:11:DC": "Xiaomi", "7C:1D:D9": "Xiaomi", "80:35:C1": "Xiaomi",
	"84:A9:3E": "Xiaomi", "8C:BE:BE": "Xiaomi", "8C:C8:4B": "Xiaomi", "90:C6:82": "Xiaomi",
	"98:FA:E3": "Xiaomi", "9C:99:A0": "Xiaomi", "A4:53:EE": "Xiaomi", "AC:C1:EE": "Xiaomi",
	"B0:E2:35": "Xiaomi", "C4:6A:B7": "Xiaomi", "C8:0F:10": "Xiaomi", "CC:2D:E0": "Xiaomi",
	"D4:97:0B": "Xiaomi", "DC:44:27": "Xiaomi", "E4:46:DA": "Xiaomi", "F0:B4:29": "Xiaomi",
	"F4:8B:32": "Xiaomi", "F8:A4:5F": "Xiaomi", "FC:64:BA": "Xiaomi",
	// TP-Link
	"00:27:19": "TP-Link", "14:CC:20": "TP-Link", "1C:3B:F3": "TP-Link", "24:05:0F": "TP-Link",
	"2C:55:D3": "TP-Link", "30:B5:C2": "TP-Link", "34:29:12": "TP-Link", "38:94:ED": "TP-Link",
	"3C:84:6A": "TP-Link", "40:4E:36": "TP-Link", "40:8D:5C": "TP-Link", "44:33:4C": "TP-Link",
	"50:3E:AA": "TP-Link", "54:A7:03": "TP-Link", "5C:89:9A": "TP-Link", "60:32:B1": "TP-Link",
	"64:70:02": "TP-Link", "6C:5G:3B": "TP-Link", "70:4F:57": "TP-Link", "74:DA:38": "TP-Link",
	"78:A1:06": "TP-Link", "84:16:F9": "TP-Link", "90:F6:52": "TP-Link",
	"98:DA:C4": "TP-Link", "A0:F3:C1": "TP-Link", "B0:4E:26": "TP-Link", "C0:4A:00": "TP-Link",
	"C4:E9:84": "TP-Link", "D8:15:0D": "TP-Link", "E8:DE:27": "TP-Link", "F0:9F:C2": "TP-Link",
	"F4:EC:38": "TP-Link", "FC:EC:DA": "TP-Link",
	// Synology
	"00:11:32": "Synology", "BC:30:7E": "Synology", "00:23:AE": "Synology",
	// QNAP
	"24:5E:BE": "QNAP", "00:08:9B": "QNAP", "28:62:66": "QNAP",
	// Raspberry Pi
	"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
	// VMware
	"00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
	// VirtualBox
	"08:00:27": "VirtualBox",
	// Dell
	"00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell", "00:0D:56": "Dell",
	"00:0F:1F": "Dell", "00:11:43": "Dell", "00:12:3F": "Dell", "00:13:72": "Dell",
	"00:14:22": "Dell", "00:15:C5": "Dell", "00:16:F0": "Dell", "00:18:8B": "Dell",
	"00:19:B9": "Dell", "00:1A:A0": "Dell", "00:1C:23": "Dell", "00:1D:09": "Dell",
	"00:1E:4F": "Dell", "00:1F:D0": "Dell", "00:21:70": "Dell", "00:22:19": "Dell",
	"00:24:E8": "Dell", "00:25:64": "Dell", "00:26:B9": "Dell",
	"08:60:6E": "Dell", "0C:C4:7A": "Dell", "10:98:36": "Dell", "14:18:77": "Dell",
	"14:FE:B5": "Dell", "18:03:73": "Dell", "18:A9:9B": "Dell", "1C:40:24": "Dell",
	"20:47:47": "Dell", "24:B6:FD": "Dell", "28:F1:0E": "Dell", "34:17:EB": "Dell",
	"34:E6:D7": "Dell", "38:EA:A7": "Dell", "3C:2C:30": "Dell", "44:A8:42": "Dell",
	"48:4D:7E": "Dell", "4C:D9:8F": "Dell", "50:9A:4C": "Dell", "54:9F:35": "Dell",
	"58:8A:5A": "Dell", "5C:26:0A": "Dell", "60:9C:9F": "Dell",
	"74:86:E2": "Dell", "78:45:C4": "Dell",
	"84:2B:2B": "Dell", "90:B1:1C": "Dell",
	"A4:BA:DB": "Dell", "B0:83:FE": "Dell", "B4:45:06": "Dell",
	"B8:AC:6F": "Dell", "BC:EE:7B": "Dell", "C8:1F:66": "Dell", "D4:AE:52": "Dell",
	"D8:9E:F3": "Dell", "EC:F4:BB": "Dell", "F0:1F:AF": "Dell", "F4:8E:38": "Dell",
	"F8:BC:12": "Dell", "FC:15:B4": "Dell",
	// HP / HPE
	"00:01:E6": "HP", "00:01:E7": "HP", "00:02:A5": "HP", "00:04:EA": "HP",
	"00:0B:CD": "HP", "00:0D:9D": "HP", "00:0E:7F": "HP",
	"00:10:83": "HP", "00:11:0A": "HP", "00:12:79": "HP", "00:13:21": "HP",
	"00:14:38": "HP", "00:15:60": "HP", "00:16:35": "HP", "00:17:08": "HP",
	"00:18:FE": "HP", "00:19:BB": "HP", "00:1A:4B": "HP", "00:1B:78": "HP",
	"00:1C:C4": "HP", "00:1D:B3": "HP", "00:1E:0B": "HP", "00:1F:29": "HP",
	"00:21:5A": "HP", "00:22:64": "HP", "00:23:7D": "HP", "00:24:81": "HP",
	"00:25:B3": "HP", "00:26:55": "HP", "3C:D9:2B": "HP",
	"48:0F:CF": "HP", "58:20:B1": "HP", "5C:8A:38": "HP",
	"68:B5:99": "HP", "6C:3B:E5": "HP", "74:46:A0": "HP", "80:C1:6E": "HP",
	"84:34:97": "HP", "88:51:FB": "HP", "94:57:A5": "HP", "98:E7:F4": "HP",
	"9C:8E:99": "HP", "A0:D3:C1": "HP", "A4:5D:36": "HP", "AC:16:2D": "HP",
	"B4:99:BA": "HP", "BC:EA:FA": "HP", "C4:34:6B": "HP", "D4:85:64": "HP",
	"D8:D3:85": "HP", "EC:B1:D7": "HP", "F0:92:1C": "HP",
	// Netgear
	"00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:14:6C": "Netgear",
	"00:18:4D": "Netgear", "00:1B:2F": "Netgear", "00:1E:2A": "Netgear",
	"00:1F:33": "Netgear", "00:22:3F": "Netgear", "00:24:B2": "Netgear",
	"00:26:F2": "Netgear", "10:0D:7F": "Netgear", "20:4E:7F": "Netgear",
	"28:C6:8E": "Netgear", "2C:30:33": "Netgear", "30:46:9A": "Netgear",
	"44:94:FC": "Netgear", "4C:60:DE": "Netgear", "6C:B0:CE": "Netgear",
	"74:44:01": "Netgear", "84:1B:5E": "Netgear", "9C:D3:6D": "Netgear",
	"A0:21:B7": "Netgear", "C0:3F:0E": "Netgear", "C4:3D:C7": "Netgear",
	"E0:46:9A": "Netgear", "E4:F4:C6": "Netgear",
	// Ubiquiti
	"00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti",
	"0C:80:63": "Ubiquiti", "18:E8:29": "Ubiquiti", "24:A4:3C": "Ubiquiti",
	"44:D9:E7": "Ubiquiti", "68:72:51": "Ubiquiti", "78:8A:20": "Ubiquiti",
	"80:2A:A8": "Ubiquiti", "DC:9F:DB": "Ubiquiti", "E4:38:83": "Ubiquiti",
	// MikroTik
	"00:0C:42": "MikroTik", "18:FD:74": "MikroTik", "2C:C8:1B": "MikroTik",
	"48:8F:5A": "MikroTik", "4C:5E:0C": "MikroTik", "64:D1:54": "MikroTik",
	"6C:3B:6B": "MikroTik", "74:4D:28": "MikroTik", "B8:69:F4": "MikroTik",
	"D4:CA:6D": "MikroTik", "DC:2C:6E": "MikroTik",
	"E4:8D:8C": "MikroTik",
}
