// Package server provides SSH-based fallback management for OpenTalon.
// This module handles devices that cannot run the Agent (routers, legacy hosts).
//
// SSH task stubs are intentionally verbose so operators can customize them.
package server

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHClient wraps an authenticated SSH connection.
type SSHClient struct {
	client *ssh.Client
	host   string
}

// NewSSHClient dials the target host with password or key authentication.
func NewSSHClient(host, user, password, keyPEM string) (*SSHClient, error) {
	var authMethods []ssh.AuthMethod

	if keyPEM != "" {
		signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("parsing SSH key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: use known_hosts in production
		Timeout:         15 * time.Second,
	}

	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}
	return &SSHClient{client: client, host: host}, nil
}

// Close cleanly shuts down the SSH connection.
func (s *SSHClient) Close() error { return s.client.Close() }

// Run executes a command and returns combined stdout+stderr.
func (s *SSHClient) Run(cmd string) (string, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

// ── Specific Task Stubs ───────────────────────────────────────────────────────

// FixRPFilter sets rp_filter=0 for tun and enp6s18 on a RockyLinux bypass-router.
// This resolves routing blackhole issues when the host acts as a transparent proxy.
//
// Target: RockyLinux with sing-box / tun-mode routing.
func (s *SSHClient) FixRPFilter() error {
	cmds := []string{
		// Persist via sysctl.d
		`bash -c 'cat > /etc/sysctl.d/99-rp-filter.conf << EOF
net.ipv4.conf.tun0.rp_filter = 0
net.ipv4.conf.enp6s18.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
EOF'`,
		// Apply immediately
		`sysctl -p /etc/sysctl.d/99-rp-filter.conf`,
	}
	for _, cmd := range cmds {
		out, err := s.Run(cmd)
		if err != nil {
			return fmt.Errorf("FixRPFilter [%s]: %v — %s", s.host, err, out)
		}
		fmt.Printf("[ssh:%s] %s\n", s.host, strings.TrimSpace(out))
	}
	return nil
}

// UpdateFNOSScript downloads and applies the latest fnos_fix script.
// NOTE: V5.0 (old FNOS) is explicitly excluded — the fix script breaks on it.
//
// Target: FNOS (Debian-based NAS OS) >= V6.0.
func (s *SSHClient) UpdateFNOSScript() error {
	cmds := []string{
		// Guard: abort on FNOS V5.0
		`bash -c 'v=$(cat /etc/fnos-release 2>/dev/null | grep VERSION_ID | cut -d= -f2 | tr -d "\""); if [[ "$v" == 5.* ]]; then echo "SKIP: fnos_fix incompatible with V5.0" ; exit 1; fi'`,
		// Download latest fix script
		`curl -fsSL https://raw.githubusercontent.com/vesaa/opentalon/main/scripts/fnos_fix.sh -o /tmp/fnos_fix.sh`,
		`chmod +x /tmp/fnos_fix.sh`,
		`bash /tmp/fnos_fix.sh`,
	}
	for _, cmd := range cmds {
		out, err := s.Run(cmd)
		msg := strings.TrimSpace(out)
		if strings.HasPrefix(msg, "SKIP:") {
			fmt.Printf("[ssh:%s] %s\n", s.host, msg)
			return nil
		}
		if err != nil {
			return fmt.Errorf("UpdateFNOSScript [%s]: %v — %s", s.host, err, msg)
		}
		if msg != "" {
			fmt.Printf("[ssh:%s] %s\n", s.host, msg)
		}
	}
	return nil
}

// singBoxConfig192_168_1_2 is the standard sing-box 1.12.16 configuration
// for the side-router at 192.168.1.2. Key rules:
//   - Uses "predefined" syntax in dns.hosts (not deprecated "streamSettings")
//   - sing-box version: 1.12.16
const singBoxConfig192_168_1_2 = `{
  "log": { "level": "info", "timestamp": true },
  "dns": {
    "servers": [
      { "tag": "remote", "address": "tls://8.8.8.8" },
      { "tag": "local",  "address": "223.5.5.5",  "detour": "direct" }
    ],
    "rules": [
      { "outbound": "any", "server": "local" },
      { "clash_mode": "direct", "server": "local" },
      { "rule_set": "geosite-cn", "server": "local" }
    ],
    "final": "remote",
    "hosts": {
      "predefined": [
        { "domain": "opentalon.internal", "ip": ["192.168.1.1"] }
      ]
    }
  },
  "inbounds": [
    {
      "type": "tun",
      "tag":  "tun-in",
      "inet4_address": "198.18.0.1/15",
      "auto_route": true,
      "strict_route": true,
      "stack": "system"
    }
  ],
  "outbounds": [
    { "type": "selector", "tag": "proxy", "outbounds": ["auto", "direct"] },
    { "type": "urltest",  "tag": "auto",  "outbounds": [] },
    { "type": "direct",   "tag": "direct" },
    { "type": "block",    "tag": "block"  },
    { "type": "dns",      "tag": "dns-out" }
  ],
  "route": {
    "rules": [
      { "protocol": "dns",    "outbound": "dns-out" },
      { "clash_mode": "direct", "outbound": "direct" },
      { "clash_mode": "global", "outbound": "proxy"  },
      { "rule_set": "geosite-cn", "outbound": "direct" },
      { "rule_set": "geoip-cn",   "outbound": "direct" }
    ],
    "rule_set": [
      {
        "tag": "geosite-cn", "type": "remote", "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geoip-cn", "type": "remote", "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
        "download_detour": "direct"
      }
    ],
    "final": "proxy"
  },
  "experimental": {
    "clash_api": { "external_controller": "127.0.0.1:9090" }
  }
}`

// PushSingBoxConfig pushes the standard sing-box 1.12.16 configuration to
// the side-router at 192.168.1.2, then restarts the sing-box service.
//
// Requirements on target:
//   - sing-box 1.12.16 installed at /usr/local/bin/sing-box
//   - systemd service named "sing-box"
//
// IMPORTANT: Config uses "hosts.predefined" syntax (1.12.x+).
// Legacy "streamSettings" is NOT used — it was removed in 1.11.
func (s *SSHClient) PushSingBoxConfig() error {
	// Write config to a temp file then move atomically
	escapedConf := strings.ReplaceAll(singBoxConfig192_168_1_2, "'", "'\"'\"'")
	cmds := []string{
		fmt.Sprintf(`bash -c 'echo '"'"'%s'"'"' > /tmp/sing-box.json'`, escapedConf),
		`mkdir -p /etc/sing-box`,
		`mv /tmp/sing-box.json /etc/sing-box/config.json`,
		// Validate config before restart
		`/usr/local/bin/sing-box check -c /etc/sing-box/config.json`,
		`systemctl restart sing-box`,
		`systemctl is-active sing-box`,
	}
	for _, cmd := range cmds {
		out, err := s.Run(cmd)
		if err != nil {
			return fmt.Errorf("PushSingBoxConfig [%s] cmd=%q: %v — %s", s.host, cmd, err, out)
		}
		if out := strings.TrimSpace(out); out != "" {
			fmt.Printf("[ssh:%s] %s\n", s.host, out)
		}
	}
	return nil
}
