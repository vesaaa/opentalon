// Package config provides dynamic configuration management for OpenTalon.
// It uses Viper to load settings from files, environment variables, and CLI flags.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all runtime configuration for OpenTalon.
type Config struct {
	// ── Server ───────────────────────────────────────────────────────────────
	ServerHost string `mapstructure:"server_host"`
	// ControlPort (6677): Web UI + JWT-protected REST API
	ControlPort int `mapstructure:"control_port"`
	// DataPort (1616): Agent heartbeat / registration — Bearer token protected
	DataPort   int    `mapstructure:"data_port"`
	DBPath     string `mapstructure:"db_path"`
	DBDriver   string `mapstructure:"db_driver"` // "sqlite" or "mysql"
	DBDSN      string `mapstructure:"db_dsn"`    // used when db_driver = mysql

	// ── Security ──────────────────────────────────────────────────────────────
	// JWTSecret: HS256 signing key for control-plane Web tokens.
	// Change this in production — default is a random-looking placeholder.
	JWTSecret string `mapstructure:"jwt_secret"`
	// AgentToken: pre-shared key for data-plane agent requests.
	// Format on wire: "Authorization: Bearer <agent_token>"
	AgentToken string `mapstructure:"agent_token"`
	// AdminUser / AdminPass: hard-coded credentials for /api/login.
	// TODO: replace with DB-backed user table in v0.2.
	AdminUser string `mapstructure:"admin_user"`
	AdminPass string `mapstructure:"admin_pass"`

	// ── Network topology hints ────────────────────────────────────────────────
	MainRouterIP string `mapstructure:"main_router_ip"`
	SideRouterIP string `mapstructure:"side_router_ip"`

	// ── Agent ────────────────────────────────────────────────────────────────
	AgentJoinAddr    string `mapstructure:"agent_join_addr"`
	AgentInterval    int    `mapstructure:"agent_interval_seconds"`
	AgentParentID    uint   `mapstructure:"agent_parent_id"`
	AgentGroup       string `mapstructure:"agent_group"`
	AgentNetworkMode string `mapstructure:"agent_network_mode"` // Bridged | NAT
	// AgentToken for outbound requests (overridden by --token CLI flag)
	AgentOutboundToken string `mapstructure:"agent_outbound_token"`

	// ── SSH defaults ──────────────────────────────────────────────────────────
	SSHUser    string `mapstructure:"ssh_user"`
	SSHKeyPath string `mapstructure:"ssh_key_path"`
}

// Load reads config from file (./config.yaml or ~/.opentalon/config.yaml)
// and falls back to smart defaults. Environment variables with prefix TALON_
// override file values.
func Load() (*Config, error) {
	v := viper.New()

	// --- Smart Defaults ---
	v.SetDefault("server_host", "0.0.0.0")
	v.SetDefault("control_port", 6677)  // Web UI + JWT API
	v.SetDefault("data_port", 1616)     // Agent data plane
	v.SetDefault("db_path", "opentalon.db")
	v.SetDefault("db_driver", "sqlite")
	v.SetDefault("db_dsn", "")

	// Security defaults — MUST be overridden in production via config.yaml or env vars.
	v.SetDefault("jwt_secret", "OtLn$Xq7@wP2!mZ9#rK6^dV4&eA1*fY") // random placeholder
	v.SetDefault("agent_token", "opentalon-secret-key-123")
	v.SetDefault("admin_user", "admin")
	v.SetDefault("admin_pass", "admin")

	v.SetDefault("main_router_ip", "192.168.1.1")
	v.SetDefault("side_router_ip", "192.168.1.2")

	v.SetDefault("agent_join_addr", "127.0.0.1:1616")
	v.SetDefault("agent_interval_seconds", 30)
	v.SetDefault("agent_parent_id", 0)
	v.SetDefault("agent_group", "default")
	v.SetDefault("agent_network_mode", "Bridged")
	v.SetDefault("agent_outbound_token", "opentalon-secret-key-123")

	v.SetDefault("ssh_user", "root")
	v.SetDefault("ssh_key_path", "~/.ssh/id_rsa")

	// --- Config file ---
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.opentalon")
	if err := v.ReadInConfig(); err != nil {
		// config file is optional; ignore "not found" errors
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	// --- Environment Variables ---
	v.SetEnvPrefix("TALON")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}
	return &cfg, nil
}
