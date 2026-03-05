// OpenTalon — Cross-platform device management & topology monitoring platform.
// Author: vesaa | License: MIT | https://github.com/vesaa/opentalon
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/vesaa/opentalon/internal/agent"
	"github.com/vesaa/opentalon/internal/config"
	"github.com/vesaa/opentalon/internal/scanner"
	"github.com/vesaa/opentalon/internal/server"
)

const asciiLogo = `
  ██████╗ ██████╗ ███████╗███╗   ██╗████████╗ █████╗ ██╗      ██████╗ ███╗   ██╗
 ██╔═══██╗██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██║     ██╔═══██╗████╗  ██║
 ██║   ██║██████╔╝█████╗  ██╔██╗ ██║   ██║   ███████║██║     ██║   ██║██╔██╗ ██║
 ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██║     ██║   ██║██║╚██╗██║
 ╚██████╔╝██║     ███████╗██║ ╚████║   ██║   ██║  ██║███████╗╚██████╔╝██║ ╚████║
  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
`

const version = "v0.1.0"

func printBanner(mode string) {
	fmt.Print(asciiLogo)
	fmt.Printf("  ► OpenTalon %s  |  Author: vesaa  |  Mode: %s\n\n", version, mode)
}

func main() {
	root := &cobra.Command{
		Use:   "opentalon",
		Short: "OpenTalon — cross-platform device management & topology platform",
		Long: `OpenTalon is a single-binary C/S platform for managing heterogeneous
network devices: Windows, Alpine, Debian/FNOS, PVE, RockyLinux, routers and more.`,
		SilenceUsage: true,
	}

	// ── server subcommand ─────────────────────────────────────────────────────
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Start the OpenTalon management server (dual-port: 6677 control + 1616 data)",
		RunE: func(cmd *cobra.Command, args []string) error {
			printBanner("SERVER")

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// CLI flag --discovery=false overrides config.
			if disco, _ := cmd.Flags().GetBool("discovery"); !disco {
				cfg.DiscoveryEnabled = false
			}

			if err := server.InitDB(cfg); err != nil {
				return fmt.Errorf("initializing database: %w", err)
			}

			// Inject security settings into server package globals.
			server.SetJWTSecret(cfg.JWTSecret)
			server.SetAgentToken(cfg.AgentToken)
			server.SetAdminCredentials(cfg.AdminUser, cfg.AdminPass)
			server.SetDiscoveryEnabled(cfg.DiscoveryEnabled)

			gin.SetMode(gin.ReleaseMode)
			corsMiddleware := func(c *gin.Context) {
				c.Header("Access-Control-Allow-Origin", "*")
				c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
				c.Header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				if c.Request.Method == "OPTIONS" {
					c.AbortWithStatus(204)
					return
				}
				c.Next()
			}

			// ── Control-plane engine (6677) ────────────────────────────────────
			ctrlEngine := gin.New()
			ctrlEngine.Use(gin.Recovery(), corsMiddleware)
			server.RegisterControlRoutes(ctrlEngine)
			server.RegisterStaticFiles(ctrlEngine)

			// ── Data-plane engine (1616) ───────────────────────────────────────
			dataEngine := gin.New()
			dataEngine.Use(gin.Recovery())
			server.RegisterDataRoutes(dataEngine)

			ctrlAddr := fmt.Sprintf("%s:%d", cfg.ServerHost, cfg.ControlPort)
			dataAddr := fmt.Sprintf("%s:%d", cfg.ServerHost, cfg.DataPort)

			fmt.Printf("  ✓ Control plane (Web UI + JWT API) → http://%s\n", ctrlAddr)
			fmt.Printf("  ✓ Data    plane (Agent reports)    → http://%s\n", dataAddr)
			fmt.Printf("  ✓ Default login: %s / %s\n", cfg.AdminUser, cfg.AdminPass)
			fmt.Printf("  ✓ Agent token:   %s\n\n", cfg.AgentToken)

			// Run both servers concurrently; shut down gracefully on SIGINT/SIGTERM.
			ctrlSrv := &http.Server{Addr: ctrlAddr, Handler: ctrlEngine}
			dataSrv := &http.Server{Addr: dataAddr, Handler: dataEngine}

			errCh := make(chan error, 2)
			go func() { errCh <- ctrlSrv.ListenAndServe() }()
			go func() { errCh <- dataSrv.ListenAndServe() }()

			// Server-side ARP scanner: runs on startup and whenever triggered via /api/scan/trigger.
			if cfg.DiscoveryEnabled {
				go func() {
					// Initial scan after a short warm-up delay.
					time.Sleep(5 * time.Second)
					runServerScan()
					// Periodic scan every 5 minutes + on-demand trigger check.
					tick := time.NewTicker(5 * time.Minute)
					checkTick := time.NewTicker(2 * time.Second)
					defer tick.Stop()
					defer checkTick.Stop()
					for {
						select {
						case <-tick.C:
							runServerScan()
						case <-checkTick.C:
							if server.TakeServerScan() {
								runServerScan()
							}
						}
					}
				}()
			}

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, os.Interrupt) // os.Interrupt = SIGINT; works on all platforms

			select {
			case err := <-errCh:
				return err
			case <-quit:
				fmt.Println("\n  → Shutting down gracefully…")
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = ctrlSrv.Shutdown(ctx)
				_ = dataSrv.Shutdown(ctx)
				return nil
			}
		},
	}

	// ── agent subcommand ──────────────────────────────────────────────────────
	agentCmd := &cobra.Command{
		Use:   "agent",
		Short: "Start the OpenTalon agent on this device",
		RunE: func(cmd *cobra.Command, args []string) error {
			printBanner("AGENT")

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// CLI flags override config values.
			if join, _ := cmd.Flags().GetString("join"); join != "" {
				if !containsPort(join) {
					join = fmt.Sprintf("%s:%d", join, cfg.DataPort)
				}
				cfg.AgentJoinAddr = join
			}
			if token, _ := cmd.Flags().GetString("token"); token != "" {
				cfg.AgentOutboundToken = token
			}
			if group, _ := cmd.Flags().GetString("group"); group != "" {
				cfg.AgentGroup = group
			}
			if parent, _ := cmd.Flags().GetUint("parent"); parent != 0 {
				cfg.AgentParentID = parent
			}
			if debugHTTP, _ := cmd.Flags().GetBool("debug-http"); debugHTTP {
				cfg.AgentDebugHTTP = true
			}

			fmt.Printf("  ✓ Joining server: %s\n", cfg.AgentJoinAddr)
			fmt.Printf("  ✓ Token:          %s\n", cfg.AgentOutboundToken)
			fmt.Printf("  ✓ Report interval: %ds\n\n", cfg.AgentInterval)
			return agent.Run(cfg)
		},
	}
	agentCmd.Flags().String("join", "", "Data-plane address, e.g. 192.168.1.1 or 192.168.1.1:1616")
	agentCmd.Flags().String("token", "", "Pre-shared token for server authentication (overrides config)")
	agentCmd.Flags().String("group", "", "Device group name")
	agentCmd.Flags().Uint("parent", 0, "Parent device ID (for PVE VM topology declaration)")
	agentCmd.Flags().Bool("debug-http", false, "Enable verbose HTTP logging for agent (requests & responses)")

	serverCmd.Flags().Bool("discovery", true, "Enable LAN ARP device discovery (default: true)")

	// ── version subcommand ────────────────────────────────────────────────────
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print OpenTalon version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("OpenTalon %s  |  Author: vesaa\n", version)
		},
	}

	root.AddCommand(serverCmd, agentCmd, versionCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// containsPort checks whether addr already has a port suffix.
func containsPort(addr string) bool {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return true
		}
		if addr[i] == '/' {
			break
		}
	}
	return false
}

// runServerScan performs an ARP scan of all local subnets from the server's
// perspective and stores results in the DiscoveredDevices table.
func runServerScan() {
	// Only scan when there are no online clients; otherwise the elected agent scans.
	if server.HasOnlineClients() {
		// Clients came online between trigger and now — clear the placeholder state.
		server.SetScanDone()
		return
	}
	serverIP := localServerIP()
	// Overwrite placeholder "server" state with real IP; auto-timeout 120s safety net.
	server.SetScanActive(serverIP, nil, 120)

	results, err := scanner.ScanLocalSubnets("")
	if err != nil {
		server.SetScanDoneWithCount(0)
		return
	}
	var managedIPs []string
	server.DB.Model(nil).Table("devices").Where("deleted_at IS NULL").Pluck("ip", &managedIPs)
	managed := make(map[string]struct{}, len(managedIPs))
	for _, ip := range managedIPs {
		managed[ip] = struct{}{}
	}
	count := 0
	for _, d := range results {
		if _, ok := managed[d.IP]; ok {
			continue
		}
		server.UpsertDiscovered(d.IP, d.MAC, d.Hostname, d.Vendor, d.OSHint, serverIP)
		count++
	}
	server.SetScanDoneWithCount(count)
}

// localServerIP returns the primary local private IP of the server process.
func localServerIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "server"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
