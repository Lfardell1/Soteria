package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is the top-level Soteria configuration.
type Config struct {
	Filesystem FilesystemConfig `json:"filesystem"`
	Monitoring MonitoringConfig `json:"monitoring"`
	VPN        VPNConfig        `json:"vpn"`
	Tor        TorConfig        `json:"tor"`
	DNSCrypt   DNSCryptConfig   `json:"dnscrypt"`
	Proxychains ProxychainsConfig `json:"proxychains"`
	Network    NetworkConfig    `json:"network"`
}

type FilesystemConfig struct {
	TmpfsSize     string   `json:"tmpfs_size"`
	MountPoint    string   `json:"mount_point"`
	ToolsDir      string   `json:"tools_dir"`
	PopulatePaths []string `json:"populate_paths"`
}

type MonitoringConfig struct {
	Processes           []string `json:"processes"`
	TmpfsFreeSpaceMin   string   `json:"tmpfs_free_space_min"`
	PollIntervalSeconds int      `json:"poll_interval_seconds"`
}

type VPNConfig struct {
	Enabled    bool   `json:"enabled"`
	ConfigFile string `json:"config_file"`
	Interface  string `json:"interface"`
}

type TorConfig struct {
	Enabled    bool   `json:"enabled"`
	SocksPort  int    `json:"socks_port"`
	ConfigFile string `json:"config_file"`
}

type DNSCryptConfig struct {
	Enabled       bool   `json:"enabled"`
	ConfigFile    string `json:"config_file"`
	ListenAddress string `json:"listen_address"`
}

type ProxychainsConfig struct {
	Enabled    bool   `json:"enabled"`
	ConfigFile string `json:"config_file"`
}

type NetworkConfig struct {
	CheckConnectivity bool   `json:"check_connectivity"`
	Gateway           string `json:"gateway"`
	KillSwitch        bool   `json:"kill_switch"`
}

// Default returns a sensible default configuration matching the README.
func Default() Config {
	return Config{
		Filesystem: FilesystemConfig{
			TmpfsSize:     "2G",
			MountPoint:    "/mnt/secure",
			ToolsDir:      "/usr/local/tools",
			PopulatePaths: []string{"/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib"},
		},
		Monitoring: MonitoringConfig{
			Processes:           []string{"openvpn", "tor"},
			TmpfsFreeSpaceMin:   "100M",
			PollIntervalSeconds: 2,
		},
		VPN: VPNConfig{
			Enabled:    false,
			ConfigFile: "/etc/openvpn/client.conf",
			Interface:  "tun0",
		},
		Tor: TorConfig{
			Enabled:   false,
			SocksPort: 9050,
		},
		DNSCrypt: DNSCryptConfig{
			Enabled:       false,
			ConfigFile:    "/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
			ListenAddress: "127.0.0.1:53",
		},
		Proxychains: ProxychainsConfig{
			Enabled:    false,
			ConfigFile: "/etc/proxychains4.conf",
		},
		Network: NetworkConfig{
			CheckConnectivity: true,
			Gateway:           "1.1.1.1",
			KillSwitch:        true,
		},
	}
}

// Load reads and validates a JSON configuration file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks required fields and feature-dependent paths.
func (c Config) Validate() error {
	if c.Filesystem.TmpfsSize == "" {
		return fmt.Errorf("filesystem.tmpfs_size is required")
	}
	if _, err := ParseSize(c.Filesystem.TmpfsSize); err != nil {
		return fmt.Errorf("filesystem.tmpfs_size: %w", err)
	}
	if c.Filesystem.MountPoint == "" {
		return fmt.Errorf("filesystem.mount_point is required")
	}
	if !filepath.IsAbs(c.Filesystem.MountPoint) {
		return fmt.Errorf("filesystem.mount_point must be absolute")
	}
	if _, err := ParseSize(c.Monitoring.TmpfsFreeSpaceMin); err != nil {
		return fmt.Errorf("monitoring.tmpfs_free_space_min: %w", err)
	}
	if c.Monitoring.PollIntervalSeconds <= 0 {
		return fmt.Errorf("monitoring.poll_interval_seconds must be > 0")
	}

	if c.VPN.Enabled {
		if c.VPN.ConfigFile == "" {
			return fmt.Errorf("vpn.config_file is required when vpn.enabled")
		}
		if c.VPN.Interface == "" {
			return fmt.Errorf("vpn.interface is required when vpn.enabled")
		}
		if err := requireFile(c.VPN.ConfigFile, "vpn.config_file"); err != nil {
			return err
		}
	}

	if c.Tor.Enabled {
		if c.Tor.SocksPort <= 0 || c.Tor.SocksPort > 65535 {
			return fmt.Errorf("tor.socks_port must be a valid TCP port")
		}
		if c.Tor.ConfigFile != "" {
			if err := requireFile(c.Tor.ConfigFile, "tor.config_file"); err != nil {
				return err
			}
		}
	}

	if c.DNSCrypt.Enabled {
		if c.DNSCrypt.ConfigFile == "" {
			return fmt.Errorf("dnscrypt.config_file is required when dnscrypt.enabled")
		}
		if err := requireFile(c.DNSCrypt.ConfigFile, "dnscrypt.config_file"); err != nil {
			return err
		}
	}

	if c.Proxychains.Enabled {
		if c.Proxychains.ConfigFile == "" {
			return fmt.Errorf("proxychains.config_file is required when proxychains.enabled")
		}
		if err := requireFile(c.Proxychains.ConfigFile, "proxychains.config_file"); err != nil {
			return err
		}
	}

	if c.Network.KillSwitch && !c.VPN.Enabled && !c.Tor.Enabled {
		return fmt.Errorf("network.kill_switch requires vpn.enabled and/or tor.enabled")
	}

	return nil
}

func requireFile(path, field string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s must be a file", field)
	}
	return nil
}

// ParseSize converts strings like "2G", "100M", "512K", "1024" into bytes.
func ParseSize(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}

	multiplier := uint64(1)
	upper := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(upper, "G"):
		multiplier = 1 << 30
		s = s[:len(s)-1]
	case strings.HasSuffix(upper, "M"):
		multiplier = 1 << 20
		s = s[:len(s)-1]
	case strings.HasSuffix(upper, "K"):
		multiplier = 1 << 10
		s = s[:len(s)-1]
	case strings.HasSuffix(upper, "B"):
		s = s[:len(s)-1]
	}

	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n * multiplier, nil
}

// FormatSize renders a human-readable size string.
func FormatSize(bytes uint64) string {
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(bytes)/float64(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
