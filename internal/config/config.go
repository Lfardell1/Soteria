package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxConfigBytes = 1 << 20
	migrationHint  = "migrate to version 1 using config/config.example.json; replace legacy OpenVPN/Tor settings with offline mode or an administrator-provisioned WireGuard profile; legacy kill-switch toggles are not supported"
)

// Config contains caller-selected limits and networking, not runtime paths or authority.
type Config struct {
	Version   int            `json:"version"`
	Resources ResourceConfig `json:"resources"`
	Network   NetworkConfig  `json:"network"`
	Transfers TransferConfig `json:"transfers"`
}

type ResourceConfig struct {
	MemoryMax     string `json:"memory_max"`
	WorkspaceSize string `json:"workspace_size"`
	TasksMax      uint64 `json:"tasks_max"`
}

type NetworkConfig struct {
	Mode    string `json:"mode"`
	Profile string `json:"profile,omitempty"`
}

type TransferConfig struct {
	MaxBytes string `json:"max_bytes"`
	MaxFiles uint64 `json:"max_files"`
}

// Default returns valid, offline version 1 settings.
func Default() Config {
	return Config{
		Version: 1,
		Resources: ResourceConfig{
			MemoryMax:     "1G",
			WorkspaceSize: "512M",
			TasksMax:      256,
		},
		Network: NetworkConfig{Mode: "offline"},
		Transfers: TransferConfig{
			MaxBytes: "256M",
			MaxFiles: 10000,
		},
	}
}

// Parse reads at most 1 MiB of strict JSON. Version is required; other omitted
// fields retain their defaults. No legacy configuration is translated.
func Parse(r io.Reader) (Config, error) {
	if r == nil {
		return Config{}, fmt.Errorf("read config: reader is required")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return Config{}, fmt.Errorf("config exceeds the 1 MiB input limit")
	}
	if !utf8.Valid(data) {
		return Config{}, fmt.Errorf("config must be valid UTF-8 JSON")
	}

	// encoding/json alone accepts duplicates, case-insensitive keys, and nulls.
	// Check the exact schema before decoding the values into their Go types.
	schema := objectSchema{
		"version": nil,
		"resources": {
			"memory_max":     nil,
			"workspace_size": nil,
			"tasks_max":      nil,
		},
		"network": {
			"mode":    nil,
			"profile": nil,
		},
		"transfers": {
			"max_bytes": nil,
			"max_files": nil,
		},
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := checkObject(decoder, "", schema); err != nil {
		return Config{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Config{}, fmt.Errorf("config must contain exactly one JSON object with no trailing data")
	}

	cfg := Default()
	cfg.Version = 0 // An omitted version must not inherit the default version.
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

type objectSchema map[string]objectSchema

func checkObject(decoder *json.Decoder, path string, schema objectSchema) error {
	start, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if start != json.Delim('{') {
		if path == "" {
			path = "config"
		}
		return fmt.Errorf("%s must be a JSON object, not null or another type", path)
	}
	seen := make(map[string]bool, len(schema))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("parse config: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("config object keys must be strings")
		}
		field := key
		if path != "" {
			field = path + "." + key
		}
		if seen[key] {
			return fmt.Errorf("duplicate config field %q", field)
		}
		seen[key] = true
		child, ok := schema[key]
		if !ok {
			switch field {
			case "filesystem", "monitoring", "vpn", "tor", "dnscrypt", "proxychains",
				"network.check_connectivity", "network.gateway", "network.kill_switch":
				return fmt.Errorf("legacy config field %q is not supported; %s", field, migrationHint)
			default:
				return fmt.Errorf("unknown config field %q", field)
			}
		}
		if child != nil {
			if err := checkObject(decoder, field, child); err != nil {
				return err
			}
			continue
		}
		value, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("parse config field %s: %w", field, err)
		}
		if value == nil {
			return fmt.Errorf("config field %s must not be null", field)
		}
		if _, ok := value.(json.Delim); ok {
			return fmt.Errorf("config field %s must be a scalar value", field)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	return nil
}

// Load reads only the selected clean absolute regular file. It is a frontend
// helper, not privileged configuration discovery or runtime authorization.
func Load(path string) (Config, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return Config{}, fmt.Errorf("config path must be a clean absolute file path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, fmt.Errorf("config path must name a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat opened config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, fmt.Errorf("config path must name a regular file")
	}
	cfg, err := Parse(file)
	if err != nil {
		return Config{}, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

// Validate checks policy without opening files or changing runtime state.
func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("config version must be explicitly set to 1; %s", migrationHint)
	}
	memory, err := ParseSize(c.Resources.MemoryMax)
	if err != nil {
		return fmt.Errorf("resources.memory_max: %w", err)
	}
	if memory < 128<<20 || memory > 64<<30 {
		return fmt.Errorf("resources.memory_max must be between 128M and 64G")
	}
	workspace, err := ParseSize(c.Resources.WorkspaceSize)
	if err != nil {
		return fmt.Errorf("resources.workspace_size: %w", err)
	}
	if workspace < 16<<20 || workspace > 32<<30 {
		return fmt.Errorf("resources.workspace_size must be between 16M and 32G")
	}
	if workspace >= memory {
		return fmt.Errorf("resources.workspace_size must be strictly below resources.memory_max")
	}
	if c.Resources.TasksMax < 32 || c.Resources.TasksMax > 4096 {
		return fmt.Errorf("resources.tasks_max must be between 32 and 4096")
	}
	transfer, err := ParseSize(c.Transfers.MaxBytes)
	if err != nil {
		return fmt.Errorf("transfers.max_bytes: %w", err)
	}
	if transfer > workspace {
		return fmt.Errorf("transfers.max_bytes must not exceed resources.workspace_size")
	}
	if c.Transfers.MaxFiles == 0 || c.Transfers.MaxFiles > 100000 {
		return fmt.Errorf("transfers.max_files must be between 1 and 100000")
	}
	switch c.Network.Mode {
	case "offline":
		if c.Network.Profile != "" {
			return fmt.Errorf("network.profile must be empty in offline mode")
		}
	case "wireguard":
		if err := ValidateProfileID(c.Network.Profile); err != nil {
			return fmt.Errorf("network.profile: %w", err)
		}
	default:
		return fmt.Errorf("network.mode must be offline or wireguard")
	}
	return nil
}

// ValidateProfileID accepts 1..48 ASCII characters: lowercase alphanumeric
// first, then lowercase alphanumeric, underscore, or hyphen. IDs are not paths.
func ValidateProfileID(id string) error {
	if len(id) == 0 || len(id) > 48 {
		return fmt.Errorf("profile ID must contain between 1 and 48 characters")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '_' || c == '-') {
			continue
		}
		return fmt.Errorf("profile ID must start with lowercase alphanumeric and contain only lowercase alphanumeric, underscore, or hyphen")
	}
	return nil
}

// ParseSize converts a positive decimal integer with an optional B, K, M, or G
// suffix to bytes. K/M/G are binary units; suffixes are case-insensitive.
func ParseSize(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("size must not be empty")
	}
	multiplier := uint64(1)
	switch s[len(s)-1] {
	case 'g', 'G':
		multiplier = 1 << 30
		s = s[:len(s)-1]
	case 'm', 'M':
		multiplier = 1 << 20
		s = s[:len(s)-1]
	case 'k', 'K':
		multiplier = 1 << 10
		s = s[:len(s)-1]
	case 'b', 'B':
		s = s[:len(s)-1]
	}
	if s == "" {
		return 0, fmt.Errorf("size requires a positive decimal integer")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("size must be a positive decimal integer with an optional B, K, M, or G suffix")
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n > ^uint64(0)/multiplier {
		return 0, fmt.Errorf("size exceeds uint64 bytes")
	}
	if n == 0 {
		return 0, fmt.Errorf("size must be greater than zero")
	}
	return n * multiplier, nil
}

// FormatSize renders an exact size without floating-point rounding. It uses the
// largest K/M/G unit that divides the value exactly, or bytes otherwise.
func FormatSize(n uint64) string {
	if n != 0 {
		for _, unit := range []struct {
			bytes  uint64
			suffix string
		}{{1 << 30, "G"}, {1 << 20, "M"}, {1 << 10, "K"}} {
			if n%unit.bytes == 0 {
				return strconv.FormatUint(n/unit.bytes, 10) + unit.suffix
			}
		}
	}
	return strconv.FormatUint(n, 10) + "B"
}
