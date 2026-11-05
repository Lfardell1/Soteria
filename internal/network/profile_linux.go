//go:build linux

package network

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const ProfileDirectory = "/etc/soteria/profiles"

const maxProfileBytes = 16 * 1024

// Profile is one validated IPv4 full-tunnel peer. The private credential is
// deliberately unexported and is never included in formatting or JSON output.
type Profile struct {
	Name             string
	Address          netip.Prefix
	DNS              []netip.Addr
	Endpoint         netip.AddrPort
	PublicKey        wgtypes.Key
	MTU              int
	KeepaliveSeconds int

	privateKey wgtypes.Key
}

func (p Profile) String() string {
	return fmt.Sprintf("WireGuard profile %q (private key redacted)", p.Name)
}
func (p Profile) GoString() string { return p.String() }

// ResolverConfig is content for the private workload's resolver file, not a
// request to change the worker's or host's /etc/resolv.conf.
func (p Profile) ResolverConfig() string {
	if err := p.validateMetadata(); err != nil {
		return ""
	}
	var content strings.Builder
	for _, server := range p.DNS {
		fmt.Fprintf(&content, "nameserver %s\n", server)
	}
	content.WriteString("options timeout:2 attempts:1\n")
	return content.String()
}

func validProfileName(name string) bool {
	if len(name) < 1 || len(name) > 48 {
		return false
	}
	for i, c := range []byte(name) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if i == 0 || c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// LoadProfile uses only a fixed, administrator-owned directory. It must run
// inside the service resource boundary; callers must not send keys over IPC.
func LoadProfile(name string) (Profile, error) {
	if !validProfileName(name) {
		return Profile{}, errors.New("invalid profile name")
	}
	dir, err := openTrustedDirectory(ProfileDirectory, false)
	if err != nil {
		return Profile{}, fmt.Errorf("open profile directory: %w", err)
	}
	defer dir.Close()
	metadata, err := openTrustedRegularAt(dir, name+".json", maxProfileBytes, false)
	if err != nil {
		return Profile{}, fmt.Errorf("open profile metadata: %w", err)
	}
	data, readErr := readBounded(metadata, maxProfileBytes)
	closeErr := metadata.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return Profile{}, fmt.Errorf("read profile metadata: %w", err)
	}
	profile, err := parseProfile(name, data)
	if err != nil {
		return Profile{}, err
	}
	keyFile, err := openTrustedRegularAt(dir, name+".key", 45, true)
	if err != nil {
		return Profile{}, fmt.Errorf("open private-key credential: %w", err)
	}
	keyData, readErr := readBounded(keyFile, 45)
	closeErr = keyFile.Close()
	defer clear(keyData)
	if err := errors.Join(readErr, closeErr); err != nil {
		return Profile{}, errors.New("read private-key credential failed")
	}
	profile.privateKey, err = parsePrivateKey(keyData)
	if err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func parseProfile(name string, data []byte) (Profile, error) {
	if !validProfileName(name) || len(data) > maxProfileBytes {
		return Profile{}, errors.New("invalid profile name or metadata size")
	}
	var raw struct {
		Version          int
		Address          string
		DNS              []string
		Endpoint         string
		PublicKey        string
		PrivateKeyFile   string
		AllowedIPs       []string
		MTU              int
		KeepaliveSeconds int
	}
	if err := decodeStrictObject(data, map[string]any{
		"version": &raw.Version, "address": &raw.Address, "dns": &raw.DNS,
		"endpoint": &raw.Endpoint, "public_key": &raw.PublicKey,
		"private_key_file": &raw.PrivateKeyFile, "allowed_ips": &raw.AllowedIPs,
		"mtu": &raw.MTU, "keepalive_seconds": &raw.KeepaliveSeconds,
	}); err != nil {
		return Profile{}, fmt.Errorf("profile metadata: %w", err)
	}
	if raw.Version != 1 {
		return Profile{}, errors.New("unsupported profile version; expected version 1")
	}
	if raw.PrivateKeyFile != name+".key" {
		return Profile{}, errors.New("private_key_file must be the selected profile name followed by .key")
	}
	if len(raw.AllowedIPs) != 1 || raw.AllowedIPs[0] != "0.0.0.0/0" {
		return Profile{}, errors.New("allowed_ips must contain only 0.0.0.0/0")
	}
	address, err := netip.ParsePrefix(raw.Address)
	if err != nil {
		return Profile{}, errors.New("address must be a literal IPv4 prefix")
	}
	endpoint, err := netip.ParseAddrPort(raw.Endpoint)
	if err != nil {
		return Profile{}, errors.New("endpoint must be a literal IPv4 address and UDP port")
	}
	key, err := wgtypes.ParseKey(raw.PublicKey)
	if err != nil || key.String() != raw.PublicKey {
		return Profile{}, errors.New("public_key must be a canonical base64 WireGuard key")
	}
	profile := Profile{Name: name, Address: address, Endpoint: endpoint, PublicKey: key, MTU: raw.MTU, KeepaliveSeconds: raw.KeepaliveSeconds}
	for _, value := range raw.DNS {
		server, err := netip.ParseAddr(value)
		if err != nil {
			return Profile{}, errors.New("dns must contain only literal IPv4 addresses")
		}
		profile.DNS = append(profile.DNS, server)
	}
	if err := profile.validateMetadata(); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func (p Profile) validateMetadata() error {
	if !validProfileName(p.Name) {
		return errors.New("invalid profile name")
	}
	if !p.Address.IsValid() || !usableIPv4(p.Address.Addr()) || p.Address.Bits() < 1 {
		return errors.New("address must be a usable IPv4 prefix with length 1..32")
	}
	if !p.Endpoint.IsValid() || !usableIPv4(p.Endpoint.Addr()) || p.Endpoint.Port() == 0 {
		return errors.New("endpoint must be a usable literal IPv4 address with port 1..65535")
	}
	if len(p.DNS) < 1 || len(p.DNS) > 3 {
		return errors.New("dns must contain one to three literal IPv4 resolvers")
	}
	seen := make(map[netip.Addr]bool, len(p.DNS))
	for _, server := range p.DNS {
		if !usableIPv4(server) || server == p.Address.Addr() || seen[server] {
			return errors.New("dns must contain distinct, usable IPv4 resolvers, not the tunnel's own address")
		}
		seen[server] = true
	}
	if p.PublicKey == (wgtypes.Key{}) {
		return errors.New("public_key must not be zero")
	}
	if p.MTU < 1280 || p.MTU > 1420 {
		return errors.New("mtu must be within 1280..1420")
	}
	if p.KeepaliveSeconds < 0 || p.KeepaliveSeconds > 120 {
		return errors.New("keepalive_seconds must be within 0..120")
	}
	return nil
}

func usableIPv4(address netip.Addr) bool {
	return address.Is4() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() &&
		!address.IsLinkLocalUnicast() && address != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func parsePrivateKey(data []byte) (wgtypes.Key, error) {
	if len(data) == 45 && data[44] == '\n' {
		data = data[:44]
	}
	if len(data) != 44 {
		return wgtypes.Key{}, errors.New("invalid private-key credential")
	}
	key, err := wgtypes.ParseKey(string(data))
	if err != nil || key == (wgtypes.Key{}) || key.String() != string(data) {
		return wgtypes.Key{}, errors.New("invalid private-key credential")
	}
	return key, nil
}
