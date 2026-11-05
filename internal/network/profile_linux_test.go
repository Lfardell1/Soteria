//go:build linux

package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testKey(value byte) wgtypes.Key {
	var key wgtypes.Key
	for i := range key {
		key[i] = value
	}
	return key
}

func profileJSON(name string) []byte {
	return []byte(fmt.Sprintf(`{"version":1,"address":"10.8.0.7/32","dns":["10.8.0.1","10.8.0.2"],"endpoint":"198.51.100.20:51820","public_key":%q,"private_key_file":%q,"allowed_ips":["0.0.0.0/0"],"mtu":1420,"keepalive_seconds":25}`, testKey(1).String(), name+".key"))
}

func testProfile(t *testing.T) Profile {
	t.Helper()
	profile, err := parseProfile("office", profileJSON("office"))
	if err != nil {
		t.Fatal(err)
	}
	profile.privateKey = testKey(2)
	return profile
}

func TestProfileValid(t *testing.T) {
	for _, name := range []string{"a", "office-vpn_2", strings.Repeat("a", 48)} {
		profile, err := parseProfile(name, profileJSON(name))
		if err != nil {
			t.Fatalf("valid name %q: %v", name, err)
		}
		if profile.Name != name || profile.Address.String() != "10.8.0.7/32" || profile.Endpoint.String() != "198.51.100.20:51820" {
			t.Fatal("profile did not preserve public metadata")
		}
		if got := profile.ResolverConfig(); got != "nameserver 10.8.0.1\nnameserver 10.8.0.2\noptions timeout:2 attempts:1\n" {
			t.Fatalf("unexpected private resolver content: %q", got)
		}
	}
}

func TestProfileRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"", strings.Repeat("a", 49), "../office", "office.json", "Office", "_office", "-office", "office/other", "office\x00", "office\n", "office ", "caf\u00e9"} {
		if _, err := parseProfile(name, profileJSON(name)); err == nil {
			t.Errorf("accepted invalid profile name %q", name)
		}
	}
}

func TestProfileRejectsUnsupportedMetadata(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value any
	}{
		{"old version", "version", 0}, {"future version", "version", 2}, {"fractional version", "version", 1.5},
		{"IPv6 address", "address", "fd00::7/64"}, {"mapped address", "address", "::ffff:10.8.0.7/128"},
		{"address without prefix", "address", "10.8.0.7"}, {"address default prefix", "address", "10.8.0.7/0"},
		{"loopback address", "address", "127.0.0.1/8"}, {"unspecified address", "address", "0.0.0.0/32"},
		{"multicast address", "address", "224.0.0.1/32"}, {"link-local address", "address", "169.254.1.1/16"},
		{"hostname endpoint", "endpoint", "vpn.example:51820"}, {"IPv6 endpoint", "endpoint", "[2001:db8::1]:51820"},
		{"zero endpoint port", "endpoint", "198.51.100.20:0"}, {"oversized endpoint port", "endpoint", "198.51.100.20:65536"},
		{"loopback endpoint", "endpoint", "127.0.0.1:51820"}, {"endpoint without port", "endpoint", "198.51.100.20"},
		{"no DNS", "dns", []string{}}, {"too many DNS", "dns", []string{"10.8.0.1", "10.8.0.2", "10.8.0.3", "10.8.0.4"}},
		{"DNS hostname", "dns", []string{"resolver.example"}}, {"IPv6 DNS", "dns", []string{"fd00::1"}},
		{"duplicate DNS", "dns", []string{"10.8.0.1", "10.8.0.1"}}, {"own address DNS", "dns", []string{"10.8.0.7"}},
		{"loopback DNS", "dns", []string{"127.0.0.1"}}, {"broadcast DNS", "dns", []string{"255.255.255.255"}},
		{"zero public key", "public_key", (wgtypes.Key{}).String()}, {"bad public key", "public_key", "not a key"},
		{"key file traversal", "private_key_file", "../office.key"}, {"different key file", "private_key_file", "other.key"},
		{"absolute key file", "private_key_file", "/etc/office.key"}, {"embedded private key", "private_key", testKey(2).String()},
		{"no allowed IPs", "allowed_ips", []string{}}, {"split tunnel", "allowed_ips", []string{"10.0.0.0/8"}},
		{"extra allowed IP", "allowed_ips", []string{"0.0.0.0/0", "10.0.0.0/8"}}, {"IPv6 allowed IP", "allowed_ips", []string{"::/0"}},
		{"small MTU", "mtu", 1279}, {"large MTU", "mtu", 1421}, {"fractional MTU", "mtu", 1400.5},
		{"negative keepalive", "keepalive_seconds", -1}, {"large keepalive", "keepalive_seconds", 121},
		{"hook", "PostUp", "anything"}, {"routing table", "Table", 99}, {"save config", "SaveConfig", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(profileJSON("office"), &raw); err != nil {
				t.Fatal(err)
			}
			raw[tc.field] = tc.value
			data, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseProfile("office", data); err == nil {
				t.Fatal("accepted unsupported profile metadata")
			}
		})
	}
}

func TestProfileStrictJSON(t *testing.T) {
	valid := string(profileJSON("office"))
	cases := []string{
		"", "[]", "null", valid + "{}", valid + "null", valid + " trailing",
		strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"\u0076ersion":1`, 1),
		strings.Replace(valid, `"version":1`, `"Version":1`, 1),
		strings.Replace(valid, `"version":1,`, "", 1),
		strings.Replace(valid, `"keepalive_seconds":25`, `"keepalive_seconds":null`, 1),
		strings.Replace(valid, `"keepalive_seconds":25`, `"keepalive_seconds":"25"`, 1),
		strings.Replace(valid, `"dns":["10.8.0.1","10.8.0.2"]`, `"dns":null`, 1),
		valid + strings.Repeat(" ", maxProfileBytes),
	}
	for i, data := range cases {
		if _, err := parseProfile("office", []byte(data)); err == nil {
			t.Errorf("accepted invalid JSON case %d", i)
		}
	}
	if _, err := parseProfile("office", []byte(valid+" \n\t")); err != nil {
		t.Fatalf("rejected trailing whitespace: %v", err)
	}
}

func TestProfileBoundsAndRedaction(t *testing.T) {
	profile := testProfile(t)
	for _, mtu := range []int{1280, 1420} {
		for _, keepalive := range []int{0, 120} {
			profile.MTU, profile.KeepaliveSeconds = mtu, keepalive
			if err := profile.validateMetadata(); err != nil {
				t.Fatal(err)
			}
		}
	}
	secret := profile.privateKey.String()
	formatted := fmt.Sprintf("%v %+v %#v %s %q", profile, profile, profile, profile, profile)
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(formatted, secret) || bytes.Contains(encoded, []byte(secret)) || !strings.Contains(formatted, "redacted") {
		t.Fatal("profile formatting exposes a private key or fails to mark it redacted")
	}
	profile.DNS = nil
	if profile.ResolverConfig() != "" {
		t.Fatal("generated resolver content from invalid metadata")
	}
}

func TestPrivateKeyParser(t *testing.T) {
	key := testKey(2)
	for _, data := range []string{key.String(), key.String() + "\n"} {
		got, err := parsePrivateKey([]byte(data))
		if err != nil || got != key {
			t.Fatal("canonical private-key credential rejected")
		}
	}
	for _, data := range []string{"", "not a key", (wgtypes.Key{}).String(), key.String() + "\r\n", key.String() + "\n\n", " " + key.String(), key.String()[:43], strings.Repeat("x", 46)} {
		_, err := parsePrivateKey([]byte(data))
		if err == nil {
			t.Error("invalid private-key credential accepted")
		} else if strings.Contains(err.Error(), data) && len(data) > 1 {
			t.Fatal("private-key parser echoed credential input")
		}
	}
}

func TestTrustedFileMetadata(t *testing.T) {
	base := unix.Stat_t{Mode: unix.S_IFREG | 0o644, Uid: 0, Nlink: 1, Size: 512}
	if err := checkRegularStat(base, maxProfileBytes, false); err != nil {
		t.Fatal(err)
	}
	if err := checkRegularStat(base, maxProfileBytes, true); err == nil {
		t.Fatal("accepted public permissions for a private key")
	}
	base.Mode = unix.S_IFREG | 0o600
	if err := checkRegularStat(base, maxProfileBytes, true); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*unix.Stat_t)
	}{
		{"untrusted owner", func(st *unix.Stat_t) { st.Uid = 1000 }},
		{"hard link", func(st *unix.Stat_t) { st.Nlink = 2 }},
		{"symlink", func(st *unix.Stat_t) { st.Mode = unix.S_IFLNK | 0o600 }},
		{"directory", func(st *unix.Stat_t) { st.Mode = unix.S_IFDIR | 0o600 }},
		{"group writable", func(st *unix.Stat_t) { st.Mode = unix.S_IFREG | 0o660 }},
		{"world writable", func(st *unix.Stat_t) { st.Mode = unix.S_IFREG | 0o606 }},
		{"special bits", func(st *unix.Stat_t) { st.Mode = unix.S_IFREG | 0o4600 }},
		{"unexpected mode", func(st *unix.Stat_t) { st.Mode = unix.S_IFREG | 0o640 }},
		{"empty", func(st *unix.Stat_t) { st.Size = 0 }},
		{"too large", func(st *unix.Stat_t) { st.Size = maxProfileBytes + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := base
			tc.edit(&st)
			if err := checkRegularStat(st, maxProfileBytes, false); err == nil {
				t.Fatal("accepted unsafe file metadata")
			}
		})
	}
}

func TestTrustedDirectoryMetadata(t *testing.T) {
	for _, mode := range []uint32{0o700, 0o755} {
		st := unix.Stat_t{Mode: unix.S_IFDIR | mode, Uid: 0}
		if err := checkDirectoryStat(st, false); err != nil {
			t.Fatal(err)
		}
		if err := checkDirectoryStat(st, true); (err == nil) != (mode == 0o700) {
			t.Fatal("runtime directory did not require exactly 0700")
		}
	}
	for _, st := range []unix.Stat_t{
		{Mode: unix.S_IFDIR | 0o755, Uid: 1000}, {Mode: unix.S_IFDIR | 0o770},
		{Mode: unix.S_IFDIR | 0o1777}, {Mode: unix.S_IFREG | 0o700}, {Mode: unix.S_IFLNK | 0o700},
	} {
		if err := checkDirectoryStat(st, false); err == nil {
			t.Fatal("accepted unsafe parent directory metadata")
		}
	}
}

func TestProfileLeafOpenRejectsSymlink(t *testing.T) {
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "target"), []byte("public test fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(path, "profile.key")); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if file, err := openTrustedRegularAt(dir, "profile.key", 45, true); err == nil {
		_ = file.Close()
		t.Fatal("followed a credential symlink")
	}
	for _, name := range []string{"", ".", "..", "../target", "a/b", "a\x00b"} {
		if file, err := openTrustedRegularAt(dir, name, 45, true); err == nil {
			_ = file.Close()
			t.Fatal("accepted an unsafe descriptor-relative leaf name")
		}
	}
}

func TestBoundedRead(t *testing.T) {
	if data, err := readBounded(strings.NewReader("1234"), 4); err != nil || string(data) != "1234" {
		t.Fatal("exact bound rejected")
	}
	if data, err := readBounded(strings.NewReader("12345"), 4); err == nil || data != nil {
		t.Fatal("over-bound input returned")
	}
}

func FuzzProfileParser(f *testing.F) {
	f.Add(profileJSON("office"))
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		profile, err := parseProfile("office", data)
		if err == nil {
			if err := profile.validateMetadata(); err != nil || profile.privateKey != (wgtypes.Key{}) {
				t.Fatal("parser returned invalid metadata or a credential")
			}
		}
	})
}
