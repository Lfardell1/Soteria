//go:build linux

package network

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func loopbackFixture() netlink.Link {
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1, Flags: net.FlagLoopback | net.FlagUp}}
}

func TestPrivateNamespaceLinkInvariant(t *testing.T) {
	intent := testIntent(t)
	link := ownedFixture(intent)
	link.Flags = net.FlagUp
	if err := validateLinkSet([]netlink.Link{loopbackFixture()}, linkIntent{}, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := validateLinkSet([]netlink.Link{loopbackFixture(), link}, intent, 42, true); err != nil {
		t.Fatal(err)
	}
	for _, links := range [][]netlink.Link{
		{}, {link}, {loopbackFixture(), link, &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 3}}},
		{loopbackFixture(), &netlink.Dummy{LinkAttrs: link.LinkAttrs}},
		{loopbackFixture(), &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: intent.Name, Index: 42, Flags: net.FlagUp}}},
		{&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1, Flags: net.FlagLoopback}}, link},
	} {
		if err := validateLinkSet(links, intent, 42, true); err == nil {
			t.Fatal("accepted an unowned, missing, or down interface")
		}
	}
	link.Flags = 0
	if err := validateLinkSet([]netlink.Link{loopbackFixture(), link}, intent, 42, false); err != nil {
		t.Fatalf("initial moved link must still be down: %v", err)
	}
	if err := validateLinkSet([]netlink.Link{loopbackFixture(), link}, intent, 42, true); err == nil {
		t.Fatal("accepted a down tunnel as ready")
	}
	if err := validateLinkSet([]netlink.Link{loopbackFixture(), link}, linkIntent{}, 0, false); err == nil {
		t.Fatal("accepted a tunnel in offline mode")
	}
}

func localLoopbackRoute() netlink.Route {
	return netlink.Route{
		LinkIndex: 1, Table: unix.RT_TABLE_LOCAL, Protocol: unix.RTPROT_KERNEL, Type: unix.RTN_LOCAL,
		Scope: netlink.SCOPE_HOST, Dst: &net.IPNet{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}, Family: unix.AF_INET,
	}
}

func TestOwnedFullTunnelRouteInvariant(t *testing.T) {
	profile := testProfile(t)
	valid := []netlink.Route{localLoopbackRoute(), defaultRoute(42, profile)}
	if err := validateRoutes(valid, 1, 42, &profile); err != nil {
		t.Fatal(err)
	}
	if err := validateRoutes([]netlink.Route{localLoopbackRoute()}, 1, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := validateRoutes(valid, 1, 0, nil); err == nil {
		t.Fatal("offline mode accepted an external route")
	}
	for _, tc := range []struct {
		name string
		edit func(*netlink.Route)
	}{
		{"wrong link", func(route *netlink.Route) { route.LinkIndex = 3 }},
		{"wrong source", func(route *netlink.Route) { route.Src = net.IPv4(10, 8, 0, 9).To4() }},
		{"wrong table", func(route *netlink.Route) { route.Table = 100 }},
		{"wrong priority", func(route *netlink.Route) { route.Priority = 100 }},
		{"gateway", func(route *netlink.Route) { route.Gw = net.IPv4(10, 8, 0, 1).To4() }},
		{"multipath", func(route *netlink.Route) { route.MultiPath = []*netlink.NexthopInfo{{LinkIndex: 3}} }},
		{"split", func(route *netlink.Route) {
			route.Dst = &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}
		}},
		{"wrong type", func(route *netlink.Route) { route.Type = unix.RTN_LOCAL }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := defaultRoute(42, profile)
			tc.edit(&route)
			if err := validateRoutes([]netlink.Route{localLoopbackRoute(), route}, 1, 42, &profile); err == nil {
				t.Fatal("accepted modified tunnel route state")
			}
		})
	}
	if err := validateRoutes([]netlink.Route{localLoopbackRoute()}, 1, 42, &profile); err == nil {
		t.Fatal("accepted missing default route")
	}
	if err := validateRoutes(append(valid, defaultRoute(42, profile)), 1, 42, &profile); err == nil {
		t.Fatal("accepted duplicate default route")
	}
	wideLocal := localLoopbackRoute()
	wideLocal.Dst = &net.IPNet{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(0, 32)}
	if err := validateRoutes([]netlink.Route{wideLocal}, 1, 0, nil); err == nil {
		t.Fatal("accepted local route outside 127/8")
	}
}

func deviceFixture(t *testing.T) (*wgtypes.Device, Profile, wgtypes.Key) {
	t.Helper()
	profile := testProfile(t)
	publicKey := profile.privateKey.PublicKey()
	return &wgtypes.Device{
		Name: testIntent(t).Name, Type: wgtypes.LinuxKernel, PublicKey: publicKey,
		Peers: []wgtypes.Peer{{PublicKey: profile.PublicKey, Endpoint: net.UDPAddrFromAddrPort(profile.Endpoint),
			PersistentKeepaliveInterval: time.Duration(profile.KeepaliveSeconds) * time.Second,
			AllowedIPs:                  []net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}},
		}},
	}, profile, publicKey
}

func TestWireGuardDeviceInvariantAndAuthenticatedRoaming(t *testing.T) {
	device, profile, publicKey := deviceFixture(t)
	if _, err := validateDevice(device, device.Name, publicKey, profile); err != nil {
		t.Fatal(err)
	}
	device.Peers[0].Endpoint = &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 60000}
	if _, err := validateDevice(device, device.Name, publicKey, profile); err != nil {
		t.Fatalf("authenticated endpoint roaming must not be mistaken for a key change: %v", err)
	}
	for _, edit := range []func(*wgtypes.Device){
		func(device *wgtypes.Device) { device.Type = wgtypes.Userspace },
		func(device *wgtypes.Device) { device.PublicKey = testKey(3) },
		func(device *wgtypes.Device) { device.FirewallMark = 1 },
		func(device *wgtypes.Device) { device.Peers = append(device.Peers, device.Peers[0]) },
		func(device *wgtypes.Device) { device.Peers[0].PublicKey = testKey(4) },
		func(device *wgtypes.Device) { device.Peers[0].PresharedKey = testKey(5) },
		func(device *wgtypes.Device) { device.Peers[0].PersistentKeepaliveInterval++ },
		func(device *wgtypes.Device) { device.Peers[0].AllowedIPs[0].Mask = net.CIDRMask(8, 32) },
		func(device *wgtypes.Device) { device.Peers[0].Endpoint = nil },
	} {
		device, profile, publicKey := deviceFixture(t)
		edit(device)
		if _, err := validateDevice(device, testIntent(t).Name, publicKey, profile); err == nil {
			t.Fatal("accepted modified WireGuard identity or full-tunnel configuration")
		}
	}
}

func TestAuthenticatedEvidenceRequiresStartupHandshakeAndActiveResponse(t *testing.T) {
	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	before := wgtypes.Peer{LastHandshakeTime: started.Add(time.Second), ReceiveBytes: 100}
	after := before
	after.ReceiveBytes++
	if err := authenticatedProbeEvidence(before, after, started); err != nil {
		t.Fatal("idle handshake age alone must not fail an active authenticated probe")
	}
	for _, edit := range []func(*wgtypes.Peer){
		func(peer *wgtypes.Peer) { peer.LastHandshakeTime = time.Time{} },
		func(peer *wgtypes.Peer) { peer.LastHandshakeTime = started.Add(-time.Nanosecond) },
		func(peer *wgtypes.Peer) { peer.ReceiveBytes = before.ReceiveBytes },
		func(peer *wgtypes.Peer) { peer.ReceiveBytes = 0 },
	} {
		peer := after
		edit(&peer)
		if err := authenticatedProbeEvidence(before, peer, started); err == nil {
			t.Fatal("accepted a stale handshake or missing active authenticated response")
		}
	}
}

func TestUninitializedAndCanceledTunnelDoesNoOSWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var nilTunnel *Tunnel
	if nilTunnel.Check(ctx) == nil || nilTunnel.WaitReady(ctx) == nil || nilTunnel.Close() != nil {
		t.Fatal("invalid nil tunnel lifecycle")
	}
	if (&Tunnel{}).Check(ctx) == nil || (&Tunnel{}).Close() == nil {
		t.Fatal("accepted missing tunnel ownership")
	}
	tunnel := &Tunnel{gate: make(chan struct{}, 1)}
	if err := tunnel.Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not propagated before OS boundary: %v", err)
	}
	if err := tunnel.WaitReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("readiness cancellation not propagated")
	}
	want := errors.New("recorded close error")
	tunnel.closed, tunnel.closeErr = true, want
	if err := tunnel.Close(); !errors.Is(err, want) {
		t.Fatal("idempotent close lost its result")
	}
}
