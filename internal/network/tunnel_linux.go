//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	readinessTimeout = 30 * time.Second
	healthTimeout    = 5 * time.Second
)

// Tunnel owns only a marked WireGuard interface in the private worker netns.
// The host supervisor retains ownership of possible pre-move residuals.
type Tunnel struct {
	gate      chan struct{}
	intent    linkIntent
	index     int
	namespace namespaceIdentity
	profile   Profile
	publicKey wgtypes.Key
	started   time.Time
	closed    bool
	closeErr  error
}

// ConfigureWireGuard is called after PrepareOffline and the supervisor's move.
// All address, MTU, route, and WireGuard configuration occurs in the worker.
func ConfigureWireGuard(ctx context.Context, linkName string, profile Profile) (*Tunnel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	namespace, err := requireNetworkNamespace(true)
	if err != nil {
		return nil, err
	}
	if err := profile.validateMetadata(); err != nil {
		return nil, err
	}
	if profile.privateKey == (wgtypes.Key{}) {
		return nil, errors.New("profile has no loaded private-key credential")
	}
	handle, err := newRouteHandle()
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	link, err := handle.LinkByName(linkName)
	if err != nil {
		return nil, fmt.Errorf("find moved WireGuard link: %w", err)
	}
	if link.Attrs() == nil || !strings.HasPrefix(link.Attrs().Alias, "soteria:") {
		return nil, errors.New("moved link has no exact ownership marker")
	}
	intent, err := intentFor(strings.TrimPrefix(link.Attrs().Alias, "soteria:"))
	if err != nil || intent.Name != linkName || !matchesOwnedLink(link, intent, 0) {
		return nil, errors.New("moved link is not an exactly marked kernel WireGuard link")
	}
	tunnel := &Tunnel{gate: make(chan struct{}, 1), intent: intent, index: link.Attrs().Index, namespace: namespace, profile: profile, publicKey: profile.privateKey.PublicKey()}
	// Health checks need only public metadata. Do not retain another key copy.
	tunnel.profile.privateKey = wgtypes.Key{}
	tunnel.profile.DNS = append([]netip.Addr(nil), profile.DNS...)
	return configureTunnel(ctx, handle, link, tunnel, profile)
}

func configureTunnel(ctx context.Context, handle *netlink.Handle, link netlink.Link, tunnel *Tunnel, profile Profile) (*Tunnel, error) {
	fail := func(cause error) (*Tunnel, error) {
		_ = handle.SetSocketTimeout(controlTimeout)
		return nil, errors.Join(cause, cleanupHostLink(handle, tunnel.intent, tunnel.index))
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return fail(err)
	}
	links, err := handle.LinkList()
	if err != nil {
		return fail(err)
	}
	if err := validateLinkSet(links, tunnel.intent, tunnel.index, false); err != nil {
		return fail(err)
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return fail(err)
	}
	loopback, err := handle.LinkByName("lo")
	if err != nil || loopback.Attrs().Flags&net.FlagUp == 0 || link.Attrs().Flags&net.FlagUp != 0 {
		return fail(errors.New("private loopback must be up and the moved WireGuard link must still be down"))
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return fail(err)
	}
	addresses, err := handle.AddrList(link, netlink.FAMILY_ALL)
	if err != nil || len(addresses) != 0 {
		return fail(errors.New("moved WireGuard link must not have pre-existing addresses"))
	}
	if err := disablePrivateIPv6(tunnel.intent.Name); err != nil {
		return fail(err)
	}
	if err := verifyPrivateIPv6(ctx, handle, tunnel.intent.Name); err != nil {
		return fail(err)
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return fail(err)
	}
	routes, err := allIPv4Routes(handle)
	if err != nil {
		return fail(err)
	}
	if err := validateRoutes(routes, loopback.Attrs().Index, 0, nil); err != nil {
		return fail(err)
	}
	device, err := wireGuardRequest(ctx, tunnel.intent.Name, nil)
	if err != nil {
		return fail(err)
	}
	pristine := device != nil && device.Type == wgtypes.LinuxKernel && device.Name == tunnel.intent.Name && len(device.Peers) == 0 && device.PublicKey == (wgtypes.Key{})
	if device != nil {
		clear(device.PrivateKey[:])
	}
	if !pristine {
		return fail(errors.New("moved WireGuard link must be an unconfigured kernel device"))
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return fail(err)
	}
	if err := handle.LinkSetMTU(link, profile.MTU); err != nil {
		return fail(fmt.Errorf("set private WireGuard MTU: %w", err))
	}
	keepalive := time.Duration(profile.KeepaliveSeconds) * time.Second
	zero := 0
	key := profile.privateKey
	config := wgtypes.Config{
		PrivateKey: &key, ListenPort: &zero, FirewallMark: &zero, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey: profile.PublicKey, Endpoint: net.UDPAddrFromAddrPort(profile.Endpoint),
			PersistentKeepaliveInterval: &keepalive, ReplaceAllowedIPs: true,
			AllowedIPs: []net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}},
		}},
	}
	tunnel.started = time.Now()
	if _, err := wireGuardRequest(ctx, tunnel.intent.Name, &config); err != nil {
		return fail(err)
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return fail(err)
	}
	address := &netlink.Addr{
		IPNet: &net.IPNet{IP: net.IP(profile.Address.Addr().AsSlice()), Mask: net.CIDRMask(profile.Address.Bits(), 32)},
		Flags: unix.IFA_F_NOPREFIXROUTE,
	}
	if err := handle.AddrAdd(link, address); err != nil {
		return fail(fmt.Errorf("assign private WireGuard address: %w", err))
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return fail(err)
	}
	if err := handle.LinkSetUp(link); err != nil {
		return fail(fmt.Errorf("bring up private WireGuard link: %w", err))
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return fail(err)
	}
	route := defaultRoute(tunnel.index, profile)
	if err := handle.RouteAdd(&route); err != nil {
		return fail(fmt.Errorf("add private WireGuard default route: %w", err))
	}
	if err := tunnel.validateState(ctx, handle); err != nil {
		return fail(err)
	}
	return tunnel, nil
}

// WaitReady additionally caps readiness at 30 seconds. The service owner must
// also impose its setup deadline externally so a failed worker is killable.
func (t *Tunnel) WaitReady(ctx context.Context) error {
	if t == nil || t.gate == nil {
		return errors.New("missing WireGuard tunnel ownership")
	}
	ctx, cancel := context.WithTimeout(ctx, readinessTimeout)
	defer cancel()
	var last error
	for {
		if err := t.Check(ctx); err == nil {
			return nil
		} else {
			last = err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(fmt.Errorf("WireGuard readiness deadline: %w", ctx.Err()), last)
		case <-timer.C:
		}
	}
}

// Check actively probes only configured resolvers through the owned interface.
// A successful probe plus newly received authenticated bytes is healthy even
// after a long idle interval; handshake age by itself is not an outage.
func (t *Tunnel) Check(ctx context.Context) error {
	if t == nil || t.gate == nil {
		return errors.New("missing WireGuard tunnel ownership")
	}
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	select {
	case t.gate <- struct{}{}:
		defer func() { <-t.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.closed {
		return errors.New("WireGuard tunnel is closed")
	}
	namespace, err := requireNetworkNamespace(true)
	if err != nil || namespace != t.namespace {
		return errors.New("WireGuard health check must run in the owning private namespace")
	}
	handle, err := newRouteHandle()
	if err != nil {
		return err
	}
	defer handle.Close()
	if err := t.validateState(ctx, handle); err != nil {
		return err
	}
	before, err := t.peerState(ctx)
	if err != nil {
		return err
	}
	if err := probeResolvers(ctx, t.intent.Name, t.profile); err != nil {
		return fmt.Errorf("configured resolver probe failed: %w", err)
	}
	after, err := t.peerState(ctx)
	if err != nil {
		return err
	}
	if err := authenticatedProbeEvidence(before, after, t.started); err != nil {
		return err
	}
	return t.validateState(ctx, handle)
}

func authenticatedProbeEvidence(before, after wgtypes.Peer, started time.Time) error {
	if after.LastHandshakeTime.IsZero() || after.LastHandshakeTime.Before(started) {
		return errors.New("no fresh authenticated WireGuard handshake since startup")
	}
	if before.ReceiveBytes < 0 || after.ReceiveBytes <= before.ReceiveBytes {
		return errors.New("resolver probe produced no newly received authenticated WireGuard traffic")
	}
	return nil
}

func (t *Tunnel) peerState(ctx context.Context) (wgtypes.Peer, error) {
	device, err := wireGuardRequest(ctx, t.intent.Name, nil)
	if err != nil {
		return wgtypes.Peer{}, err
	}
	if device == nil {
		return wgtypes.Peer{}, errors.New("kernel WireGuard device is missing")
	}
	clear(device.PrivateKey[:])
	return validateDevice(device, t.intent.Name, t.publicKey, t.profile)
}

func validateDevice(device *wgtypes.Device, name string, publicKey wgtypes.Key, profile Profile) (wgtypes.Peer, error) {
	if device == nil || device.Name != name || device.Type != wgtypes.LinuxKernel || device.PublicKey != publicKey || device.FirewallMark != 0 || len(device.Peers) != 1 {
		return wgtypes.Peer{}, errors.New("kernel WireGuard device state differs from the owned profile")
	}
	peer := device.Peers[0]
	if peer.PublicKey != profile.PublicKey || peer.PresharedKey != (wgtypes.Key{}) ||
		peer.PersistentKeepaliveInterval != time.Duration(profile.KeepaliveSeconds)*time.Second || !isFullTunnel(peer.AllowedIPs) ||
		peer.Endpoint == nil || peer.Endpoint.Port < 1 || peer.Endpoint.Port > 65535 || peer.Endpoint.IP.To16() == nil {
		return wgtypes.Peer{}, errors.New("authenticated peer configuration differs from the owned full tunnel")
	}
	// Do not compare the live endpoint tuple: WireGuard supports authenticated
	// roaming. Only public-key identity and the owned path are the invariant.
	return peer, nil
}

func isFullTunnel(allowed []net.IPNet) bool {
	if len(allowed) != 1 || allowed[0].IP.To4() == nil {
		return false
	}
	ones, bits := allowed[0].Mask.Size()
	return ones == 0 && bits == 32 && allowed[0].IP.IsUnspecified()
}

func (t *Tunnel) validateState(ctx context.Context, handle *netlink.Handle) error {
	if err := setRouteDeadline(ctx, handle); err != nil {
		return err
	}
	links, err := handle.LinkList()
	if err != nil {
		return err
	}
	if err := validateLinkSet(links, t.intent, t.index, true); err != nil {
		return err
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return err
	}
	link, err := handle.LinkByName(t.intent.Name)
	if err != nil {
		return err
	}
	if link.Attrs().MTU != t.profile.MTU {
		return errors.New("owned WireGuard MTU has changed")
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return err
	}
	addresses, err := handle.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	if len(addresses) != 1 || addresses[0].IPNet == nil || !addresses[0].IP.Equal(net.IP(t.profile.Address.Addr().AsSlice())) {
		return errors.New("owned WireGuard address state has changed")
	}
	ones, bits := addresses[0].Mask.Size()
	if ones != t.profile.Address.Bits() || bits != 32 {
		return errors.New("owned WireGuard prefix has changed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyPrivateIPv6(ctx, handle, t.intent.Name); err != nil {
		return err
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return err
	}
	loopback, err := handle.LinkByName("lo")
	if err != nil {
		return err
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return err
	}
	routes, err := allIPv4Routes(handle)
	if err != nil {
		return err
	}
	if err := validateRoutes(routes, loopback.Attrs().Index, t.index, &t.profile); err != nil {
		return err
	}
	for _, resolver := range t.profile.DNS {
		if err := setRouteDeadline(ctx, handle); err != nil {
			return err
		}
		routes, err := handle.RouteGet(net.IP(resolver.AsSlice()))
		if err != nil || len(routes) != 1 || routes[0].LinkIndex != t.index || routes[0].Type != unix.RTN_UNICAST ||
			len(routes[0].Gw) != 0 || len(routes[0].MultiPath) != 0 || !routes[0].Src.Equal(net.IP(t.profile.Address.Addr().AsSlice())) {
			return errors.New("configured resolver is not routed through the owned WireGuard interface")
		}
	}
	return ctx.Err()
}

// Close removes the exact marked interface, which also removes its addresses
// and routes. It never deletes a route or interface by a loose name prefix.
func (t *Tunnel) Close() error {
	if t == nil {
		return nil
	}
	if t.gate == nil {
		return errors.New("missing WireGuard tunnel ownership")
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout+controlTimeout)
	defer cancel()
	select {
	case t.gate <- struct{}{}:
		defer func() { <-t.gate }()
	case <-ctx.Done():
		return errors.New("timed out waiting for WireGuard health check to stop")
	}
	if t.closed {
		return t.closeErr
	}
	t.closed = true
	namespace, err := requireNetworkNamespace(true)
	if err != nil || namespace != t.namespace {
		t.closeErr = errors.New("WireGuard close must run in the owning private namespace")
		return t.closeErr
	}
	handle, err := newRouteHandle()
	if err != nil {
		t.closeErr = err
		return err
	}
	defer handle.Close()
	t.closeErr = cleanupHostLink(handle, t.intent, t.index)
	return t.closeErr
}

type wireGuardResult struct {
	device *wgtypes.Device
	err    error
}

func wireGuardRequest(ctx context.Context, name string, config *wgtypes.Config) (*wgtypes.Device, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		if config != nil && config.PrivateKey != nil {
			clear(config.PrivateKey[:])
		}
		return nil, err
	}
	client, err := wgctrl.New()
	if err != nil {
		if config != nil && config.PrivateKey != nil {
			clear(config.PrivateKey[:])
		}
		return nil, errors.New("open kernel WireGuard control failed")
	}
	defer client.Close()
	result := make(chan wireGuardResult, 1)
	go func() {
		var out wireGuardResult
		if config == nil {
			out.device, out.err = client.Device(name)
			if out.device != nil {
				clear(out.device.PrivateKey[:])
			}
		} else {
			out.err = client.ConfigureDevice(name, *config)
			if config.PrivateKey != nil {
				clear(config.PrivateKey[:])
			}
		}
		result <- out
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case out := <-result:
		if out.err != nil {
			// Do not forward control-library errors containing request data.
			return nil, errors.New("kernel WireGuard control request failed")
		}
		return out.device, nil
	}
}
