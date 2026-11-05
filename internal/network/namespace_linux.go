//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type namespaceIdentity struct {
	device uint64
	inode  uint64
}

func networkNamespaceIdentity(fd int) (namespaceIdentity, error) {
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET {
		return namespaceIdentity{}, errors.New("descriptor is not a network namespace")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return namespaceIdentity{}, err
	}
	return namespaceIdentity{device: uint64(st.Dev), inode: st.Ino}, nil
}

// The fixed worker is fork/exec'd with CLONE_NEWNET before the Go runtime
// starts. No function in this package calls setns or unshare on a live thread.
func requireNetworkNamespace(private bool) (namespaceIdentity, error) {
	if os.Geteuid() != 0 {
		return namespaceIdentity{}, errors.New("network setup requires the root service worker/supervisor")
	}
	current, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return namespaceIdentity{}, fmt.Errorf("open current network namespace: %w", err)
	}
	defer current.Close()
	init, err := os.Open("/proc/1/ns/net")
	if err != nil {
		return namespaceIdentity{}, fmt.Errorf("open init network namespace: %w", err)
	}
	defer init.Close()
	identity, err := networkNamespaceIdentity(int(current.Fd()))
	if err != nil {
		return namespaceIdentity{}, err
	}
	host, err := networkNamespaceIdentity(int(init.Fd()))
	if err != nil {
		return namespaceIdentity{}, err
	}
	if private == (identity == host) {
		if private {
			return namespaceIdentity{}, errors.New("refusing workload network operations in the host network namespace")
		}
		return namespaceIdentity{}, errors.New("host link operations must run in the host network namespace")
	}
	return identity, nil
}

// PrepareOffline runs only in the newly born worker. It changes no host
// sysctls, routes, resolver files, firewall rules, or interfaces.
func PrepareOffline() error {
	if _, err := requireNetworkNamespace(true); err != nil {
		return err
	}
	handle, err := newRouteHandle()
	if err != nil {
		return err
	}
	defer handle.Close()
	links, err := handle.LinkList()
	if err != nil {
		return err
	}
	if err := validateLinkSet(links, linkIntent{}, 0, false); err != nil {
		return err
	}
	if err := disablePrivateIPv6(""); err != nil {
		return err
	}
	if err := handle.LinkSetUp(links[0]); err != nil {
		return fmt.Errorf("bring up private loopback: %w", err)
	}
	links, err = handle.LinkList()
	if err != nil {
		return err
	}
	if err := validateLinkSet(links, linkIntent{}, 0, true); err != nil {
		return err
	}
	if err := verifyPrivateIPv6(context.Background(), handle, ""); err != nil {
		return err
	}
	routes, err := allIPv4Routes(handle)
	if err != nil {
		return err
	}
	return validateRoutes(routes, links[0].Attrs().Index, 0, nil)
}

func validateLinkSet(links []netlink.Link, intent linkIntent, index int, requireUp bool) error {
	expected := 1
	if intent.Name != "" {
		expected = 2
	}
	if len(links) != expected {
		return errors.New("private namespace contains unexpected network interfaces")
	}
	var loopback, tunnel bool
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			return errors.New("invalid namespace interface state")
		}
		attrs := link.Attrs()
		if attrs.Name == "lo" && attrs.Flags&net.FlagLoopback != 0 && attrs.Index > 0 && !loopback {
			loopback = true
		} else if intent.Name != "" && matchesOwnedLink(link, intent, index) && !tunnel {
			tunnel = true
		} else {
			return errors.New("private namespace contains an unowned network interface")
		}
		if requireUp && attrs.Flags&net.FlagUp == 0 {
			return errors.New("required private network interface is down")
		}
	}
	if !loopback || expected == 2 && !tunnel {
		return errors.New("required private network interface is missing")
	}
	return nil
}

func ipv6Controls(linkName string) []string {
	controls := []string{"all", "default", "lo"}
	if linkName != "" {
		controls = append(controls, linkName)
	}
	return controls
}

func disablePrivateIPv6(linkName string) error {
	// Keep this check adjacent to the writes, including error cleanup paths.
	if _, err := requireNetworkNamespace(true); err != nil {
		return err
	}
	for _, name := range ipv6Controls(linkName) {
		path := "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6"
		if err := os.WriteFile(path, []byte("1\n"), 0); err != nil {
			return fmt.Errorf("disable native IPv6 in private namespace: %w", err)
		}
	}
	return nil
}

func verifyPrivateIPv6(ctx context.Context, handle *netlink.Handle, linkName string) error {
	for _, name := range ipv6Controls(linkName) {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6")
		if err != nil || strings.TrimSpace(string(value)) != "1" {
			return errors.New("native IPv6 is not verifiably disabled in the private namespace")
		}
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return err
	}
	addresses, err := handle.AddrList(nil, netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	if len(addresses) != 0 {
		return errors.New("private namespace still has an IPv6 address")
	}
	if err := setRouteDeadline(ctx, handle); err != nil {
		return err
	}
	routes, err := handle.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.Type != unix.RTN_UNREACHABLE && route.Type != unix.RTN_PROHIBIT && route.Type != unix.RTN_BLACKHOLE {
			return errors.New("private namespace still has an IPv6 route")
		}
	}
	return nil
}

func allIPv4Routes(handle *netlink.Handle) ([]netlink.Route, error) {
	return handle.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
}

func setRouteDeadline(ctx context.Context, handle *netlink.Handle) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := controlTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < time.Microsecond {
			return context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	return handle.SetSocketTimeout(timeout)
}

func defaultRoute(index int, profile Profile) netlink.Route {
	return netlink.Route{
		LinkIndex: index, Dst: &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		Src: net.IP(profile.Address.Addr().AsSlice()), Scope: netlink.SCOPE_UNIVERSE,
		Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_STATIC, Family: unix.AF_INET,
	}
}

func validateRoutes(routes []netlink.Route, loopbackIndex, tunnelIndex int, profile *Profile) error {
	defaults := 0
	for _, route := range routes {
		if len(route.Gw) != 0 || len(route.MultiPath) != 0 || route.Via != nil || route.Encap != nil || route.NewDst != nil || route.MPLSDst != nil || route.ILinkIndex != 0 || route.Tos != 0 {
			return errors.New("private namespace contains an unexpected routed path")
		}
		if profile != nil && route.Equal(defaultRoute(tunnelIndex, *profile)) {
			defaults++
			continue
		}
		if route.Table != unix.RT_TABLE_LOCAL || route.Protocol != unix.RTPROT_KERNEL || route.Dst == nil || route.Dst.IP.To4() == nil ||
			(route.Type != unix.RTN_LOCAL && route.Type != unix.RTN_BROADCAST) {
			return errors.New("private namespace route state differs from the owned full tunnel")
		}
		ones, bits := route.Dst.Mask.Size()
		if route.LinkIndex == loopbackIndex && ones >= 8 && bits == 32 && route.Dst.IP.Mask(route.Dst.Mask).IsLoopback() {
			continue
		}
		if profile != nil && route.LinkIndex == tunnelIndex {
			address := net.IP(profile.Address.Addr().AsSlice()).To4()
			network := net.IP(profile.Address.Masked().Addr().AsSlice()).To4()
			mask := net.CIDRMask(profile.Address.Bits(), 32)
			broadcast := make(net.IP, net.IPv4len)
			for i := range broadcast {
				broadcast[i] = network[i] | ^mask[i]
			}
			ones, bits := route.Dst.Mask.Size()
			if ones == 32 && bits == 32 && (route.Dst.IP.Equal(address) || route.Type == unix.RTN_BROADCAST && (route.Dst.IP.Equal(network) || route.Dst.IP.Equal(broadcast))) {
				continue
			}
		}
		return errors.New("private namespace contains an unexpected local route")
	}
	if profile != nil && defaults != 1 {
		return errors.New("the owned WireGuard default IPv4 route is missing or duplicated")
	}
	return nil
}
