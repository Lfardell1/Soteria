//go:build linux

package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const controlTimeout = 2 * time.Second

type linkIntent struct {
	Version   int    `json:"version"`
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
	Alias     string `json:"alias"`
}

func intentFor(sessionID string) (linkIntent, error) {
	if len(sessionID) != 32 {
		return linkIntent{}, errors.New("session ID must be 32 lowercase hexadecimal characters")
	}
	for _, c := range []byte(sessionID) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return linkIntent{}, errors.New("session ID must be 32 lowercase hexadecimal characters")
		}
	}
	return linkIntent{Version: 1, SessionID: sessionID, Name: "st" + sessionID[:13], Alias: "soteria:" + sessionID}, nil
}

func (i linkIntent) fileName() string { return i.SessionID + ".wireguard.json" }

type hostLinkOps interface {
	LinkByName(string) (netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkSetNsFd(netlink.Link, int) error
	LinkDel(netlink.Link) error
}

// OwnedLink identifies a host-born WireGuard link. Cleanup never enters the
// workload namespace: its ordinary lifetime is owned by that namespace.
type OwnedLink struct {
	Name string

	mu      sync.Mutex
	intent  linkIntent
	index   int
	hostNS  namespaceIdentity
	dir     *os.File
	cleaned bool
	result  error
}

// CreateAndMove must be called by the host-network supervisor, never by the
// namespace worker. It does not change host routes, addresses, or firewall.
func CreateAndMove(sessionID string, namespaceFD int, runtimeDir string) (*OwnedLink, error) {
	intent, err := intentFor(sessionID)
	if err != nil {
		return nil, err
	}
	hostNS, err := requireNetworkNamespace(false)
	if err != nil {
		return nil, err
	}
	fd, err := unix.FcntlInt(uintptr(namespaceFD), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("duplicate worker network namespace: %w", err)
	}
	defer unix.Close(fd)
	target, err := networkNamespaceIdentity(fd)
	if err != nil || target == hostNS {
		return nil, errors.New("target must be a distinct network namespace descriptor")
	}
	dir, err := openTrustedDirectory(runtimeDir, true)
	if err != nil {
		return nil, fmt.Errorf("open runtime directory: %w", err)
	}
	handle, err := newRouteHandle()
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	defer handle.Close()
	owned, err := createAndMove(handle, intent, fd, dir, hostNS)
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	return owned, nil
}

func createAndMove(ops hostLinkOps, intent linkIntent, namespaceFD int, dir *os.File, hostNS namespaceIdentity) (*OwnedLink, error) {
	if _, err := ops.LinkByName(intent.Name); err == nil {
		return nil, errors.New("requested host link name is already in use")
	} else if !linkNotFound(err) {
		return nil, fmt.Errorf("check host link name: %w", err)
	}
	if err := persistIntent(dir, intent); err != nil {
		return nil, fmt.Errorf("persist WireGuard ownership intent: %w", err)
	}
	owned := &OwnedLink{Name: intent.Name, intent: intent, dir: dir, hostNS: hostNS}
	fail := func(cause error) (*OwnedLink, error) {
		cleanupErr := cleanupHostLink(ops, intent, owned.index)
		if cleanupErr == nil {
			cleanupErr = removeIntent(dir, intent)
		}
		return nil, errors.Join(cause, cleanupErr)
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name, attrs.Alias = intent.Name, intent.Alias
	// Alias and type are part of the same RTM_NEWLINK as creation. There is no
	// unmarked create-before-move window, even if the supervisor dies here.
	if err := ops.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
		return fail(fmt.Errorf("create host WireGuard link: %w", err))
	}
	link, err := ops.LinkByName(intent.Name)
	if err != nil {
		return fail(fmt.Errorf("find created WireGuard link: %w", err))
	}
	if !matchesOwnedLink(link, intent, 0) || link.Attrs().Flags&net.FlagUp != 0 {
		return fail(errors.New("created link does not match the exact down, owned WireGuard link"))
	}
	owned.index = link.Attrs().Index
	if err := ops.LinkSetNsFd(link, namespaceFD); err != nil {
		return fail(fmt.Errorf("move WireGuard link into worker namespace: %w", err))
	}
	return owned, nil
}

func matchesOwnedLink(link netlink.Link, intent linkIntent, index int) bool {
	if link == nil || link.Attrs() == nil {
		return false
	}
	expected, err := intentFor(intent.SessionID)
	if err != nil || intent != expected {
		return false
	}
	attrs := link.Attrs()
	return link.Type() == "wireguard" && attrs.Name == intent.Name && attrs.Alias == intent.Alias &&
		attrs.Index > 0 && (index == 0 || attrs.Index == index)
}

func cleanupHostLink(ops hostLinkOps, intent linkIntent, index int) error {
	link, err := ops.LinkByName(intent.Name)
	if linkNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect host residual: %w", err)
	}
	if !matchesOwnedLink(link, intent, index) {
		return errors.New("refusing to remove host link without exact WireGuard ownership marker")
	}
	if err := ops.LinkDel(link); err != nil && !linkNotFound(err) {
		return fmt.Errorf("remove owned host residual: %w", err)
	}
	return nil
}

// Cleanup removes only a positively marked host residual. A moved link is not
// visible here and is removed by Tunnel.Close or namespace destruction instead.
func (o *OwnedLink) Cleanup() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cleaned {
		return o.result
	}
	if o.dir == nil {
		return errors.New("missing host link ownership")
	}
	o.cleaned = true
	defer func() { _ = o.dir.Close() }()
	ns, err := requireNetworkNamespace(false)
	if err != nil || ns != o.hostNS {
		o.result = errors.New("host residual cleanup must run in the original host network namespace")
		return o.result
	}
	handle, err := newRouteHandle()
	if err != nil {
		o.result = err
		return err
	}
	defer handle.Close()
	o.result = cleanupHostLink(handle, o.intent, o.index)
	if o.result == nil {
		o.result = removeIntent(o.dir, o.intent)
	}
	return o.result
}

// CleanupResidual is the fixed ExecStopPost helper's operation. No intent means
// no authority to delete; a loose interface-name prefix is never sufficient.
func CleanupResidual(sessionID, runtimeDir string) error {
	expected, err := intentFor(sessionID)
	if err != nil {
		return err
	}
	if _, err := requireNetworkNamespace(false); err != nil {
		return err
	}
	dir, err := openTrustedDirectory(runtimeDir, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open cleanup runtime directory: %w", err)
	}
	defer dir.Close()
	intent, err := readIntent(dir, expected)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	handle, err := newRouteHandle()
	if err != nil {
		return err
	}
	defer handle.Close()
	if err := cleanupHostLink(handle, intent, 0); err != nil {
		return err
	}
	return removeIntent(dir, intent)
}

func persistIntent(dir *os.File, intent linkIntent) error {
	fd, err := unix.Openat(int(dir.Fd()), intent.fileName(), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), intent.fileName())
	data, err := json.Marshal(intent)
	if err == nil {
		err = file.Chmod(0o600)
	}
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = dir.Sync()
	}
	if err != nil {
		_ = unix.Unlinkat(int(dir.Fd()), intent.fileName(), 0)
	}
	return err
}

func readIntent(dir *os.File, expected linkIntent) (linkIntent, error) {
	file, err := openTrustedRegularAt(dir, expected.fileName(), 1024, true)
	if err != nil {
		return linkIntent{}, err
	}
	data, readErr := readBounded(file, 1024)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return linkIntent{}, err
	}
	var intent linkIntent
	if err := decodeStrictObject(data, map[string]any{
		"version": &intent.Version, "session_id": &intent.SessionID, "name": &intent.Name, "alias": &intent.Alias,
	}); err != nil {
		return linkIntent{}, fmt.Errorf("invalid ownership intent: %w", err)
	}
	if intent != expected {
		return linkIntent{}, errors.New("ownership intent does not match the exact requested session")
	}
	return intent, nil
}

func removeIntent(dir *os.File, expected linkIntent) error {
	if _, err := readIntent(dir, expected); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := unix.Unlinkat(int(dir.Fd()), expected.fileName(), 0); err != nil {
		return err
	}
	return dir.Sync()
}

func linkNotFound(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENODEV)
}

func newRouteHandle() (*netlink.Handle, error) {
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open namespace netlink control: %w", err)
	}
	if err := handle.SetSocketTimeout(controlTimeout); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}
