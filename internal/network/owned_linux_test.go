//go:build linux

package network

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

const testSessionID = "0123456789abcdef0123456789abcdef"

func testIntent(t *testing.T) linkIntent {
	t.Helper()
	intent, err := intentFor(testSessionID)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func ownedFixture(intent linkIntent) *netlink.Wireguard {
	return &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: intent.Name, Alias: intent.Alias, Index: 42}}
}

func TestSessionLinkIdentity(t *testing.T) {
	intent := testIntent(t)
	if len(intent.Name) > 15 || intent.Alias != "soteria:"+testSessionID || intent.Name != "st0123456789abc" {
		t.Fatal("incorrect full ownership marker or interface-name bound")
	}
	for _, value := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), testSessionID[:31] + "/", testSessionID[:31] + "\n"} {
		if _, err := intentFor(value); err == nil {
			t.Errorf("accepted invalid session ID %q", value)
		}
	}
}

func TestOwnedLinkMatcher(t *testing.T) {
	intent := testIntent(t)
	link := ownedFixture(intent)
	if !matchesOwnedLink(link, intent, 42) || !matchesOwnedLink(link, intent, 0) {
		t.Fatal("exact owner did not match, including the pre-move intent window")
	}
	if matchesOwnedLink(link, intent, 41) || matchesOwnedLink(nil, intent, 0) {
		t.Fatal("matched a missing or recycled interface index")
	}
	for _, edit := range []func(*netlink.LinkAttrs){
		func(attrs *netlink.LinkAttrs) { attrs.Name += "x" },
		func(attrs *netlink.LinkAttrs) { attrs.Alias = "soteria:" },
		func(attrs *netlink.LinkAttrs) { attrs.Alias = "soteria:" + testSessionID[:31] + "0" },
		func(attrs *netlink.LinkAttrs) { attrs.Index = 0 },
	} {
		link := ownedFixture(intent)
		edit(link.Attrs())
		if matchesOwnedLink(link, intent, 0) {
			t.Fatal("matched a loose name/alias or invalid index")
		}
	}
	if matchesOwnedLink(&netlink.Dummy{LinkAttrs: link.LinkAttrs}, intent, 0) {
		t.Fatal("matched an owned-looking non-WireGuard interface")
	}
	for _, edit := range []func(*linkIntent){
		func(intent *linkIntent) { intent.Version = 0 },
		func(intent *linkIntent) { intent.Name = "lo" },
		func(intent *linkIntent) { intent.Alias = "soteria:other" },
		func(intent *linkIntent) { intent.SessionID = "bad" },
	} {
		bad := intent
		edit(&bad)
		if matchesOwnedLink(link, bad, 0) {
			t.Fatal("matched a forged intent")
		}
	}
}

type fakeHostLinks struct {
	link      netlink.Link
	lookupErr error
	addErr    error
	moveErr   error
	deleteErr error
	onAdd     func(netlink.Link)
	adds      int
	moves     int
	deletes   int
	moveFD    int
}

func (f *fakeHostLinks) LinkByName(string) (netlink.Link, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	if f.link == nil {
		return nil, os.ErrNotExist
	}
	return f.link, nil
}

func (f *fakeHostLinks) LinkAdd(link netlink.Link) error {
	f.adds++
	if f.onAdd != nil {
		f.onAdd(link)
	} else {
		link.Attrs().Index = 42
		f.link = link
	}
	return f.addErr
}

func (f *fakeHostLinks) LinkSetNsFd(_ netlink.Link, fd int) error {
	f.moves++
	f.moveFD = fd
	if f.moveErr == nil {
		f.link = nil
	}
	return f.moveErr
}

func (f *fakeHostLinks) LinkDel(netlink.Link) error {
	f.deletes++
	if f.deleteErr == nil {
		f.link = nil
	}
	return f.deleteErr
}

func TestResidualCleanupOnlyExactMarkedLink(t *testing.T) {
	intent := testIntent(t)
	for _, tc := range []struct {
		name string
		link netlink.Link
		want int
	}{
		{"absent", nil, 0}, {"exact", ownedFixture(intent), 1},
		{"unmarked", &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: intent.Name, Index: 42}}, 0},
		{"prefix only", &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: intent.Name, Alias: "soteria:", Index: 42}}, 0},
		{"other type", &netlink.Dummy{LinkAttrs: ownedFixture(intent).LinkAttrs}, 0},
		{"same name different full ID", &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: intent.Name, Alias: "soteria:" + testSessionID[:31] + "0", Index: 42}}, 0},
		{"same full marker recycled index", &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: intent.Name, Alias: intent.Alias, Index: 43}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := &fakeHostLinks{link: tc.link}
			err := cleanupHostLink(ops, intent, 42)
			if ops.deletes != tc.want {
				t.Fatalf("deleted %d links, want %d", ops.deletes, tc.want)
			}
			if tc.link != nil && tc.want == 0 && err == nil {
				t.Fatal("did not report refused ownership mismatch")
			}
		})
	}
	failed := errors.New("injected delete failure")
	ops := &fakeHostLinks{link: ownedFixture(intent), deleteErr: failed}
	if err := cleanupHostLink(ops, intent, 42); !errors.Is(err, failed) {
		t.Fatal("lost cleanup error")
	}
}

func TestCreateIntentPrecedesAtomicMarkedCreateAndMove(t *testing.T) {
	intent := testIntent(t)
	path := t.TempDir()
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	ops := &fakeHostLinks{}
	ops.onAdd = func(link netlink.Link) {
		data, err := os.ReadFile(filepath.Join(path, intent.fileName()))
		if err != nil {
			t.Fatalf("ownership intent missing before create: %v", err)
		}
		var saved linkIntent
		if err := json.Unmarshal(data, &saved); err != nil || saved != intent {
			t.Fatal("pre-create intent does not identify the full session")
		}
		if link.Type() != "wireguard" || link.Attrs().Alias != intent.Alias || link.Attrs().Name != intent.Name || link.Attrs().Flags&net.FlagUp != 0 {
			t.Fatal("creation was not an atomically marked, down WireGuard link")
		}
		link.Attrs().Index = 42
		ops.link = link
	}
	owned, err := createAndMove(ops, intent, 73, dir, namespaceIdentity{inode: 1})
	if err != nil {
		t.Fatal(err)
	}
	if owned.Name != intent.Name || owned.index != 42 || ops.moves != 1 || ops.moveFD != 73 || ops.deletes != 0 || ops.link != nil {
		t.Fatal("incorrect host-to-worker move or ownership result")
	}
	if _, err := os.Stat(filepath.Join(path, intent.fileName())); err != nil {
		t.Fatal("removed residual authority before session cleanup")
	}
}

func TestCreateFailureWindowsNeverDeleteAnUnmarkedCollision(t *testing.T) {
	intent := testIntent(t)
	failed := errors.New("injected create or move failure")
	for _, tc := range []struct {
		name    string
		addErr  error
		moveErr error
		marked  bool
		deletes int
	}{
		{"create acknowledged late", failed, nil, true, 1},
		{"create collision", failed, nil, false, 0},
		{"move failed", nil, failed, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			ops := &fakeHostLinks{addErr: tc.addErr, moveErr: tc.moveErr}
			ops.onAdd = func(link netlink.Link) {
				link.Attrs().Index = 42
				if !tc.marked {
					link.Attrs().Alias = "unrelated"
				}
				ops.link = link
			}
			if _, err := createAndMove(ops, intent, 73, dir, namespaceIdentity{}); !errors.Is(err, failed) {
				t.Fatal("lost acquisition failure")
			}
			if ops.deletes != tc.deletes {
				t.Fatalf("deleted %d links, want %d", ops.deletes, tc.deletes)
			}
		})
	}
}

func TestPreexistingHostLinkNeverAcquired(t *testing.T) {
	intent := testIntent(t)
	path := t.TempDir()
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	ops := &fakeHostLinks{link: ownedFixture(intent)}
	if _, err := createAndMove(ops, intent, 73, dir, namespaceIdentity{}); err == nil {
		t.Fatal("adopted a pre-existing host interface")
	}
	if ops.adds != 0 || ops.moves != 0 || ops.deletes != 0 {
		t.Fatal("touched a pre-existing interface")
	}
	if _, err := os.Stat(filepath.Join(path, intent.fileName())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("persisted authority for a pre-existing interface")
	}
}

func FuzzSessionIdentity(f *testing.F) {
	f.Add(testSessionID)
	f.Add("../../lo")
	f.Fuzz(func(t *testing.T, id string) {
		intent, err := intentFor(id)
		if err == nil && (len(intent.Name) > 15 || intent.Alias != "soteria:"+id || len(id) != 32) {
			t.Fatal("invalid ownership identity")
		}
	})
}
