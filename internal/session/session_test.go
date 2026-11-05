package session

import (
	"strings"
	"testing"

	"github.com/Lfardell1/Soteria/internal/config"
)

func TestRequestValidate(t *testing.T) {
	for _, name := range []string{"bash", "/bin/bash", "/usr/bin/python3", "python3.13"} {
		if err := (Request{Config: config.Default(), Command: []string{name, "literal ; not a shell"}}).Validate(); err != nil {
			t.Errorf("valid command %q: %v", name, err)
		}
	}
	for _, name := range []string{"", "-bash", ".", "..", "./bash", "../bin/bash", "/tmp/tool", "/bin/../bin/bash", "/bin/sub/tool", "bash;id", "bash\x00", "/usr/libexec/soteria/soteria"} {
		if err := (Request{Config: config.Default(), Command: []string{name}}).Validate(); err == nil {
			t.Errorf("unsafe executable %q accepted", name)
		}
	}
	request := Request{Config: config.Default(), Command: []string{"bash", strings.Repeat("x", 33<<10)}}
	if err := request.Validate(); err == nil {
		t.Fatal("unbounded command accepted")
	}
	request.Command = nil
	if err := request.Validate(); err == nil {
		t.Fatal("empty command accepted")
	}
	request.Command = []string{"bash"}
	request.Config.Network.Mode = "unsafe"
	if err := request.Validate(); err == nil {
		t.Fatal("invalid resource/network policy accepted")
	}
}

func TestSessionIDIsNotAPathOrUnit(t *testing.T) {
	if !validSessionID("0123456789abcdef0123456789abcdef") {
		t.Fatal("valid session ID rejected")
	}
	for _, id := range []string{"", "abc", strings.Repeat("a", 33), strings.Repeat("A", 32), "../0123456789abcdef0123456789abcde", "soteria-0123456789abcdef0123456789abcdef.service", strings.Repeat("0", 31) + "/"} {
		if validSessionID(id) {
			t.Errorf("invalid ID %q accepted", id)
		}
	}
}
