package session

import (
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/Lfardell1/Soteria/internal/config"
)

const InfrastructureFailure = 125

// Request contains caller policy, never privileged executable paths or identity.
// Host transfer paths are used only by the non-root frontend, never sent to root.
type Request struct {
	Config          config.Config
	Command         []string
	Imports         []string
	ExportDirectory string
	Interactive     bool
}

type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// Validate checks policy without opening files or acquiring runtime resources.
func (r Request) Validate() error {
	if err := r.Config.Validate(); err != nil {
		return err
	}
	if len(r.Command) == 0 || len(r.Command) > 256 {
		return fmt.Errorf("command must contain between 1 and 256 arguments")
	}
	if err := validateExecutable(r.Command[0]); err != nil {
		return err
	}
	bytes := 0
	for _, arg := range r.Command {
		if strings.IndexByte(arg, 0) >= 0 || !utf8.ValidString(arg) {
			return fmt.Errorf("command arguments must be valid UTF-8 without NUL bytes")
		}
		bytes += len(arg) + 1
		if bytes > 32<<10 {
			return fmt.Errorf("command exceeds the 32 KiB argument limit")
		}
	}
	if len(r.Imports) > 100000 {
		return fmt.Errorf("too many imports")
	}
	for _, name := range append(append([]string(nil), r.Imports...), r.ExportDirectory) {
		if strings.IndexByte(name, 0) >= 0 || len(name) > 4095 || !utf8.ValidString(name) {
			return fmt.Errorf("transfer paths must be valid UTF-8 without NUL bytes, at most 4095 bytes")
		}
	}
	return nil
}

func validateExecutable(name string) error {
	base := name
	if strings.Contains(name, "/") {
		if path.Clean(name) != name || (path.Dir(name) != "/bin" && path.Dir(name) != "/usr/bin") {
			return fmt.Errorf("command must name a curated runtime executable in /bin or /usr/bin")
		}
		base = path.Base(name)
	}
	if base == "" || base == "." || base == ".." || strings.HasPrefix(base, "-") || len(base) > 255 {
		return fmt.Errorf("invalid curated runtime executable name")
	}
	for _, c := range []byte(base) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._+-", rune(c))) {
			return fmt.Errorf("invalid curated runtime executable name")
		}
	}
	return nil
}

func validSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range []byte(id) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
