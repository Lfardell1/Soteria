//go:build linux

package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Every component is opened relative to an already checked descriptor. A
// privileged caller must not follow a replaceable parent or leaf symlink.
func openTrustedDirectory(path string, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("directory must be a clean absolute path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	if err := checkDirectory(dir, false); err != nil {
		_ = dir.Close()
		return nil, err
	}
	if path != "/" {
		for _, component := range strings.Split(path[1:], "/") {
			fd, err = unix.Openat(int(dir.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			_ = dir.Close()
			if err != nil {
				return nil, fmt.Errorf("open trusted directory component: %w", err)
			}
			dir = os.NewFile(uintptr(fd), component)
			if err := checkDirectory(dir, false); err != nil {
				_ = dir.Close()
				return nil, err
			}
		}
	}
	if err := checkDirectory(dir, private); err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

func checkDirectory(dir *os.File, private bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return err
	}
	return checkDirectoryStat(st, private)
}

func checkDirectoryStat(st unix.Stat_t, private bool) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 || st.Mode&0o7000 != 0 {
		return errors.New("directory must be root-owned, non-writable by group/others, and have no special mode bits")
	}
	if private && st.Mode&0o777 != 0o700 {
		return errors.New("runtime directory must have mode 0700")
	}
	return nil
}

func openTrustedRegularAt(dir *os.File, name string, maxBytes int64, private bool) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, errors.New("invalid file name")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := checkRegularStat(st, maxBytes, private); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func checkRegularStat(st unix.Stat_t, maxBytes int64, private bool) error {
	mode := st.Mode & 0o7777
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 {
		return errors.New("file must be a root-owned regular file with exactly one link")
	}
	if mode != 0o600 && (private || mode != 0o644) {
		return errors.New("file permissions must be 0600 (or 0644 for public metadata)")
	}
	if st.Size <= 0 || st.Size > maxBytes {
		return errors.New("file size is outside the permitted bound")
	}
	return nil
}

func readBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		clear(data)
		return nil, errors.New("file exceeds the permitted size")
	}
	return data, nil
}

// Decode field by field instead of encoding/json's permissive struct matching:
// field names are exact, every field is required, and duplicates/nulls fail.
func decodeStrictObject(data []byte, fields map[string]any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("expected a JSON object")
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("invalid JSON object")
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("invalid JSON field")
		}
		target, ok := fields[name]
		if !ok {
			return errors.New("unknown JSON field")
		}
		if seen[name] {
			return fmt.Errorf("duplicate JSON field %s", name)
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("invalid JSON field %s", name)
		}
		if err := json.Unmarshal(value, target); err != nil {
			return fmt.Errorf("invalid JSON field %s", name)
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return errors.New("invalid JSON object terminator")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	if len(seen) != len(fields) {
		return errors.New("missing required JSON field")
	}
	return nil
}
