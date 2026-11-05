// Package transfer copies explicitly selected regular-file trees using the
// process's existing credentials. It neither changes credentials nor mounts
// filesystems. Callers must drop credentials before invoking it when necessary.
//
// Transfers are not directory transactions: published files and newly created
// directories remain on failure. Only the incomplete, anonymous temporary file
// is discarded. No existing destination entry is replaced or merged.
//
// The wire format is a private, versioned, depth-first stream, not an archive.
// Paths and frames have fixed bounds; file data is copied in bounded chunks.
// Context cancellation is checked between I/O operations. The caller owns the
// stream and must close it to interrupt an already-blocked Read or Write, and
// must provide EOF after Send returns for Receive to complete.
package transfer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	streamMagic       = "SOTR\x00\x00\x00\x01"
	headerBytes       = 11 // kind, uint16 name length, uint64 file size; big endian
	maxPathBytes      = 4095
	maxComponentBytes = 255
	maxDepth          = 64
	maxEntries        = 100000
	bufferBytes       = 32 * 1024
)

const (
	endStream byte = iota
	directoryEntry
	fileEntry
	endFile
	endDirectory
)

var (
	ErrLimit    = errors.New("transfer limit exceeded")
	ErrUnsafe   = errors.New("unsafe transfer tree")
	ErrChanged  = errors.New("transfer source changed")
	ErrProtocol = errors.New("invalid transfer stream")
)

// Limits bounds aggregate file contents and tree entries. Both values must be
// nonzero. MaxFiles includes directories, with an additional hard ceiling of
// 100000 entries per stream. Names are limited to 4095 bytes, 255 bytes per
// component, and 64 components, independently of these limits.
type Limits struct {
	MaxBytes uint64
	MaxFiles uint64
}

// Source names one explicitly selected file or directory. Name must be a single
// normalized basename; Path is a clean host path, not a path from the stream.
// Sources are revalidated by Send, including when constructed without Imports.
// Outputs may use an explicit /proc/self/fd/N directory root; that descriptor
// must remain open until Send returns.
type Source struct {
	Path string
	Name string
}

// ReceiveError reports partial export, including errors after publication such
// as closing a file. Published entries are intentionally not rolled back.
type ReceiveError struct {
	PublishedFiles     uint64
	CreatedDirectories uint64
	Err                error
}

func (e *ReceiveError) Error() string {
	return fmt.Sprintf("receive: %d files published, %d directories created (partial output is not rolled back): %v", e.PublishedFiles, e.CreatedDirectories, e.Err)
}

func (e *ReceiveError) Unwrap() error { return e.Err }

type budget struct {
	limits Limits
	bytes  uint64
	files  uint64
}

func (l Limits) validate() error {
	if l.MaxBytes == 0 || l.MaxFiles == 0 {
		return fmt.Errorf("%w: byte and entry limits must both be nonzero", ErrLimit)
	}
	return nil
}

func (b *budget) add(size uint64) error {
	if b.files >= b.limits.MaxFiles || b.files >= maxEntries || size > b.limits.MaxBytes-b.bytes || size > math.MaxInt64 {
		return ErrLimit
	}
	b.files++
	b.bytes += size
	return nil
}

func validName(name string) error {
	if len(name) > maxPathBytes {
		return fmt.Errorf("%w: path exceeds %d bytes", ErrLimit, maxPathBytes)
	}
	if len(name) == 0 || !utf8.ValidString(name) || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name {
		return fmt.Errorf("%w: non-normal relative name %q", ErrUnsafe, name)
	}
	parts := strings.Split(name, "/")
	if len(parts) > maxDepth {
		return fmt.Errorf("%w: path depth exceeds %d", ErrLimit, maxDepth)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > maxComponentBytes {
			return fmt.Errorf("%w: invalid path component in %q", ErrUnsafe, name)
		}
	}
	return nil
}

func validBase(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("%w: source name %q is not a basename", ErrUnsafe, name)
	}
	return nil
}

func validHostPath(name string) error {
	if len(name) > maxPathBytes {
		return fmt.Errorf("%w: source/destination path exceeds %d bytes", ErrLimit, maxPathBytes)
	}
	if name == "" || strings.ContainsAny(name, "\\\x00") || filepath.Clean(name) != name {
		return fmt.Errorf("%w: source/destination path is not clean: %q", ErrUnsafe, name)
	}
	if name == "." || name == "/" {
		return nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if part == "" || part == "." || part == ".." || len(part) > maxComponentBytes {
			return fmt.Errorf("%w: invalid source/destination path %q", ErrUnsafe, name)
		}
	}
	return nil
}

type frame struct {
	kind byte
	name string
	size uint64
}

func writeBytes(ctx context.Context, w io.Writer, p []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := w.Write(p)
	if canceled := ctx.Err(); canceled != nil {
		return canceled
	}
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func writeFrame(ctx context.Context, w io.Writer, f frame) error {
	var header [headerBytes]byte
	header[0] = f.kind
	binary.BigEndian.PutUint16(header[1:3], uint16(len(f.name)))
	binary.BigEndian.PutUint64(header[3:], f.size)
	if err := writeBytes(ctx, w, header[:]); err != nil {
		return err
	}
	if f.name != "" {
		return writeBytes(ctx, w, []byte(f.name))
	}
	return nil
}

type streamReader struct {
	ctx context.Context
	r   io.Reader
}

func (r streamReader) full(p []byte) error {
	read, stalled := 0, 0
	for read < len(p) {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		n, err := r.r.Read(p[read:])
		if canceled := r.ctx.Err(); canceled != nil {
			return canceled
		}
		if n < 0 || n > len(p)-read {
			return errors.New("transfer: invalid reader byte count")
		}
		read += n
		if read == len(p) {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) && read != 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if n == 0 {
			stalled++
			if stalled == 100 {
				return io.ErrNoProgress
			}
		} else {
			stalled = 0
		}
	}
	return nil
}

func (r streamReader) next() (frame, error) {
	var header [headerBytes]byte
	if err := r.full(header[:]); err != nil {
		return frame{}, err
	}
	f := frame{kind: header[0], size: binary.BigEndian.Uint64(header[3:])}
	length := int(binary.BigEndian.Uint16(header[1:3]))
	switch f.kind {
	case endStream, endFile, endDirectory:
		if length != 0 || f.size != 0 {
			return frame{}, fmt.Errorf("%w: nonempty control frame", ErrProtocol)
		}
		return f, nil
	case directoryEntry, fileEntry:
		if length == 0 || length > maxPathBytes || (f.kind == directoryEntry && f.size != 0) {
			return frame{}, fmt.Errorf("%w: invalid entry header", ErrProtocol)
		}
	default:
		return frame{}, fmt.Errorf("%w: unknown frame kind %d", ErrProtocol, f.kind)
	}
	name := make([]byte, length)
	if err := r.full(name); err != nil {
		return frame{}, err
	}
	f.name = string(name)
	if err := validName(f.name); err != nil {
		return frame{}, err
	}
	return f, nil
}

func (r streamReader) eof() error {
	var extra [1]byte
	err := r.full(extra[:])
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: trailing bytes", ErrProtocol)
}

func copySized(r streamReader, w io.Writer, size uint64, buffer []byte) error {
	for size != 0 {
		n := min(size, uint64(len(buffer)))
		p := buffer[:int(n)]
		if err := r.full(p); err != nil {
			return err
		}
		if err := writeBytes(r.ctx, w, p); err != nil {
			return err
		}
		size -= n
	}
	return r.ctx.Err()
}

// treeOrder enforces a canonical depth-first stream. Strictly increasing sibling
// names reject duplicates and file/directory conflicts without an unbounded map.
type treeOrder struct {
	path string
	last string
}

func (o *treeOrder) accept(name string) (string, error) {
	parent, base := "", name
	if index := strings.LastIndexByte(name, '/'); index >= 0 {
		parent, base = name[:index], name[index+1:]
	}
	if parent != o.path || base <= o.last {
		return "", fmt.Errorf("%w: duplicate, conflicting, or out-of-order entry %q", ErrProtocol, name)
	}
	o.last = base
	return base, nil
}
