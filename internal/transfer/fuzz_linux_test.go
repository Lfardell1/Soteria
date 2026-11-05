package transfer

import (
	"bytes"
	"context"
	"io"
	"path"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzPathValidation(f *testing.F) {
	for _, name := range []string{"", ".", "..", "a", "a/b", "/a", "a//b", "a/../b", "a\\b", "a\x00b", string([]byte{0xff}), strings.Repeat("a/", maxDepth) + "file"} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if err := validName(name); err != nil {
			return
		}
		if !utf8.ValidString(name) || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00") || len(name) > maxPathBytes {
			t.Fatalf("accepted unsafe name %q", name)
		}
		parts := strings.Split(name, "/")
		if len(parts) > maxDepth {
			t.Fatal("accepted excessive depth")
		}
		for _, component := range parts {
			if component == "" || component == "." || component == ".." || len(component) > maxComponentBytes {
				t.Fatalf("accepted unsafe component %q", component)
			}
		}
	})
}

func FuzzFrameParser(f *testing.F) {
	f.Add(oneFileStream(f, "file", []byte("binary\x00data")))
	f.Add(encoded(f, wireRecord{frame: frame{kind: directoryEntry, name: "dir"}}, wireRecord{frame: frame{kind: endDirectory}}, wireRecord{frame: frame{kind: endStream}}))
	f.Add([]byte(streamMagic))
	f.Add([]byte("invalid"))
	f.Add(encoded(f, wireRecord{frame: frame{kind: fileEntry, name: "../bad", size: ^uint64(0)}}))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 256*1024 {
			return
		}
		r := streamReader{ctx: context.Background(), r: bytes.NewReader(wire)}
		var magic [len(streamMagic)]byte
		if err := r.full(magic[:]); err != nil || string(magic[:]) != streamMagic {
			return
		}
		quota := budget{limits: Limits{MaxBytes: 65536, MaxFiles: 128}}
		stack := []treeOrder{{}}
		buffer := make([]byte, 512)
		for steps := 0; steps < 3*128+1; steps++ {
			entry, err := r.next()
			if err != nil {
				return
			}
			switch entry.kind {
			case endStream:
				if len(stack) == 1 {
					_ = r.eof()
				}
				return
			case endDirectory:
				if len(stack) == 1 {
					return
				}
				stack = stack[:len(stack)-1]
			case directoryEntry, fileEntry:
				if err := quota.add(entry.size); err != nil {
					return
				}
				if _, err := stack[len(stack)-1].accept(entry.name); err != nil {
					return
				}
				if err := validName(entry.name); err != nil {
					t.Fatal("parser returned an invalid name")
				}
				if entry.kind == directoryEntry {
					stack = append(stack, treeOrder{path: entry.name})
					continue
				}
				if err := copySized(r, io.Discard, entry.size, buffer); err != nil {
					return
				}
				commit, err := r.next()
				if err != nil || commit.kind != endFile {
					return
				}
			default:
				return
			}
		}
		t.Fatal("parser exceeded entry-derived frame bound")
	})
}
