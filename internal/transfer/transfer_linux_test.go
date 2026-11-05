package transfer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var testLimits = Limits{MaxBytes: 8 << 20, MaxFiles: 1024}

type wireRecord struct {
	frame
	data []byte
}

func encoded(t testing.TB, records ...wireRecord) []byte {
	t.Helper()
	var out bytes.Buffer
	out.WriteString(streamMagic)
	for _, record := range records {
		if err := writeFrame(context.Background(), &out, record.frame); err != nil {
			t.Fatal(err)
		}
		out.Write(record.data)
	}
	return out.Bytes()
}

func fileRecords(name string, data []byte) []wireRecord {
	return []wireRecord{
		{frame: frame{kind: fileEntry, name: name, size: uint64(len(data))}, data: data},
		{frame: frame{kind: endFile}},
	}
}

func oneFileStream(t testing.TB, name string, data []byte) []byte {
	t.Helper()
	records := append(fileRecords(name, data), wireRecord{frame: frame{kind: endStream}})
	return encoded(t, records...)
}

func putFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t testing.TB, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func requireEmpty(t testing.TB, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected visible output: %v", entries)
	}
}

func requireContents(t testing.TB, path string, expected []byte) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("contents differ: got %d bytes, want %d", len(actual), len(expected))
	}
}

func receiveFailure(t testing.TB, data []byte, destination string, limits Limits) *ReceiveError {
	t.Helper()
	err := Receive(context.Background(), bytes.NewReader(data), destination, limits)
	var partial *ReceiveError
	if !errors.As(err, &partial) {
		t.Fatalf("expected ReceiveError, got %v", err)
	}
	return partial
}

func TestRoundTripBinaryTreeAndPermissions(t *testing.T) {
	source := t.TempDir()
	tree := filepath.Join(source, "tree")
	mkdir(t, tree)
	mkdir(t, filepath.Join(tree, "empty"))
	mkdir(t, filepath.Join(tree, "nested"))
	data := make([]byte, 3*bufferBytes+17)
	for i := range data {
		data[i] = byte(i)
	}
	putFile(t, filepath.Join(tree, "nested", "binary"), data)
	putFile(t, filepath.Join(tree, "zero"), nil)
	putFile(t, filepath.Join(tree, ".hidden"), []byte("hidden"))
	putFile(t, filepath.Join(source, "space and\nline"), []byte("odd but valid"))
	if err := os.Chmod(filepath.Join(tree, "nested", "binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	sources, err := Imports([]string{tree, filepath.Join(source, "space and\nline")})
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := Send(context.Background(), &wire, sources, testLimits); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	rootBefore, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := Receive(context.Background(), bytes.NewReader(wire.Bytes()), destination, testLimits); err != nil {
		t.Fatal(err)
	}
	requireContents(t, filepath.Join(destination, "tree", "nested", "binary"), data)
	requireContents(t, filepath.Join(destination, "tree", "zero"), nil)
	requireContents(t, filepath.Join(destination, "tree", ".hidden"), []byte("hidden"))
	requireContents(t, filepath.Join(destination, "space and\nline"), []byte("odd but valid"))
	if err := filepath.WalkDir(destination, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if path == destination {
			if info.Mode() != rootBefore.Mode() {
				t.Error("modified existing destination root permissions")
			}
			return nil
		}
		want := os.FileMode(0o600)
		if entry.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			t.Errorf("mode %s: got %v, want %v", path, info.Mode(), want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	outputs, err := Outputs(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 2 || outputs[0].Name != "space and\nline" || outputs[1].Name != "tree" {
		t.Fatalf("unexpected outputs: %#v", outputs)
	}
	wire.Reset()
	if err := Send(context.Background(), &wire, outputs, testLimits); err != nil {
		t.Fatal(err)
	}
	if err := Receive(context.Background(), &wire, t.TempDir(), testLimits); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyTransfer(t *testing.T) {
	var wire bytes.Buffer
	if err := Send(context.Background(), &wire, nil, testLimits); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := Receive(context.Background(), &wire, destination, testLimits); err != nil {
		t.Fatal(err)
	}
	requireEmpty(t, destination)
	outputs, err := Outputs(destination)
	if err != nil || len(outputs) != 0 {
		t.Fatalf("empty outputs: %v, %v", outputs, err)
	}
}

func TestImportsRejectUncleanAndCollidingPaths(t *testing.T) {
	dir := t.TempDir()
	putFile(t, filepath.Join(dir, "a"), []byte("a"))
	mkdir(t, filepath.Join(dir, "sub"))
	putFile(t, filepath.Join(dir, "sub", "a"), []byte("other"))
	for _, input := range []string{"", ".", "/", "..", "../a", "./a", dir + "/", dir + "//a", dir + "/sub/../a", "a\\b", "a\x00b"} {
		t.Run(strconv.Quote(input), func(t *testing.T) {
			if _, err := Imports([]string{input}); err == nil {
				t.Fatalf("accepted %q", input)
			}
		})
	}
	if _, err := Imports([]string{filepath.Join(dir, "a"), filepath.Join(dir, "sub", "a")}); err == nil {
		t.Fatal("accepted basename collision")
	}
	if _, err := Imports([]string{filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("accepted missing source")
	}
	if _, err := Imports(nil); err != nil {
		t.Fatal(err)
	}
}

func TestSendRevalidatesForgedSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "safe")
	putFile(t, path, nil)
	for _, sources := range [][]Source{
		{{Path: path, Name: "../bad"}},
		{{Path: path, Name: "dir/file"}},
		{{Path: path, Name: "/absolute"}},
		{{Path: path + "/../safe", Name: "safe"}},
		{{Path: path, Name: "same"}, {Path: path, Name: "same"}},
	} {
		var wire bytes.Buffer
		if err := Send(context.Background(), &wire, sources, testLimits); err == nil {
			t.Fatalf("accepted %#v", sources)
		}
		if wire.Len() != 0 {
			t.Fatal("wrote stream before basic source validation")
		}
	}
}

func TestPathValidation(t *testing.T) {
	bad := []string{"", ".", "..", "./a", "a/.", "a/..", "../a", "a/../b", "a//b", "a/./b", "a/", "/a", "//a", "\\a", "a\\b", "a\x00b", string([]byte{0xff}), strings.Repeat("a", 256), strings.Repeat("d/", maxDepth) + "f", strings.Repeat("a", maxPathBytes+1)}
	for _, name := range bad {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			if err := validName(name); err == nil {
				t.Fatal("accepted unsafe name")
			}
			wire := encoded(t, wireRecord{frame: frame{kind: fileEntry, name: name}}, wireRecord{frame: frame{kind: endFile}}, wireRecord{frame: frame{kind: endStream}})
			destination := t.TempDir()
			partial := receiveFailure(t, wire, destination, testLimits)
			if partial.PublishedFiles != 0 || partial.CreatedDirectories != 0 {
				t.Fatal("unsafe name caused visible output")
			}
			requireEmpty(t, destination)
		})
	}
	for _, name := range []string{"a", ".hidden", "a b", "a\nb", "a/b", strings.Repeat("d/", maxDepth-1) + "f", strings.Repeat(strings.Repeat("a", 255)+"/", 15) + strings.Repeat("a", 255)} {
		if err := validName(name); err != nil {
			t.Fatalf("rejected normal name %q: %v", name, err)
		}
	}
}

func TestTreeDepthBound(t *testing.T) {
	for _, excessive := range []bool{false, true} {
		t.Run(strconv.FormatBool(excessive), func(t *testing.T) {
			directories := maxDepth - 1
			if excessive {
				directories++
			}
			var records []wireRecord
			name := "d"
			for i := 0; i < directories; i++ {
				records = append(records, wireRecord{frame: frame{kind: directoryEntry, name: name}})
				name += "/d"
			}
			records = append(records, fileRecords(strings.TrimSuffix(name, "d")+"file", []byte("deep"))...)
			for i := 0; i < directories; i++ {
				records = append(records, wireRecord{frame: frame{kind: endDirectory}})
			}
			records = append(records, wireRecord{frame: frame{kind: endStream}})
			destination := t.TempDir()
			err := Receive(context.Background(), bytes.NewReader(encoded(t, records...)), destination, testLimits)
			if excessive {
				if !errors.Is(err, ErrLimit) {
					t.Fatalf("accepted excessive depth: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	source := filepath.Join(t.TempDir(), "tree")
	mkdir(t, source)
	path := source
	for i := 1; i < maxDepth; i++ {
		path = filepath.Join(path, "d")
		mkdir(t, path)
	}
	putFile(t, filepath.Join(path, "too-deep"), nil)
	if err := Send(context.Background(), io.Discard, []Source{{Path: source, Name: "tree"}}, testLimits); !errors.Is(err, ErrLimit) {
		t.Fatalf("Send excessive depth: %v", err)
	}
}

func TestReceiveRejectsMalformedFrames(t *testing.T) {
	valid := oneFileStream(t, "file", []byte("data"))
	oversizedName := append([]byte(streamMagic), make([]byte, headerBytes)...)
	oversizedName[len(streamMagic)] = fileEntry
	binary.BigEndian.PutUint16(oversizedName[len(streamMagic)+1:], math.MaxUint16)
	cases := map[string][]byte{
		"magic":              []byte("not a transfer"),
		"unknown kind":       encoded(t, wireRecord{frame: frame{kind: 255}}),
		"directory size":     encoded(t, wireRecord{frame: frame{kind: directoryEntry, name: "d", size: 1}}),
		"control name":       encoded(t, wireRecord{frame: frame{kind: endStream, name: "a"}}),
		"control size":       encoded(t, wireRecord{frame: frame{kind: endStream, size: 1}}),
		"unexpected commit":  encoded(t, wireRecord{frame: frame{kind: endFile}}),
		"unexpected dir end": encoded(t, wireRecord{frame: frame{kind: endDirectory}}),
		"unclosed dir":       encoded(t, wireRecord{frame: frame{kind: directoryEntry, name: "d"}}, wireRecord{frame: frame{kind: endStream}}),
		"missing commit":     encoded(t, wireRecord{frame: frame{kind: fileEntry, name: "f", size: 1}, data: []byte("x")}, wireRecord{frame: frame{kind: endStream}}),
		"extra file bytes":   encoded(t, wireRecord{frame: frame{kind: fileEntry, name: "f", size: 1}, data: []byte("xx")}, wireRecord{frame: frame{kind: endFile}}),
		"oversized name":     oversizedName,
		"trailing bytes":     append(bytes.Clone(valid), 1),
		"second stream":      append(bytes.Clone(valid), valid...),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			partial := receiveFailure(t, wire, t.TempDir(), testLimits)
			if !errors.Is(partial, ErrProtocol) {
				t.Fatalf("expected protocol error, got %v", partial)
			}
		})
	}
}

func TestReceiveRejectsDuplicateAndConflictingTrees(t *testing.T) {
	file := func(name string) []wireRecord { return fileRecords(name, nil) }
	dir := func(name string) wireRecord { return wireRecord{frame: frame{kind: directoryEntry, name: name}} }
	endDir := wireRecord{frame: frame{kind: endDirectory}}
	cases := map[string][]wireRecord{
		"duplicate files": append(file("a"), file("a")...),
		"unsorted files":  append(file("b"), file("a")...),
		"file then dir":   append(file("a"), dir("a")),
		"dir then file":   append([]wireRecord{dir("a"), endDir}, file("a")...),
		"duplicate dirs":  {dir("a"), endDir, dir("a")},
		"implicit parent": file("missing/file"),
		"file as parent":  append(file("a"), file("a/file")...),
		"wrong parent":    append([]wireRecord{dir("a")}, file("b/file")...),
		"reenter dir":     append([]wireRecord{dir("a"), endDir}, file("a/file")...),
	}
	for name, records := range cases {
		t.Run(name, func(t *testing.T) {
			records = append(records, wireRecord{frame: frame{kind: endStream}})
			partial := receiveFailure(t, encoded(t, records...), t.TempDir(), testLimits)
			if !errors.Is(partial, ErrProtocol) {
				t.Fatalf("expected duplicate/conflict protocol error, got %v", partial)
			}
		})
	}
}

func TestQuotas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	putFile(t, path, []byte("12345"))
	source := []Source{{Path: path, Name: "file"}}
	for _, limits := range []Limits{{}, {MaxBytes: 1}, {MaxFiles: 1}, {MaxBytes: 4, MaxFiles: 1}} {
		if err := Send(context.Background(), io.Discard, source, limits); !errors.Is(err, ErrLimit) {
			t.Fatalf("Send limits %#v: %v", limits, err)
		}
		destination := t.TempDir()
		partial := receiveFailure(t, oneFileStream(t, "file", []byte("12345")), destination, limits)
		if !errors.Is(partial, ErrLimit) || partial.PublishedFiles != 0 {
			t.Fatalf("Receive limits %#v: %v", limits, partial)
		}
		requireEmpty(t, destination)
	}
	if err := Send(context.Background(), io.Discard, source, Limits{MaxBytes: 5, MaxFiles: 1}); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(t.TempDir(), "tree")
	mkdir(t, tree)
	putFile(t, filepath.Join(tree, "child"), nil)
	if err := Send(context.Background(), io.Discard, []Source{{Path: tree, Name: "tree"}}, Limits{MaxBytes: 1, MaxFiles: 1}); !errors.Is(err, ErrLimit) {
		t.Fatalf("directory did not consume quota: %v", err)
	}
	records := []wireRecord{{frame: frame{kind: directoryEntry, name: "tree"}}}
	records = append(records, fileRecords("tree/child", nil)...)
	records = append(records, wireRecord{frame: frame{kind: endDirectory}}, wireRecord{frame: frame{kind: endStream}})
	partial := receiveFailure(t, encoded(t, records...), t.TempDir(), Limits{MaxBytes: 1, MaxFiles: 1})
	if !errors.Is(partial, ErrLimit) || partial.CreatedDirectories != 1 || partial.PublishedFiles != 0 {
		t.Fatalf("directory quota/partial count: %v", partial)
	}
	huge := encoded(t, wireRecord{frame: frame{kind: fileEntry, name: "huge", size: math.MaxUint64}})
	partial = receiveFailure(t, huge, t.TempDir(), Limits{MaxBytes: math.MaxUint64, MaxFiles: 1})
	if !errors.Is(partial, ErrLimit) {
		t.Fatalf("accepted uint64 file size: %v", partial)
	}
	quota := budget{limits: Limits{MaxBytes: math.MaxUint64, MaxFiles: math.MaxUint64}, files: maxEntries}
	if !errors.Is(quota.add(0), ErrLimit) {
		t.Fatal("hard entry bound was not enforced")
	}
	records = append(fileRecords("a", []byte("123")), fileRecords("b", []byte("456"))...)
	records = append(records, wireRecord{frame: frame{kind: endStream}})
	partial = receiveFailure(t, encoded(t, records...), t.TempDir(), Limits{MaxBytes: 5, MaxFiles: 3})
	if !errors.Is(partial, ErrLimit) || partial.PublishedFiles != 1 {
		t.Fatalf("aggregate byte quota: %v", partial)
	}
}

func TestNoOverwriteAndPartialOutput(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "hardlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			destination := t.TempDir()
			victim := filepath.Join(t.TempDir(), "victim")
			putFile(t, victim, []byte("original"))
			target := filepath.Join(destination, "b")
			switch kind {
			case "file":
				putFile(t, target, []byte("original"))
			case "symlink":
				if err := os.Symlink(victim, target); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(victim, target); err != nil {
					t.Fatal(err)
				}
			case "directory":
				mkdir(t, target)
			}
			records := append(fileRecords("a", []byte("published first")), fileRecords("b", []byte("must not replace"))...)
			records = append(records, wireRecord{frame: frame{kind: endStream}})
			partial := receiveFailure(t, encoded(t, records...), destination, testLimits)
			if !errors.Is(partial, os.ErrExist) || partial.PublishedFiles != 1 || partial.CreatedDirectories != 0 {
				t.Fatalf("wrong partial/no-overwrite result: %v", partial)
			}
			requireContents(t, filepath.Join(destination, "a"), []byte("published first"))
			requireContents(t, victim, []byte("original"))
			if kind == "file" || kind == "hardlink" {
				requireContents(t, target, []byte("original"))
			}
			entries, err := os.ReadDir(destination)
			if err != nil || len(entries) != 2 {
				t.Fatalf("temporary output leaked: %v, %v", entries, err)
			}
		})
	}
	t.Run("no directory merge", func(t *testing.T) {
		destination := t.TempDir()
		mkdir(t, filepath.Join(destination, "d"))
		putFile(t, filepath.Join(destination, "d", "existing"), []byte("keep"))
		wire := encoded(t, wireRecord{frame: frame{kind: directoryEntry, name: "d"}})
		partial := receiveFailure(t, wire, destination, testLimits)
		if !errors.Is(partial, os.ErrExist) || partial.CreatedDirectories != 0 {
			t.Fatal(partial)
		}
		requireContents(t, filepath.Join(destination, "d", "existing"), []byte("keep"))
	})
}

func TestDestinationMustExistAndMayBeAuthorizedFD(t *testing.T) {
	parent := t.TempDir()
	missing := filepath.Join(parent, "missing")
	partial := receiveFailure(t, oneFileStream(t, "f", nil), missing, testLimits)
	if !errors.Is(partial, os.ErrNotExist) {
		t.Fatal(partial)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created destination: %v", err)
	}
	putFile(t, filepath.Join(parent, "not-directory"), nil)
	partial = receiveFailure(t, oneFileStream(t, "f", nil), filepath.Join(parent, "not-directory"), testLimits)
	if !errors.Is(partial, ErrUnsafe) {
		t.Fatal(partial)
	}
	destination := t.TempDir()
	f, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fdPath := "/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)
	if err := Receive(context.Background(), bytes.NewReader(oneFileStream(t, "f", []byte("via descriptor"))), fdPath, testLimits); err != nil {
		t.Fatal(err)
	}
	requireContents(t, filepath.Join(destination, "f"), []byte("via descriptor"))
	for _, name := range []string{fdPath + "/.", fdPath + "/child", "/proc/self/fd/01", "/proc/self/fd/-1", "/proc/self/fd/1/"} {
		if authorizedFDPath(name) {
			t.Fatalf("accepted non-exact fd root %q", name)
		}
	}
}

func TestOutputsFromAuthorizedDirectoryFD(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "outputs")
	mkdir(t, source)
	putFile(t, filepath.Join(source, "file"), []byte("descriptor export"))
	mkdir(t, filepath.Join(source, "tree"))
	putFile(t, filepath.Join(source, "tree", "child"), []byte("child"))
	directory, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	fdPath := "/proc/self/fd/" + strconv.FormatUint(uint64(directory.Fd()), 10)
	// Move the selected root away and replace its old pathname. Outputs and
	// Send must keep using the explicitly authorized descriptor's directory.
	if err := os.Rename(source, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	mkdir(t, source)
	putFile(t, filepath.Join(source, "wrong"), []byte("do not export"))
	sources, err := Outputs(fdPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].Name != "file" || sources[1].Name != "tree" {
		t.Fatalf("wrong fd-root outputs: %#v", sources)
	}
	var wire bytes.Buffer
	if err := Send(context.Background(), &wire, sources, testLimits); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := Receive(context.Background(), &wire, destination, testLimits); err != nil {
		t.Fatal(err)
	}
	requireContents(t, filepath.Join(destination, "file"), []byte("descriptor export"))
	requireContents(t, filepath.Join(destination, "tree", "child"), []byte("child"))
	if _, err := Imports([]string{fdPath + "/file"}); err == nil {
		t.Fatal("Imports implicitly allowed proc-fd symlinks")
	}
	if err := os.Symlink(source, filepath.Join(base, "moved", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Outputs(fdPath); err == nil {
		t.Fatal("fd-root Outputs followed a child symlink")
	}
	if err := Send(context.Background(), io.Discard, []Source{{Path: fdPath + "/link/wrong", Name: "wrong"}}, testLimits); err == nil {
		t.Fatal("fd-root Send followed an intermediate symlink")
	}
}

func TestAuthorizedFDRootRejectsSpecialAndRegularFiles(t *testing.T) {
	base := t.TempDir()
	regular := filepath.Join(base, "file")
	putFile(t, regular, nil)
	fifo := filepath.Join(base, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{regular, fifo, "/dev/null"} {
		fd, err := unix.Open(name, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), name)
		fdPath := "/proc/self/fd/" + strconv.Itoa(fd)
		if err := Receive(context.Background(), bytes.NewReader(encoded(t, wireRecord{frame: frame{kind: endStream}})), fdPath, testLimits); !errors.Is(err, ErrUnsafe) {
			t.Errorf("Receive accepted a nondirectory fd root %s: %v", name, err)
		}
		if _, err := Outputs(fdPath); !errors.Is(err, ErrUnsafe) {
			t.Errorf("Outputs accepted a nondirectory fd root %s: %v", name, err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSymlinkSourcesAndDestinations(t *testing.T) {
	base := t.TempDir()
	mkdir(t, filepath.Join(base, "real"))
	putFile(t, filepath.Join(base, "real", "file"), []byte("must not follow"))
	for name, target := range map[string]string{"file-link": filepath.Join(base, "real", "file"), "dir-link": filepath.Join(base, "real")} {
		if err := os.Symlink(target, filepath.Join(base, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(base, "file-link"), filepath.Join(base, "dir-link"), filepath.Join(base, "dir-link", "file")} {
		if _, err := Imports([]string{path}); err == nil {
			t.Fatalf("Imports followed %s", path)
		}
		if err := Send(context.Background(), io.Discard, []Source{{Path: path, Name: "input"}}, testLimits); err == nil {
			t.Fatalf("Send followed %s", path)
		}
	}
	if _, err := Outputs(filepath.Join(base, "dir-link")); err == nil {
		t.Fatal("Outputs followed root symlink")
	}
	tree := filepath.Join(base, "tree")
	mkdir(t, tree)
	if err := os.Symlink(filepath.Join(base, "real", "file"), filepath.Join(tree, "link")); err != nil {
		t.Fatal(err)
	}
	if err := Send(context.Background(), io.Discard, []Source{{Path: tree, Name: "tree"}}, testLimits); err == nil {
		t.Fatal("Send followed nested symlink")
	}
	if _, err := Outputs(tree); err == nil {
		t.Fatal("Outputs accepted symlink entry")
	}
	for _, destination := range []string{filepath.Join(base, "dir-link"), filepath.Join(base, "dir-link", "missing")} {
		receiveFailure(t, oneFileStream(t, "output", []byte("no")), destination, testLimits)
	}
	requireContents(t, filepath.Join(base, "real", "file"), []byte("must not follow"))
	if _, err := os.Lstat(filepath.Join(base, "real", "output")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("destination symlink was followed")
	}
}

func TestRejectSpecialFilesHardlinksAndPrivilegedMetadata(t *testing.T) {
	base := t.TempDir()
	regular := filepath.Join(base, "regular")
	putFile(t, regular, nil)
	linked := filepath.Join(base, "linked")
	if err := os.Link(regular, linked); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(base, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(base, "socket")
	socket, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	for _, path := range []string{regular, linked, fifo, socketPath, "/dev/null"} {
		if _, err := Imports([]string{path}); err == nil {
			t.Fatalf("Imports accepted unsafe type %s", path)
		}
		if err := Send(context.Background(), io.Discard, []Source{{Path: path, Name: "input"}}, testLimits); err == nil {
			t.Fatalf("Send accepted unsafe type %s", path)
		}
	}
	for _, mode := range []os.FileMode{os.ModeSetuid | 0o700, os.ModeSetgid | 0o700, os.ModeSticky | 0o600} {
		path := filepath.Join(t.TempDir(), "metadata")
		putFile(t, path, nil)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Imports([]string{path}); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("accepted metadata %v: %v", mode, err)
		}
	}
	dir := filepath.Join(t.TempDir(), "sticky")
	mkdir(t, dir)
	if err := os.Chmod(dir, os.ModeSticky|0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Outputs(dir); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("accepted sticky directory: %v", err)
	}
}

func TestTruncationNeverPublishesIncompleteFile(t *testing.T) {
	data := []byte("binary\x00\xffcontents")
	wire := oneFileStream(t, "file", data)
	commitEnd := len(streamMagic) + headerBytes + len("file") + len(data) + headerBytes
	for cut := 0; cut < len(wire); cut++ {
		destination := t.TempDir()
		partial := receiveFailure(t, wire[:cut], destination, testLimits)
		if cut < commitEnd {
			if partial.PublishedFiles != 0 {
				t.Fatalf("published incomplete file at prefix %d: %v", cut, partial)
			}
			requireEmpty(t, destination)
		} else {
			if partial.PublishedFiles != 1 {
				t.Fatalf("lost partial publication count at prefix %d: %v", cut, partial)
			}
			requireContents(t, filepath.Join(destination, "file"), data)
		}
	}
}

type hookWriter struct {
	bytes.Buffer
	hook func([]byte)
}

func (w *hookWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if w.hook != nil {
		w.hook(p)
	}
	return n, err
}

func TestSourceMutationsFail(t *testing.T) {
	for _, mutation := range []string{"grow", "truncate", "rewrite", "hardlink", "replace with symlink", "rename directory", "add directory entry", "replace nested with symlink", "change already sent file"} {
		t.Run(mutation, func(t *testing.T) {
			base := t.TempDir()
			tree := filepath.Join(base, "tree")
			mkdir(t, tree)
			original := []byte("ORIGINAL")
			file := filepath.Join(tree, "a")
			putFile(t, file, original)
			putFile(t, filepath.Join(tree, "b"), []byte("SECOND"))
			outside := t.TempDir()
			victim := filepath.Join(outside, "victim")
			putFile(t, victim, []byte("EXTERNAL-SECRET"))
			mutated := false
			writer := &hookWriter{}
			writer.hook = func(p []byte) {
				if mutated {
					return
				}
				trigger := "tree/a"
				if mutation == "rename directory" || mutation == "add directory entry" || mutation == "replace nested with symlink" {
					trigger = "tree"
				}
				if mutation == "change already sent file" {
					trigger = "tree/b"
				}
				if !bytes.Equal(p, []byte(trigger)) {
					return
				}
				mutated = true
				switch mutation {
				case "grow":
					putFile(t, file, append(bytes.Clone(original), 'x'))
				case "truncate":
					putFile(t, file, nil)
				case "rewrite", "change already sent file":
					putFile(t, file, []byte("MUTATED!"))
				case "hardlink":
					if err := os.Link(file, filepath.Join(outside, "alias")); err != nil {
						t.Fatal(err)
					}
				case "replace with symlink", "replace nested with symlink":
					if err := os.Remove(file); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(victim, file); err != nil {
						t.Fatal(err)
					}
				case "rename directory":
					if err := os.Rename(tree, filepath.Join(base, "moved")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, tree); err != nil {
						t.Fatal(err)
					}
				case "add directory entry":
					putFile(t, filepath.Join(tree, "new"), nil)
				}
			}
			err := Send(context.Background(), writer, []Source{{Path: tree, Name: "tree"}}, testLimits)
			if err == nil || !mutated {
				t.Fatalf("mutation %s: mutated=%v, err=%v", mutation, mutated, err)
			}
			if bytes.Contains(writer.Bytes(), []byte("EXTERNAL-SECRET")) {
				t.Fatal("followed a source symlink during mutation")
			}
			requireContents(t, victim, []byte("EXTERNAL-SECRET"))
			partial := receiveFailure(t, writer.Bytes(), t.TempDir(), testLimits)
			if mutation != "change already sent file" && mutation != "rename directory" && partial.PublishedFiles > 0 {
				t.Fatalf("in-progress mutated file published: %v", partial)
			}
		})
	}
}

type hookReader struct {
	r    io.Reader
	hook func([]byte)
}

func (r hookReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if r.hook != nil {
		r.hook(p[:n])
	}
	return n, err
}

func TestDestinationDirectoryRenameAndSymlinkRace(t *testing.T) {
	destination := t.TempDir()
	outside := t.TempDir()
	putFile(t, filepath.Join(outside, "sentinel"), []byte("keep"))
	data := []byte("PAYLOAD-TRIGGER")
	records := []wireRecord{{frame: frame{kind: directoryEntry, name: "tree"}}}
	records = append(records, fileRecords("tree/file", data)...)
	records = append(records, wireRecord{frame: frame{kind: endDirectory}}, wireRecord{frame: frame{kind: endStream}})
	mutated := false
	reader := hookReader{r: bytes.NewReader(encoded(t, records...)), hook: func(p []byte) {
		if mutated || !bytes.Equal(p, data) {
			return
		}
		mutated = true
		if err := os.Rename(filepath.Join(destination, "tree"), filepath.Join(outside, "moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(destination, "tree")); err != nil {
			t.Fatal(err)
		}
	}}
	err := Receive(context.Background(), reader, destination, testLimits)
	var partial *ReceiveError
	if !mutated || !errors.As(err, &partial) || partial.PublishedFiles != 0 || partial.CreatedDirectories != 1 {
		t.Fatalf("rename race: mutated=%v, err=%v", mutated, err)
	}
	requireContents(t, filepath.Join(outside, "sentinel"), []byte("keep"))
	requireEmpty(t, filepath.Join(outside, "moved"))
	if _, err := os.Lstat(filepath.Join(outside, "file")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published outside destination: %v", err)
	}
}

func TestCleanupOnlyOwnAnonymousTemporary(t *testing.T) {
	destination := t.TempDir()
	putFile(t, filepath.Join(destination, ".soteria-transfer-existing"), []byte("keep"))
	data := oneFileStream(t, "file", []byte("incomplete"))
	partial := receiveFailure(t, data[:len(streamMagic)+headerBytes+len("file")+3], destination, testLimits)
	if partial.PublishedFiles != 0 {
		t.Fatal(partial)
	}
	requireContents(t, filepath.Join(destination, ".soteria-transfer-existing"), []byte("keep"))
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary cleanup affected unrelated entries: %v, %v", entries, err)
	}
}

func TestAtomicPublicationRace(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(strconv.FormatBool(symlink), func(t *testing.T) {
			destination := t.TempDir()
			victim := filepath.Join(t.TempDir(), "victim")
			putFile(t, victim, []byte("external sentinel"))
			data := []byte("PAYLOAD-ATOMIC")
			injected := false
			reader := hookReader{r: bytes.NewReader(oneFileStream(t, "file", data)), hook: func(p []byte) {
				if injected || !bytes.Equal(p, data) {
					return
				}
				injected = true
				// Even while data is being copied there must be no named,
				// partially written file for another process to observe.
				requireEmpty(t, destination)
				if symlink {
					if err := os.Symlink(victim, filepath.Join(destination, "file")); err != nil {
						t.Fatal(err)
					}
				} else {
					putFile(t, filepath.Join(destination, "file"), []byte("concurrent owner"))
				}
			}}
			err := Receive(context.Background(), reader, destination, testLimits)
			var partial *ReceiveError
			if !injected || !errors.Is(err, os.ErrExist) || !errors.As(err, &partial) || partial.PublishedFiles != 0 {
				t.Fatalf("no-replace race: injected=%v err=%v", injected, err)
			}
			requireContents(t, victim, []byte("external sentinel"))
			if !symlink {
				requireContents(t, filepath.Join(destination, "file"), []byte("concurrent owner"))
			}
		})
	}
}

func TestDestinationRootRemainsAnchoredAfterRename(t *testing.T) {
	base := t.TempDir()
	destination := filepath.Join(base, "selected")
	mkdir(t, destination)
	outside := t.TempDir()
	data := []byte("ROOT-RENAME-TRIGGER")
	mutated := false
	reader := hookReader{r: bytes.NewReader(oneFileStream(t, "file", data)), hook: func(p []byte) {
		if mutated || !bytes.Equal(p, data) {
			return
		}
		mutated = true
		if err := os.Rename(destination, filepath.Join(base, "selected-moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, destination); err != nil {
			t.Fatal(err)
		}
	}}
	if err := Receive(context.Background(), reader, destination, testLimits); err != nil {
		t.Fatal(err)
	}
	if !mutated {
		t.Fatal("rename seam was not exercised")
	}
	requireEmpty(t, outside)
	requireContents(t, filepath.Join(base, "selected-moved", "file"), data)
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type stalledReader struct{}

func (stalledReader) Read([]byte) (int, error) { return 0, nil }

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestBrokenStreamsAndNoProgress(t *testing.T) {
	if err := Send(context.Background(), shortWriter{}, nil, testLimits); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write not propagated: %v", err)
	}
	r, w := io.Pipe()
	failure := errors.New("broken pipe test")
	if err := r.CloseWithError(failure); err != nil {
		t.Fatal(err)
	}
	if err := Send(context.Background(), w, nil, testLimits); !errors.Is(err, failure) {
		t.Fatalf("pipe error not propagated: %v", err)
	}
	w.Close()
	path := filepath.Join(t.TempDir(), "file")
	putFile(t, path, bytes.Repeat([]byte("x"), 2*bufferBytes))
	var prefix bytes.Buffer
	brokenDuringData := writerFunc(func(p []byte) (int, error) {
		if len(p) == bufferBytes {
			prefix.Write(p[:7])
			return 7, failure
		}
		return prefix.Write(p)
	})
	if err := Send(context.Background(), brokenDuringData, []Source{{Path: path, Name: "file"}}, testLimits); !errors.Is(err, failure) {
		t.Fatalf("mid-file broken pipe was lost: %v", err)
	}
	destination := t.TempDir()
	partial := receiveFailure(t, prefix.Bytes(), destination, testLimits)
	if partial.PublishedFiles != 0 {
		t.Fatal("published file from a broken send")
	}
	requireEmpty(t, destination)
	for _, reader := range []io.Reader{errorReader{failure}, stalledReader{}} {
		destination := t.TempDir()
		err := Receive(context.Background(), reader, destination, testLimits)
		if !errors.Is(err, failure) && !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("reader error not propagated: %v", err)
		}
		requireEmpty(t, destination)
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Send(ctx, io.Discard, nil, testLimits); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := Receive(ctx, errorReader{errors.New("should not read")}, t.TempDir(), testLimits); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "file")
	data := bytes.Repeat([]byte("x"), bufferBytes*2)
	putFile(t, path, data)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	writer := &hookWriter{hook: func(p []byte) {
		if len(p) == bufferBytes {
			cancel()
		}
	}}
	if err := Send(ctx, writer, []Source{{Path: path, Name: "file"}}, testLimits); !errors.Is(err, context.Canceled) {
		t.Fatalf("send cancellation: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	reader := hookReader{r: bytes.NewReader(oneFileStream(t, "file", data)), hook: func(p []byte) {
		if len(p) == bufferBytes {
			cancel()
		}
	}}
	destination := t.TempDir()
	if err := Receive(ctx, reader, destination, testLimits); !errors.Is(err, context.Canceled) {
		t.Fatalf("receive cancellation: %v", err)
	}
	requireEmpty(t, destination)
}

func TestCallerClosesBlockedStreamOnCancellation(t *testing.T) {
	for _, sending := range []bool{false, true} {
		t.Run(strconv.FormatBool(sending), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, w := io.Pipe()
			defer r.Close()
			defer w.Close()
			finished := make(chan error, 1)
			started := make(chan struct{}, 1)
			if sending {
				writer := writerFunc(func(p []byte) (int, error) {
					select {
					case started <- struct{}{}:
					default:
					}
					return w.Write(p)
				})
				go func() { finished <- Send(ctx, writer, nil, testLimits) }()
			} else {
				destination := t.TempDir()
				reader := readerFunc(func(p []byte) (int, error) {
					select {
					case started <- struct{}{}:
					default:
					}
					return r.Read(p)
				})
				go func() { finished <- Receive(ctx, reader, destination, testLimits) }()
			}
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("transfer did not reach its blocking I/O operation")
			}
			cancel()
			if sending {
				r.CloseWithError(ctx.Err())
			} else {
				w.CloseWithError(ctx.Err())
			}
			select {
			case err := <-finished:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel returned %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stream did not stop after caller closed it")
			}
		})
	}
}
