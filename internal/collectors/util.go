package collectors

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
)

func num(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func isPerm(err error) bool { return errors.Is(err, fs.ErrPermission) }

// ignoreSet is a compiled ignore list, checked during a directory walk:
//
//	"/abs/path"   exact path (file or directory)
//	"/abs/glob*"  full-path glob
//	"/abs/dir/**" the directory and everything below it
//	"name"        base-name glob, anywhere
//	"name/**"     any directory with that base name, and its contents
//
// Recursive patterns are tested on directories only; the walk then skips the
// whole subtree, so each path costs a few comparisons.
type ignoreSet struct {
	exact    map[string]bool
	dirGlobs []string // recursive, full path
	dirNames []string // recursive, base name
	globs    []string // full-path globs
	names    []string // base-name globs
}

func newIgnoreSet(patterns []string) *ignoreSet {
	s := &ignoreSet{exact: map[string]bool{}}
	for _, g := range patterns {
		dir, recursive := strings.CutSuffix(g, "/**")
		abs := strings.HasPrefix(g, "/")
		glob := strings.ContainsAny(g, "*?[")
		switch {
		case recursive && abs && !strings.ContainsAny(dir, "*?["):
			s.exact[dir] = true
		case recursive && abs:
			s.dirGlobs = append(s.dirGlobs, dir)
		case recursive:
			s.dirNames = append(s.dirNames, dir)
		case abs && !glob:
			s.exact[g] = true
		case abs:
			s.globs = append(s.globs, g)
		default:
			s.names = append(s.names, g)
		}
	}
	return s
}

// match reports whether a path seen during the walk should be skipped.
func (s *ignoreSet) match(path string, isDir bool) bool {
	if s.exact[path] {
		return true
	}
	base := filepath.Base(path)
	if isDir {
		for _, g := range s.dirGlobs {
			if ok, _ := filepath.Match(g, path); ok {
				return true
			}
		}
		for _, g := range s.dirNames {
			if ok, _ := filepath.Match(g, base); ok {
				return true
			}
		}
	}
	for _, g := range s.globs {
		if ok, _ := filepath.Match(g, path); ok {
			return true
		}
	}
	for _, g := range s.names {
		if ok, _ := filepath.Match(g, base); ok {
			return true
		}
	}
	return false
}

// fileFinding builds the common part of a finding for a path on disk.
func fileFinding(kind model.Kind, path string, info fs.FileInfo) model.Finding {
	added, source, mtime := inspect.Times(path)
	return timedFinding(kind, path, info, added, source, mtime)
}

// entryFinding is fileFinding for a file found without following links.
func entryFinding(kind model.Kind, e *inspect.Entry) model.Finding {
	added, source, mtime := e.Times()
	return timedFinding(kind, e.Path, e.Info, added, source, mtime)
}

func timedFinding(kind model.Kind, path string, info fs.FileInfo, added time.Time, source string, mtime time.Time) model.Finding {
	f := model.Finding{Kind: kind, Subject: path}
	f.Added, f.AddedSource = added, source
	if f.Added.IsZero() {
		f.Added, f.AddedSource = info.ModTime(), "modified"
	}
	f.SetFact("size", inspect.HumanSize(info.Size()))
	f.SetFact("mode", inspect.ModeString(info.Mode()))
	f.SetFact("owner", inspect.Owner(info))
	if !mtime.IsZero() {
		f.SetFact("modified", mtime.Format(time.DateTime))
	}
	f.Fingerprint = strconv.FormatInt(info.Size(), 10) + ":" + strconv.FormatInt(info.ModTime().UnixNano(), 10)
	return f
}

// addContent inspects file contents and folds the result into f. A root
// scan adds contents and the hash only for files its user could read; for
// the rest the fingerprint stays size and time.
func addContent(f *model.Finding, path string, info fs.FileInfo) inspect.Result {
	if !info.Mode().IsRegular() {
		return inspect.Result{}
	}
	r := inspect.Inspect(path, info.Size())
	addResult(f, r)
	if info.Size() < 64<<20 {
		addHash(f, inspect.SharedSHA256(path))
	}
	return r
}

// addEntryContent is addContent for a file found without following links,
// open as file.
func addEntryContent(f *model.Finding, e *inspect.Entry, file *os.File, r inspect.Result) {
	addResult(f, r)
	if e.Info.Size() < 64<<20 {
		addHash(f, inspect.SharedSHA256File(file, e.Path))
	}
}

func addResult(f *model.Finding, r inspect.Result) {
	for _, fl := range r.Flags() {
		f.AddFlag(fl)
	}
	if r.Type != "" {
		t := string(r.Type)
		if r.Interpreter != "" {
			t += " (" + r.Interpreter + ")"
		}
		f.SetFact("type", t)
	}
	f.Preview = r.Preview
}

func addHash(f *model.Finding, sum string) {
	if sum != "" {
		f.SetFact("sha256", sum)
		f.Fingerprint = sum
	}
}

func readlink(path string) string {
	t, _ := os.Readlink(path)
	return t
}

// The Omarchy installation window: from the creation of /etc/machine-id
// (the installer's first steps) to the last line of Omarchy's install log.
var installWindow = sync.OnceValues(func() (time.Time, time.Time) {
	start, _, ok := inspect.Born("/etc/machine-id")
	info, err := os.Stat("/var/log/omarchy-install.log")
	if !ok || err != nil || info.ModTime().Before(start) || info.ModTime().Sub(start) > 6*time.Hour {
		return time.Time{}, time.Time{}
	}
	return start.Add(-10 * time.Minute), info.ModTime().Add(2 * time.Minute)
})

// installedWithOmarchy reports whether a file was created while Omarchy was
// being installed and has not changed since: the installer wrote it.
func installedWithOmarchy(path string) (time.Time, bool) {
	start, end := installWindow()
	if start.IsZero() {
		return time.Time{}, false
	}
	born, changed, ok := inspect.Born(path)
	if !ok || born.Before(start) || born.After(end) || changed.After(end) {
		return time.Time{}, false
	}
	return born, true
}
