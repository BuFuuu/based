package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// A root scan hands its result to the user who started it. Root reads every
// file it needs to judge, but what it hands over depends on whether that
// user could read the file themselves:
//
//	Full     they could: verdicts and contents (previews, commands, hashes)
//	Verdict  they could not: verdicts only (flags like "risky pattern" or
//	         "grants sudo without a password"), never text or hashes
//	Hidden   the path leads somewhere else through a link, into a file they
//	         could not read: nothing, so a planted link can't make root
//	         judge /etc/shadow for them
//
// Checks run on the opened file, so swapping a file after the check doesn't
// help. revealUID < 0 means no limit: a scan as yourself, or root keeping
// its own result.
var (
	revealUID  = -1
	revealGIDs map[uint32]bool
)

type Access int

const (
	Hidden Access = iota
	Verdict
	Full
)

// LimitContentTo restricts file contents in the result to what this user
// could read.
func LimitContentTo(uid int, gids []int) {
	revealUID = uid
	revealGIDs = map[uint32]bool{}
	for _, g := range gids {
		revealGIDs[uint32(g)] = true
	}
}

// Limited reports whether a scan hands its result to another user.
func Limited() bool { return revealUID >= 0 }

// ErrNotYours is returned for a file whose contents the user may not see.
var ErrNotYours = errors.New("not readable by the user the scan reports to")

// AccessOf says what the result may hold about the open file f, found at
// path.
func AccessOf(f *os.File, path string) Access {
	if revealUID < 0 {
		return Full
	}
	real := realPath(f)
	if real == "" {
		return Hidden
	}
	if userCanRead(f, real) {
		return Full
	}
	if filepath.IsAbs(path) && filepath.Clean(path) == real {
		return Verdict
	}
	return Hidden
}

// Shareable reports whether the user the scan reports to could read the
// file (or list the folder) behind an open handle.
func Shareable(f *os.File) bool {
	return revealUID < 0 || userCanRead(f, realPath(f))
}

// realPath is where an open file really is, links resolved, or "".
func realPath(f *os.File) string {
	real, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil || !filepath.IsAbs(real) || strings.HasSuffix(real, " (deleted)") {
		return ""
	}
	return real
}

// userCanRead reports whether the user the scan reports to could read the
// file: its own read bit, and the search bit of every folder on its real
// path, which they need to reach it.
func userCanRead(f *os.File, real string) bool {
	if real == "" {
		return false
	}
	info, err := f.Stat()
	if err != nil || !allowed(info, 0o4) {
		return false
	}
	for dir := filepath.Dir(real); ; dir = filepath.Dir(dir) {
		di, err := os.Stat(dir)
		if err != nil || !di.IsDir() || !allowed(di, 0o1) {
			return false
		}
		if dir == "/" {
			return true
		}
	}
}

// allowed reports whether the user the scan reports to has the access bits
// (4 read, 1 search) on a file.
func allowed(info fs.FileInfo, bits fs.FileMode) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	perm := info.Mode().Perm()
	switch {
	case int(st.Uid) == revealUID:
		return perm&(bits<<6) != 0
	case revealGIDs[st.Gid]:
		return perm&(bits<<3) != 0
	}
	return perm&bits != 0
}

// openRead opens a file for reading without blocking on a FIFO swapped in
// for it.
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// ReadFile reads up to max bytes of a file for the result: only files the
// user could read themselves.
func ReadFile(path string, max int64) ([]byte, error) {
	b, acc, err := Read(path, max)
	if err == nil && acc != Full {
		return nil, ErrNotYours
	}
	return b, err
}

// Read reads up to max bytes of a file to judge it, and says what the
// result may hold about it. A Verdict file's bytes must only feed
// decisions, never text in the result.
func Read(path string, max int64) ([]byte, Access, error) {
	f, err := openRead(path)
	if err != nil {
		return nil, Hidden, err
	}
	defer f.Close()
	acc := AccessOf(f, path)
	if acc == Hidden {
		return nil, Hidden, ErrNotYours
	}
	b, err := io.ReadAll(io.LimitReader(f, max))
	return b, acc, err
}

// Shared reports whether the result may hold the contents of a file (or
// the names in a folder).
func Shared(path string) bool {
	if revealUID < 0 {
		return true
	}
	f, err := openRead(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return AccessOf(f, path) == Full
}

// SharedSHA256 hashes a file for the result, or returns "" when the user
// couldn't read it: a hash lets anyone confirm a guess at the contents.
func SharedSHA256(path string) string {
	f, err := openRead(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	return SharedSHA256File(f, path)
}

// SharedSHA256File is SharedSHA256 on an open file.
func SharedSHA256File(f *os.File, path string) string {
	if AccessOf(f, path) != Full {
		return ""
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, info.Size())); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
