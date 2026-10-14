package inspect

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Entry is a regular file found by WalkNoLinks. It is held by a handle
// that only names it, so every later look (opening, times, capabilities)
// is at this very file, even if its name is swapped meanwhile.
type Entry struct {
	Path string
	Info fs.FileInfo
	ref  *os.File // O_PATH: names the file, can't read it
}

// proc is the entry's handle as a path the kernel resolves to the file
// itself, not to whatever its name holds now.
func (e *Entry) proc() string { return "/proc/self/fd/" + strconv.Itoa(int(e.ref.Fd())) }

// Open opens the file for reading, with the usual permission checks.
func (e *Entry) Open() (*os.File, error) {
	fd, err := unix.Open(e.proc(), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: e.Path, Err: err}
	}
	return os.NewFile(uintptr(fd), e.Path), nil
}

// Times is Times for the entry.
func (e *Entry) Times() (added time.Time, source string, mtime time.Time) {
	var st unix.Statx_t
	if err := unix.Statx(int(e.ref.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_BTIME|unix.STATX_CTIME|unix.STATX_MTIME, &st); err != nil {
		return time.Time{}, "", time.Time{}
	}
	return statxTimes(&st)
}

// HasCaps is HasCaps for the entry.
func (e *Entry) HasCaps() bool {
	n, err := unix.Getxattr(e.proc(), "security.capability", nil)
	return err == nil && n > 0
}

// Close lets go of an entry from StatNoLinks.
func (e *Entry) Close() error { return e.ref.Close() }

// StatNoLinks looks up an absolute path without following any link on
// the way. The entry can be any type; close it when done.
func StatNoLinks(path string) (*Entry, error) {
	path = filepath.Clean(path)
	dir, name := filepath.Split(path)
	if name == "" {
		return nil, fs.ErrInvalid
	}
	fd, err := openDirNoLinks(dir)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	ref, err := unix.Openat(fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	rf := os.NewFile(uintptr(ref), name)
	info, err := rf.Stat()
	if err != nil {
		rf.Close()
		return nil, err
	}
	return &Entry{Path: path, Info: info, ref: rf}, nil
}

// WalkNoLinks walks the folder root without following links: not the ones
// it finds, and not one swapped in for a folder while it walks, because
// every name is opened inside the folder already open, never by its path.
// It is for places where others can write, where any name may turn into a
// link at any moment. Root itself must be reachable without links.
//
// dir is called for every folder below root and says whether to go in,
// file for every regular file, and fail for what can't be opened.
func WalkNoLinks(ctx context.Context, root string, dir func(path string) bool, file func(e *Entry), fail func(path string, err error)) error {
	root = filepath.Clean(root)
	fd, err := openDirNoLinks(root)
	if err != nil {
		fail(root, err)
		return nil
	}
	return walkDirFd(ctx, fd, root, 0, dir, file, fail)
}

// openDirNoLinks opens an absolute folder one name at a time, refusing
// links.
func openDirNoLinks(path string) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fs.ErrInvalid
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			continue
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// maxDepth keeps a very deep tree from using up file descriptors: each
// level holds its folder open.
const maxDepth = 128

func walkDirFd(ctx context.Context, fd int, path string, depth int, dir func(string) bool, file func(*Entry), fail func(string, error)) error {
	d := os.NewFile(uintptr(fd), path)
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil {
		fail(path, err)
		if len(ents) == 0 {
			return nil
		}
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	for _, de := range ents {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := de.Name()
		p := filepath.Join(path, name)
		t := de.Type()
		if t&(fs.ModeSymlink|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeDevice|fs.ModeCharDevice) != 0 {
			continue
		}
		ref, err := unix.Openat(fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			fail(p, err)
			continue
		}
		rf := os.NewFile(uintptr(ref), name)
		info, err := rf.Stat()
		switch {
		case err != nil:
			fail(p, err)
		case info.IsDir():
			if depth+1 >= maxDepth || !dir(p) {
				break
			}
			// open the folder through the handle, so it is the one stat'ed
			sub, err := unix.Open("/proc/self/fd/"+strconv.Itoa(ref), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				fail(p, err)
				break
			}
			if err := walkDirFd(ctx, sub, p, depth+1, dir, file, fail); err != nil {
				rf.Close()
				return err
			}
		case info.Mode().IsRegular():
			file(&Entry{Path: p, Info: info, ref: rf})
		}
		rf.Close()
	}
	return nil
}
