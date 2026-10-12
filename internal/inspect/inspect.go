// Package inspect looks at a single file and turns what it finds into flags.
// It only reads small headers and never executes anything.
package inspect

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/BuFuuu/based/internal/model"
)

const headerSize = 64 << 10

// Times returns the best "added" time for a file: btime when the filesystem
// records it (btrfs/ext4 do), otherwise ctime.
func Times(path string) (added time.Time, source string, mtime time.Time) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME|unix.STATX_CTIME|unix.STATX_MTIME, &st); err != nil {
		return time.Time{}, "", time.Time{}
	}
	mtime = time.Unix(st.Mtime.Sec, int64(st.Mtime.Nsec))
	if st.Mask&unix.STATX_BTIME != 0 && st.Btime.Sec > 0 {
		return time.Unix(st.Btime.Sec, int64(st.Btime.Nsec)), "created", mtime
	}
	return time.Unix(st.Ctime.Sec, int64(st.Ctime.Nsec)), "changed", mtime
}

// Born returns a file's creation and last change time (ctime). Neither can
// be set back with ordinary tools. ok is false when the filesystem doesn't
// record creation times.
func Born(path string) (btime, ctime time.Time, ok bool) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME|unix.STATX_CTIME, &st); err != nil {
		return time.Time{}, time.Time{}, false
	}
	if st.Mask&unix.STATX_BTIME == 0 || st.Btime.Sec == 0 {
		return time.Time{}, time.Time{}, false
	}
	return time.Unix(st.Btime.Sec, 0), time.Unix(st.Ctime.Sec, 0), true
}

// FileType is a coarse classification of file contents.
type FileType string

const (
	TypeELF    FileType = "elf"
	TypeScript FileType = "script"
	TypeData   FileType = "data"
)

// Result is what Inspect learned about a file.
type Result struct {
	Type        FileType
	Interpreter string
	Static      bool
	Packed      bool
	Patterns    []string
	Preview     string
	Header      []byte
}

// Inspect reads the start of a regular file and classifies it. Files larger
// than maxScript bytes are not pattern-scanned.
func Inspect(path string, size int64) Result {
	var r Result
	f, err := os.Open(path)
	if err != nil {
		return r
	}
	defer f.Close()
	buf := make([]byte, headerSize)
	n, _ := io.ReadFull(f, buf)
	buf = buf[:n]
	r.Header = buf
	r.Type = TypeData
	switch {
	case bytes.HasPrefix(buf, []byte("\x7fELF")):
		r.Type = TypeELF
		r.Packed = bytes.Contains(buf, []byte("UPX!"))
		if ef, err := elf.Open(path); err == nil {
			r.Static = true
			for _, p := range ef.Progs {
				if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
					r.Static = false
					break
				}
			}
			ef.Close()
		}
	case bytes.HasPrefix(buf, []byte("#!")):
		r.Type = TypeScript
		line, _, _ := bytes.Cut(buf, []byte("\n"))
		r.Interpreter = strings.TrimSpace(string(line[2:]))
	}
	if r.Type == TypeScript || (r.Type == TypeData && looksLikeText(buf) && size < 1<<20) {
		r.Patterns = RiskyPatterns(string(buf))
		if r.Type == TypeScript || len(r.Patterns) > 0 {
			r.Preview = preview(buf, 40)
		}
	}
	return r
}

// Flags turns a Result into model flags.
func (r Result) Flags() []model.Flag {
	var out []model.Flag
	if r.Type == TypeELF {
		out = append(out, model.FlagELF)
		if r.Static {
			out = append(out, model.FlagStatic)
		}
		if r.Packed {
			out = append(out, model.FlagPacked)
		}
	}
	if len(r.Patterns) > 0 {
		fl := model.FlagSuspiciousScript
		fl.Label = "risky patterns: " + strings.Join(r.Patterns, ", ")
		out = append(out, fl)
	}
	return out
}

type pattern struct {
	name string
	re   *regexp.Regexp
}

var patterns = []pattern{
	{"download piped to shell", regexp.MustCompile(`(curl|wget)[^\n|;]*\|\s*(ba|z|da)?sh\b`)},
	// decoding base64 is everyday code; running what was decoded is how
	// droppers hide their payload
	{"runs base64-decoded code", regexp.MustCompile(`base64\s+(-d|--decode)[^\n]*\|\s*(ba|z|da)?sh\b|\b(exec|eval|Function)\s*\([^\n]{0,60}(b64decode|atob|base64)`)},
	{"reverse shell", regexp.MustCompile(`/dev/tcp/|\bnc(at)?\b[^\n]*\s-e\s|socat[^\n]*exec:|bash -i >&`)},
	{"eval of remote data", regexp.MustCompile(`eval\s*["']?\$\((curl|wget)`)},
	{"chmod +x in temp", regexp.MustCompile(`chmod\s+(\+x|[0-7]*7[0-7]{2})\s+/(tmp|dev/shm|var/tmp)/`)},
	{"history tampering", regexp.MustCompile(`unset\s+HISTFILE|HISTFILE=/dev/null|history\s+-c`)},
	{"LD_PRELOAD", regexp.MustCompile(`LD_PRELOAD=|/etc/ld\.so\.preload`)},
	{"crypto miner", regexp.MustCompile(`(?i)xmrig|stratum\+tcp://|minerd\b`)},
	{"raw IP download", regexp.MustCompile(`(curl|wget)\s+[^\n]*https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)},
}

// hasLongBlob finds a run of 400+ base64 characters (a regexp with a
// counted repeat is far too slow for this).
func hasLongBlob(s string) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' {
			if run++; run >= 400 {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// RiskyPatterns returns the names of risky patterns found in a script.
func RiskyPatterns(s string) []string {
	var out []string
	for _, p := range patterns {
		if p.re.MatchString(s) {
			out = append(out, p.name)
		}
	}
	if hasLongBlob(s) {
		out = append(out, "long encoded blob")
	}
	return out
}

func looksLikeText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return !bytes.ContainsRune(b[:min(len(b), 4096)], 0)
}

func preview(b []byte, lines int) string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), headerSize)
	for sc.Scan() && len(out) < lines {
		l := sc.Text()
		if len(l) > 200 {
			l = l[:200] + "…"
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// ModeFlags inspects permission bits and ownership.
func ModeFlags(path string, info fs.FileInfo, systemPath bool) []model.Flag {
	var out []model.Flag
	m := info.Mode()
	if m&fs.ModeSetuid != 0 {
		out = append(out, model.FlagSUID)
	}
	if m&fs.ModeSetgid != 0 {
		out = append(out, model.FlagSGID)
	}
	if systemPath && m.Perm()&0o002 != 0 && m.IsRegular() {
		out = append(out, model.FlagWorldWritable)
	}
	if m.IsRegular() && HasCaps(path) {
		out = append(out, model.FlagCapabilities)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if _, known := UserName(st.Uid); !known {
			out = append(out, model.FlagUnknownOwner)
		}
	}
	return out
}

// RootCaps reports whether a file carries capabilities that amount to root:
// chown, dac_override, dac_read_search, fowner, setgid, setuid, sys_module,
// sys_ptrace or sys_admin.
func RootCaps(path string) bool {
	buf := make([]byte, 24)
	n, err := unix.Lgetxattr(path, "security.capability", buf)
	if err != nil || n < 8 {
		return false
	}
	// vfs_cap_data: magic, then permitted/inheritable pairs of 32-bit words
	permitted := uint64(binary.LittleEndian.Uint32(buf[4:8]))
	if n >= 20 {
		permitted |= uint64(binary.LittleEndian.Uint32(buf[12:16])) << 32
	}
	const root = 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<6 | 1<<7 | 1<<16 | 1<<19 | 1<<21
	return permitted&root != 0
}

func HasCaps(path string) bool {
	n, err := unix.Lgetxattr(path, "security.capability", nil)
	return err == nil && n > 0
}

func IsExecutable(info fs.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// IsHidden reports whether any component below base starts with a dot.
// The standard XDG directories (.config, .local/bin, .local/share,
// .local/state, .cache) do not count as hiding.
func IsHidden(path, base string) bool {
	rel := strings.TrimPrefix(strings.TrimPrefix(path, base), "/")
	for _, std := range []string{".config/", ".local/bin/", ".local/share/", ".local/state/", ".cache/"} {
		if strings.HasPrefix(rel, std) {
			rel = rel[len(std):]
			break
		}
	}
	for _, part := range strings.Split(rel, "/") {
		if len(part) > 1 && part[0] == '.' && part != ".." {
			return true
		}
	}
	return false
}

var (
	usersOnce sync.Once
	users     map[uint32]string
)

// UserName resolves a uid via /etc/passwd (no cgo, no NSS).
func UserName(uid uint32) (string, bool) {
	usersOnce.Do(func() {
		users = map[uint32]string{}
		b, err := os.ReadFile("/etc/passwd")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":")
			if len(f) < 3 {
				continue
			}
			if id, err := strconv.ParseUint(f[2], 10, 32); err == nil {
				users[uint32(id)] = f[0]
			}
		}
	})
	if len(users) == 0 {
		return strconv.Itoa(int(uid)), true
	}
	n, ok := users[uid]
	if !ok {
		return strconv.Itoa(int(uid)), false
	}
	return n, true
}

func Owner(info fs.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		n, _ := UserName(st.Uid)
		return n
	}
	return ""
}

func SHA256(path string) (string, error) { return hashFile(path, sha256.New()) }
func MD5(path string) (string, error)    { return hashFile(path, md5.New()) }

func hashFile(path string, h interface {
	io.Writer
	Sum([]byte) []byte
}) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HumanSize formats a byte count compactly.
func HumanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + "B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	s := strconv.FormatFloat(v, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return s + string("KMGTPE"[exp])
}

// ModeString renders permissions like ls does, plus the octal value:
// "-rwxr-sr-x (2755)".
func ModeString(m fs.FileMode) string {
	b := []byte("-rwxrwxrwx")
	switch {
	case m.IsDir():
		b[0] = 'd'
	case m&fs.ModeSymlink != 0:
		b[0] = 'l'
	}
	for i := 0; i < 9; i++ {
		if m.Perm()&(1<<uint(8-i)) == 0 {
			b[i+1] = '-'
		}
	}
	set := func(i int, on bool, x, noX byte) {
		if !on {
			return
		}
		if b[i] == '-' {
			b[i] = noX
		} else {
			b[i] = x
		}
	}
	set(3, m&fs.ModeSetuid != 0, 's', 'S')
	set(6, m&fs.ModeSetgid != 0, 's', 'S')
	set(9, m&fs.ModeSticky != 0, 't', 'T')
	oct := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		oct |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		oct |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		oct |= 0o1000
	}
	return string(b) + " (" + strconv.FormatUint(uint64(oct), 8) + ")"
}
