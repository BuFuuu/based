// Package pacman reads the local pacman database directly (no pacman
// process, no root needed) to answer "which package owns this file and what
// should it look like".
package pacman

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
)

const DefaultRoot = "/var/lib/pacman"

type Package struct {
	Name        string
	Version     string
	Desc        string
	URL         string
	Packager    string
	InstallDate time.Time
	Explicit    bool // %REASON% absent = explicitly installed
	Depends     []string
	OptDepends  []string
	Provides    []string
	Files       []string          // absolute paths, dirs end in "/"
	Backup      map[string]string // absolute path -> md5 of the shipped file
	Repo        string            // sync repo it is available from, "" if foreign
	HasInstall  bool
	dir         string
}

// Entry is one file record from a package's mtree.
type Entry struct {
	Size   int64
	Mtime  int64
	SHA256 string
	Mode   uint32
	Type   string
	Uid    int    // -1 when the record has none
	Link   string // symlink target
}

type DB struct {
	Root     string
	Packages []*Package
	byName   map[string]*Package
	owner    map[string]int32 // path -> index into Packages
	mtree    map[string]Entry
	provides map[string][]*Package
}

// Load reads every installed package. tick is called once per package so the
// caller can show progress.
func Load(root string, tick func(name string)) (*DB, error) {
	local := filepath.Join(root, "local")
	ents, err := os.ReadDir(local)
	if err != nil {
		return nil, err
	}
	db := &DB{Root: root, byName: map[string]*Package{}, owner: make(map[string]int32, 350000), mtree: make(map[string]Entry, 350000)}
	dirs := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(local, e.Name()))
		}
	}
	pkgs := make([]*Package, len(dirs))
	parallel(len(dirs), func(i int) { pkgs[i], _ = readPackage(dirs[i]) })
	for _, p := range pkgs {
		if p == nil || p.Name == "" {
			continue
		}
		db.byName[p.Name] = p
		db.Packages = append(db.Packages, p)
		for _, f := range p.Files {
			db.owner[f] = int32(len(db.Packages) - 1)
		}
		if tick != nil {
			tick(p.Name)
		}
	}
	db.loadMtrees(tick)
	db.markRepos()
	return db, nil
}

func (db *DB) Package(name string) *Package { return db.byName[name] }

// Owner returns the package owning path, or nil.
func (db *DB) Owner(path string) *Package {
	if i, ok := db.owner[path]; ok {
		return db.Packages[i]
	}
	if i, ok := db.owner[path+"/"]; ok {
		return db.Packages[i]
	}
	return nil
}

// Expected returns the mtree record for an owned file.
func (db *DB) Expected(path string) (Entry, bool) {
	e, ok := db.mtree[path]
	return e, ok
}

// Closure returns the names of the given packages plus everything they
// depend on (including optional dependencies), resolving virtual provides.
func (db *DB) Closure(roots []string) map[string]bool {
	if db.provides == nil {
		db.provides = map[string][]*Package{}
		for _, p := range db.Packages {
			db.provides[p.Name] = append(db.provides[p.Name], p)
			for _, v := range p.Provides {
				db.provides[v] = append(db.provides[v], p)
			}
		}
	}
	seen := map[string]bool{}
	stack := append([]string(nil), roots...)
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, p := range db.provides[n] {
			if seen[p.Name] {
				continue
			}
			seen[p.Name] = true
			stack = append(stack, p.Depends...)
			stack = append(stack, p.OptDepends...)
		}
	}
	return seen
}

// OwnedUnder counts owned non-directory paths below the given roots; used to
// estimate scan length up front.
func (db *DB) OwnedUnder(roots ...string) int {
	n := 0
	for p := range db.owner {
		if strings.HasSuffix(p, "/") {
			continue
		}
		for _, r := range roots {
			if strings.HasPrefix(p, r+"/") {
				n++
				break
			}
		}
	}
	return n
}

func readPackage(dir string) (*Package, error) {
	p := &Package{dir: dir, Explicit: true}
	sections, err := readSections(filepath.Join(dir, "desc"))
	if err != nil {
		return nil, err
	}
	first := func(k string) string {
		if v := sections[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	p.Name = first("NAME")
	p.Version = first("VERSION")
	p.Desc = first("DESC")
	p.URL = first("URL")
	p.Packager = first("PACKAGER")
	if ts, err := strconv.ParseInt(first("INSTALLDATE"), 10, 64); err == nil {
		p.InstallDate = time.Unix(ts, 0)
	}
	p.Explicit = first("REASON") != "1"
	p.Depends = stripVersions(sections["DEPENDS"])
	p.OptDepends = stripVersions(sections["OPTDEPENDS"])
	p.Provides = stripVersions(sections["PROVIDES"])

	files, err := readSections(filepath.Join(dir, "files"))
	if err == nil {
		for _, f := range files["FILES"] {
			p.Files = append(p.Files, "/"+f)
		}
		for _, b := range files["BACKUP"] {
			path, sum, _ := strings.Cut(b, "\t")
			if p.Backup == nil {
				p.Backup = map[string]string{}
			}
			p.Backup["/"+path] = sum
		}
	}
	_, err = os.Stat(filepath.Join(dir, "install"))
	p.HasInstall = err == nil
	return p, nil
}

// InstallScript returns the package's .INSTALL script, if any.
func (p *Package) InstallScript() string {
	b, err := os.ReadFile(filepath.Join(p.dir, "install"))
	if err != nil {
		return ""
	}
	return string(b)
}

func readSections(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string][]string{}
	var cur string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") && len(line) > 2 {
			cur = line[1 : len(line)-1]
			continue
		}
		if line == "" || cur == "" {
			continue
		}
		out[cur] = append(out[cur], line)
	}
	return out, sc.Err()
}

// stripVersions turns "glibc>=2.38" or "python: for scripts" into "glibc" / "python".
func stripVersions(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		if i := strings.IndexAny(d, "<>=:"); i >= 0 {
			d = d[:i]
		}
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func (db *DB) loadMtrees(tick func(string)) {
	trees := make([]map[string]Entry, len(db.Packages))
	parallel(len(db.Packages), func(i int) {
		trees[i] = parseMtree(filepath.Join(db.Packages[i].dir, "mtree"))
	})
	for _, m := range trees {
		for k, v := range m {
			db.mtree[k] = v
		}
		if tick != nil {
			tick("")
		}
	}
}

// parallel runs fn(0..n-1) across all CPUs.
func parallel(n int, fn func(i int)) {
	var next atomic.Int64
	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				fn(i)
			}
		}()
	}
	wg.Wait()
}

func parseMtree(path string) map[string]Entry {
	out := map[string]Entry{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return out
	}
	def := Entry{Uid: -1}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name, rest, _ := strings.Cut(line, " ")
		if name == "/set" {
			setAttrs(&def, rest)
			continue
		}
		if !strings.HasPrefix(name, "./") || (name[2] == '.' && !strings.Contains(name[2:], "/")) {
			continue // .PKGINFO, .BUILDINFO, .MTREE, .INSTALL
		}
		e := def
		setAttrs(&e, rest)
		out[unescape(name[1:])] = e
	}
	return out
}

func setAttrs(e *Entry, attrs string) {
	for attrs != "" {
		var kv string
		kv, attrs, _ = strings.Cut(attrs, " ")
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "type":
			e.Type = v
		case "sha256digest":
			e.SHA256 = v
		case "size":
			e.Size, _ = strconv.ParseInt(v, 10, 64)
		case "time":
			sec, _, _ := strings.Cut(v, ".")
			e.Mtime, _ = strconv.ParseInt(sec, 10, 64)
		case "mode":
			if m, err := strconv.ParseUint(v, 8, 32); err == nil {
				e.Mode = uint32(m)
			}
		case "uid":
			e.Uid, _ = strconv.Atoi(v)
		case "link":
			e.Link = unescape(v)
		}
	}
}

// unescape decodes mtree's \ooo octal escapes (e.g. \040 for a space).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// markRepos sets Package.Repo from the sync databases; packages left with an
// empty Repo are foreign (AUR, manually built, or from a removed repo).
func (db *DB) markRepos() {
	dbs, _ := filepath.Glob(filepath.Join(db.Root, "sync", "*.db"))
	for _, path := range dbs {
		repo := strings.TrimSuffix(filepath.Base(path), ".db")
		for name := range syncNames(path) {
			if p := db.byName[name]; p != nil && p.Repo == "" {
				p.Repo = repo
			}
		}
	}
}

// decompress handles the gzip and zstd sync databases pacman produces.
func decompress(f *os.File) (io.Reader, error) {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		d, err := zstd.NewReader(f)
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	}
	return gzip.NewReader(f)
}

func syncNames(path string) map[string]struct{} {
	out := map[string]struct{}{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	zr, err := decompress(f)
	if err != nil {
		return out
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF || err != nil {
			break
		}
		if !strings.HasSuffix(h.Name, "/desc") {
			continue
		}
		// read %NAME% from desc; dir names are ambiguous with dashes
		sc := bufio.NewScanner(tr)
		for sc.Scan() {
			if sc.Text() == "%NAME%" && sc.Scan() {
				out[sc.Text()] = struct{}{}
				break
			}
		}
	}
	return out
}
