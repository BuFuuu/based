// Package store persists scans under ~/.local/state/based:
//
//	latest.json      the most recent snapshot
//	snapshots/       older snapshots (gzipped, last 20 kept)
//	seen.json        id -> first time Based ever saw the item
//	accepted.json    id -> fingerprint the user marked as known-good
//	summary.json     tiny file the bar widget watches
package store

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/BuFuuu/based/internal/model"
)

const keepSnapshots = 20

type Snapshot struct {
	Version    int             `json:"version"`
	ScannedAt  time.Time       `json:"scanned_at"`
	Duration   string          `json:"duration"`
	Host       string          `json:"host"`
	AsRoot     bool            `json:"as_root"`
	Counts     map[string]int  `json:"counts"`     // collector id -> items checked
	Unreadable map[string]int  `json:"unreadable"` // collector id -> paths skipped
	Stats      map[string]int  `json:"stats"`      // e.g. "trust:arch" -> files checked
	Home       string          `json:"home"`
	Findings   []model.Finding `json:"findings"`
	Persist    []model.Entry   `json:"persistence"`
	Network    []model.Entry   `json:"network,omitempty"`
}

type Accepted struct {
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	At          time.Time `json:"at"`
	Note        string    `json:"note,omitempty"`
}

type Summary struct {
	ScannedAt time.Time `json:"scanned_at"`
	High      int       `json:"high"`
	Med       int       `json:"med"`
	Low       int       `json:"low"`
	Info      int       `json:"info"`
	Accepted  int       `json:"accepted"`
	Top       string    `json:"top"` // worst severity with open items: high, med, low, info, clean
}

// Store lives in the state folder of the user running the process. A root
// scan never opens it: the root process only scans and hands its result to
// the user's own process (see `based scan --sudo`), so nothing here ever
// writes into a user's files with root's rights.
type Store struct {
	Dir string
}

// Open returns the store of the user running this process.
func Open() (*Store, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		base = filepath.Join(home, ".local", "state")
	}
	s := &Store{Dir: filepath.Join(base, "based")}
	if os.Geteuid() == 0 {
		if err := rootSafe(s.Dir); err != nil {
			return nil, err
		}
	}
	return s, os.MkdirAll(filepath.Join(s.Dir, "snapshots"), 0o700)
}

// rootSafe refuses a state folder that root must not write into: one with
// a symlink or a folder owned by another user on the way, as with
// `sudo -E`, which keeps the user's HOME. Root's own state folder passes.
func rootSafe(dir string) error {
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return err
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("refusing to write %s as root: %s is a symlink", dir, p)
		default:
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
				return fmt.Errorf("refusing to write %s as root: %s belongs to another user; run based as yourself", dir, p)
			}
		}
		if p == "/" {
			return nil
		}
	}
}

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

func (s *Store) readJSON(name string, v any) error {
	b, err := os.ReadFile(s.path(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (s *Store) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(s.path(name), b)
}

// writeFile replaces a file atomically through a temporary file with an
// unpredictable name in the same folder.
func (s *Store) writeFile(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(f.Name())
		return werr
	}
	return os.Rename(f.Name(), path)
}

// Latest loads the most recent snapshot. It returns (nil, nil) if no scan
// has been run yet.
func (s *Store) Latest() (*Snapshot, error) {
	var snap Snapshot
	if err := s.readJSON("latest.json", &snap); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &snap, nil
}

func (s *Store) Seen() map[string]time.Time {
	m := map[string]time.Time{}
	s.readJSON("seen.json", &m)
	return m
}

func (s *Store) Accepted() map[string]Accepted {
	m := map[string]Accepted{}
	s.readJSON("accepted.json", &m)
	return m
}

func (s *Store) SaveAccepted(m map[string]Accepted) error {
	if err := s.writeJSON("accepted.json", m); err != nil {
		return err
	}
	if snap, err := s.Latest(); err == nil && snap != nil {
		return s.writeSummary(snap, m)
	}
	return nil
}

// IsAccepted reports whether f was accepted and has not changed since, or
// lies in an accepted folder.
func IsAccepted(acc map[string]Accepted, f model.Finding) bool {
	if a, ok := acc[f.ID]; ok && a.Fingerprint == f.Fingerprint {
		return true
	}
	return AcceptedFolder(acc, f) != ""
}

// Folder accepts live in the same map under "dir:<path>". They cover every
// file below the folder, also after it changes or when new files appear, so
// a project you build stays quiet. Very unusual items (a setuid file dropped
// into the project) always stay visible; packages have no folder.
const FolderPrefix = "dir:"

// FolderKey is the accepted-map key for a folder rule.
func FolderKey(dir string) string { return FolderPrefix + dir }

// FolderCovers reports whether a folder rule for dir would hide f.
func FolderCovers(dir string, f model.Finding) bool {
	if f.Kind == model.KindPackage || f.Severity >= model.High {
		return false
	}
	subj := strings.TrimSuffix(f.Subject, "/")
	return subj == dir || strings.HasPrefix(subj, dir+"/")
}

// AcceptedFolder returns the accepted folder that hides f, or "".
func AcceptedFolder(acc map[string]Accepted, f model.Finding) string {
	for k := range acc {
		if dir, ok := strings.CutPrefix(k, FolderPrefix); ok && FolderCovers(dir, f) {
			return dir
		}
	}
	return ""
}

// broadFolders hold things from many sources; accepting one whole would
// hide whatever lands there next. Their subfolders are fine.
var broadFolders = []string{
	"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libexec", "/usr/share", "/usr/include",
	"/usr/src", "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib", "/usr/local/share",
	"/etc/systemd", "/etc/systemd/system", "/etc/systemd/user", "/etc/xdg", "/etc/xdg/autostart",
	"/etc/profile.d", "/etc/sudoers.d", "/etc/cron.d", "/etc/pacman.d", "/etc/udev", "/etc/udev/rules.d",
	"/var/lib", "/var/cache", "/var/tmp", "/var/spool", "/var/log", "/var/opt", "/dev/shm",
	"~/.config", "~/.config/systemd", "~/.config/systemd/user", "~/.config/autostart", "~/.config/hypr",
	"~/.local", "~/.local/bin", "~/.local/lib", "~/.local/share", "~/.local/state", "~/.cache", "~/.ssh",
	"~/bin", "~/Downloads", "~/Desktop", "~/Documents", "~/.npm", "~/.cargo", "~/.cargo/bin", "~/go", "~/go/bin",
}

// FolderAllowed says whether dir may be accepted as a whole, and if not, why.
func FolderAllowed(dir, home string) (bool, string) {
	dir = filepath.Clean(dir)
	switch {
	case dir == "/" || strings.Count(dir, "/") == 1:
		return false, dir + " is a top folder"
	case home != "" && (dir == home || strings.HasPrefix(home, dir+"/")):
		return false, "that would cover your whole home"
	}
	for _, b := range broadFolders {
		if home != "" {
			b = strings.Replace(b, "~", home, 1)
		}
		if dir == b {
			return false, dir + " holds things from many sources"
		}
	}
	return true, ""
}

// Save stores a new snapshot, stamps first-seen times, rotates old
// snapshots and refreshes the summary.
func (s *Store) Save(snap *Snapshot) error {
	seen := s.Seen()
	for i := range snap.Findings {
		f := &snap.Findings[i]
		if t, ok := seen[f.ID]; ok {
			f.FirstSeen = t
		} else {
			f.FirstSeen = snap.ScannedAt
			seen[f.ID] = snap.ScannedAt
		}
	}
	if err := s.writeJSON("seen.json", seen); err != nil {
		return err
	}
	if prev, err := s.Latest(); err == nil && prev != nil {
		s.archive(prev)
	}
	if err := s.writeJSON("latest.json", snap); err != nil {
		return err
	}
	return s.writeSummary(snap, s.Accepted())
}

func (s *Store) archive(prev *Snapshot) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	json.NewEncoder(zw).Encode(prev)
	zw.Close()
	name := filepath.Join(s.Dir, "snapshots", prev.ScannedAt.UTC().Format("2006-01-02T15-04-05")+".json.gz")
	if err := s.writeFile(name, buf.Bytes()); err != nil {
		return
	}

	old, _ := filepath.Glob(filepath.Join(s.Dir, "snapshots", "*.json.gz"))
	sort.Strings(old)
	for len(old) > keepSnapshots {
		os.Remove(old[0])
		old = old[1:]
	}
}

// ReportPath is where the Markdown report for a snapshot lives.
func (s *Store) ReportPath(snap *Snapshot) string {
	return filepath.Join(s.Dir, "reports", "based-report-"+snap.ScannedAt.Format("2006-01-02-1504")+".md")
}

// SaveReport writes the report for a snapshot and keeps the last 20.
func (s *Store) SaveReport(snap *Snapshot, content []byte) (string, error) {
	path := s.ReportPath(snap)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := s.writeFile(path, content); err != nil {
		return "", err
	}
	old, _ := filepath.Glob(filepath.Join(s.Dir, "reports", "based-report-*.md"))
	sort.Strings(old)
	for len(old) > keepSnapshots {
		os.Remove(old[0])
		old = old[1:]
	}
	return path, nil
}

func (s *Store) writeSummary(snap *Snapshot, acc map[string]Accepted) error {
	sum := Summary{ScannedAt: snap.ScannedAt, Top: "clean"}
	for _, f := range snap.Findings {
		if IsAccepted(acc, f) {
			sum.Accepted++
			continue
		}
		switch f.Severity {
		case model.High:
			sum.High++
		case model.Med:
			sum.Med++
		case model.Low:
			sum.Low++
		default:
			sum.Info++
		}
	}
	switch {
	case sum.High > 0:
		sum.Top = "high"
	case sum.Med > 0:
		sum.Top = "med"
	case sum.Low > 0:
		sum.Top = "low"
	}
	return s.writeJSON("summary.json", sum)
}
