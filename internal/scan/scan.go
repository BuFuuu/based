// Package scan runs collectors and reports progress. A collector is anything
// that walks some part of the system and emits findings; adding a new check
// (persistence, network, ...) means writing one Collector and registering it.
package scan

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/pacman"
)

// Collector is one scan phase.
type Collector interface {
	ID() string    // stable id, e.g. "files.system"
	Title() string // shown in the scan UI
	// Estimate returns the expected number of Tick calls, or 0 if unknown.
	// prev is the count from the last scan, if any.
	Estimate(env *Env, prev int) int
	Collect(ctx context.Context, env *Env, r *Reporter) error
}

// Env is shared, read-only context for collectors.
type Env struct {
	Pacman      *pacman.DB
	Home        string // the scanned user's home (SUDO_USER aware)
	OmarchyPath string // /usr/share/omarchy
	IsRoot      bool
	Deep        bool // hash every package file instead of the metadata pre-check

	// Defaults holds the packages of the Omarchy install (set by the
	// package database phase).
	Defaults map[string]bool

	// A root scan for a user leaves their home to a helper that runs as
	// them (see UserPart). ReportTo is that user, UserPart the helper's
	// results; HomeOnly is set inside the helper.
	ReportTo *Account
	UserPart *UserPart
	HomeOnly bool
}

// Account is the user a root scan reports to.
type Account struct {
	Name     string
	UID, GID int
	GIDs     []int
}

// Repos built and signed by Arch Linux itself, and by Omarchy ("offline" is
// the mirror on the Omarchy ISO). Any other repo is a third party.
var (
	archRepos    = map[string]bool{"core": true, "extra": true, "multilib": true, "core-testing": true, "extra-testing": true, "multilib-testing": true}
	omarchyRepos = map[string]bool{"omarchy": true, "offline": true}
)

// Trust classifies a package by where it comes from.
func (e *Env) Trust(p *pacman.Package) model.Trust {
	switch {
	case p == nil:
		return model.TrustUnknown
	case !archRepos[p.Repo] && !omarchyRepos[p.Repo]:
		return model.TrustForeign // AUR, manual build, or a third-party repo
	case omarchyRepos[p.Repo] || e.Defaults[p.Name]:
		return model.TrustOmarchy
	}
	return model.TrustArch
}

// RepoKind describes a repo name for display.
func RepoKind(repo string) string {
	switch {
	case repo == "":
		return "none: AUR or built manually"
	case archRepos[repo]:
		return repo + " (official Arch)"
	case omarchyRepos[repo]:
		return repo + " (Omarchy)"
	}
	return repo + " (third-party repo)"
}

func NewEnv() *Env {
	env := &Env{OmarchyPath: "/usr/share/omarchy", IsRoot: os.Geteuid() == 0}
	if p := os.Getenv("OMARCHY_PATH"); p != "" {
		env.OmarchyPath = p
	}
	env.Home, _ = os.UserHomeDir()
	if su := os.Getenv("SUDO_USER"); env.IsRoot && su != "" && su != "root" {
		// a root scan for this user: their home is scanned as them (see
		// UserPart), and they get only contents they could read themselves
		acct, home, err := lookupAccount(su)
		if err != nil {
			// share only what anyone could read, and scan no home
			inspect.LimitContentTo(65534, nil)
			env.UserPart = failedUserPart(err)
		} else {
			env.Home, env.ReportTo = home, acct
			inspect.LimitContentTo(acct.UID, acct.GIDs)
		}
	}
	env.Home = filepath.Clean(env.Home)
	return env
}

func lookupAccount(name string) (*Account, string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, "", fmt.Errorf("can't look up user %q: %w", name, err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid == 0 || u.HomeDir == "" {
		return nil, "", fmt.Errorf("user %q has no usable uid, gid or home", name)
	}
	acct := &Account{Name: u.Username, UID: uid, GID: gid}
	ids, _ := u.GroupIds()
	for _, g := range ids {
		if n, err := strconv.Atoi(g); err == nil {
			acct.GIDs = append(acct.GIDs, n)
		}
	}
	return acct, u.HomeDir, nil
}

// Phase is the live state of one collector, read by the UI.
type Phase struct {
	ID         string
	Title      string
	Estimate   int
	Done       atomic.Int64
	Unreadable atomic.Int64
	Found      atomic.Int64
	Started    time.Time
	Finished   time.Time
	State      atomic.Int32 // 0 pending, 1 running, 2 done, 3 failed
	Err        error
	Note       string         // short summary shown when done
	Stats      map[string]int // free-form counters, e.g. files checked per trust level

	skipped []string // paths that could not be opened (the first maxSkipped)
}

const maxSkipped = 256

const (
	PhasePending int32 = iota
	PhaseRunning
	PhaseDone
	PhaseFailed
)

// Event is a line in the live stream: a checked path or a hit.
type Event struct {
	Path     string
	Detail   string
	Hit      bool
	Severity model.Severity
}

// Progress is shared between the scanning goroutine and the UI.
type Progress struct {
	Phases  []*Phase
	Started time.Time

	mu       sync.Mutex
	ring     [64]Event
	ringPos  int
	ringLen  int
	findings []model.Finding
	entries  []model.Entry
	net      []model.Entry

	entryPhase []string // the phase of each entry
	counts     [4]int
}

// Recent returns up to n of the latest events, oldest first.
func (p *Progress) Recent(n int) []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n > p.ringLen {
		n = p.ringLen
	}
	out := make([]Event, n)
	for i := range n {
		idx := (p.ringPos - n + i + len(p.ring)) % len(p.ring)
		out[i] = p.ring[idx]
	}
	return out
}

func (p *Progress) Counts() [4]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts
}

func (p *Progress) Findings() []model.Finding {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]model.Finding(nil), p.findings...)
}

// Entries returns the persistence entries recorded so far.
func (p *Progress) Entries() []model.Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]model.Entry(nil), p.entries...)
}

// NetEntries returns the network entries recorded so far.
func (p *Progress) NetEntries() []model.Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]model.Entry(nil), p.net...)
}

func (p *Progress) push(e Event) {
	p.mu.Lock()
	p.ring[p.ringPos] = e
	p.ringPos = (p.ringPos + 1) % len(p.ring)
	if p.ringLen < len(p.ring) {
		p.ringLen++
	}
	p.mu.Unlock()
}

// Reporter is handed to a collector to report work and findings.
type Reporter struct {
	phase    *Phase
	progress *Progress
}

// Tick records one checked item; detail is a short annotation for the stream.
func (r *Reporter) Tick(path, detail string) {
	r.phase.Done.Add(1)
	r.progress.push(Event{Path: path, Detail: detail})
}

// Unreadable records an item that could not be checked (usually permissions).
func (r *Reporter) Unreadable(path string) {
	r.phase.Unreadable.Add(1)
	if len(r.phase.skipped) < maxSkipped {
		r.phase.skipped = append(r.phase.skipped, path)
	}
	r.Stat("unreadable:" + TopDir(path))
}

// File records one checked file: its trust level and its top-level folder.
func (r *Reporter) File(path string, t model.Trust) {
	r.Stat("trust:" + t.Name())
	r.Stat("dir:" + TopDir(path))
}

// TopDir returns the first path component: "/usr/bin/ls" -> "/usr".
func TopDir(path string) string {
	rest := strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return "/" + rest
}

// Stat bumps a counter that is saved with the snapshot.
func (r *Reporter) Stat(key string) {
	if r.phase.Stats == nil {
		r.phase.Stats = map[string]int{}
	}
	r.phase.Stats[key]++
}

// Note sets the one-line summary shown next to the finished phase.
func (r *Reporter) Note(s string) { r.phase.Note = s }

// Entry records a persistence entry. A flagged entry carries a finding,
// which is reported too and linked by id.
func (r *Reporter) Entry(e model.Entry, f *model.Finding) {
	if f != nil {
		f.Finalize()
		e.FindingID = f.ID
		r.Report(*f)
	}
	r.progress.mu.Lock()
	r.progress.entries = append(r.progress.entries, e)
	r.progress.entryPhase = append(r.progress.entryPhase, r.phase.ID)
	r.progress.mu.Unlock()
}

// NetEntry records a program with open sockets, like Entry does for
// persistence.
func (r *Reporter) NetEntry(e model.Entry, f *model.Finding) {
	if f != nil {
		f.Finalize()
		e.FindingID = f.ID
		r.Report(*f)
	}
	r.progress.mu.Lock()
	r.progress.net = append(r.progress.net, e)
	r.progress.mu.Unlock()
}

// Report finalizes and records a finding.
func (r *Reporter) Report(f model.Finding) {
	f.Collector = r.phase.ID
	f.Finalize()
	r.phase.Found.Add(1)
	r.progress.mu.Lock()
	r.progress.findings = append(r.progress.findings, f)
	r.progress.counts[f.Severity]++
	r.progress.mu.Unlock()
	if f.Severity >= model.Low {
		r.progress.push(Event{Path: f.Subject, Detail: f.Title, Hit: true, Severity: f.Severity})
	}
}

// NewProgress prepares phases for the given collectors.
func NewProgress(cs []Collector) *Progress {
	p := &Progress{}
	for _, c := range cs {
		p.Phases = append(p.Phases, &Phase{ID: c.ID(), Title: c.Title()})
	}
	return p
}

// Run executes collectors in order. Estimates are computed lazily right
// before each phase so they can use state loaded by earlier phases.
func Run(ctx context.Context, env *Env, cs []Collector, p *Progress, prevCounts map[string]int) {
	p.Started = time.Now()
	for i, c := range cs {
		ph := p.Phases[i]
		if ctx.Err() != nil {
			ph.State.Store(PhaseFailed)
			ph.Err = ctx.Err()
			continue
		}
		ph.Estimate = c.Estimate(env, prevCounts[c.ID()])
		ph.Started = time.Now()
		ph.State.Store(PhaseRunning)
		err := c.Collect(ctx, env, &Reporter{phase: ph, progress: p})
		ph.Finished = time.Now()
		if err != nil {
			ph.Err = err
			ph.State.Store(PhaseFailed)
			continue
		}
		ph.State.Store(PhaseDone)
	}
}

// TestReporter exposes a Reporter for UI tests.
func TestReporter(p *Progress, ph *Phase) *Reporter { return &Reporter{phase: ph, progress: p} }
