package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/BuFuuu/based/internal/model"
)

// UserPart is the half of a root scan that runs as the user it reports to.
// Anything in their home could be a link they planted, so root opens
// nothing there by name: a helper process with the user's own rights scans
// the home and the persistence kept in it, and root only merges what it
// found. The helper starts with the scan and runs alongside the system
// phases; the home phases wait for it.
//
// What the helper sends is data from a process the user controls, the same
// as a scan they ran themselves: root stores it in the result and acts on
// nothing in it, except the paths in Skipped, which it walks without
// following links (see inspect.WalkNoLinks).
type UserPart struct {
	done    chan struct{}
	results map[string]PhaseResult
	err     error
}

// PhaseResult is what one phase found, handed from one process to another.
type PhaseResult struct {
	Findings   []model.Finding `json:"findings,omitempty"`
	Entries    []model.Entry   `json:"entries,omitempty"`
	Done       int64           `json:"done"`
	Unreadable int64           `json:"unreadable"`
	Stats      map[string]int  `json:"stats,omitempty"`
	Note       string          `json:"note,omitempty"`
	Err        string          `json:"err,omitempty"`
	Skipped    []string        `json:"skipped,omitempty"` // paths it couldn't open
}

// maxUserPart caps what root reads from the helper; a home has far less to
// report.
const maxUserPart = 512 << 20

// StartUserPart starts the helper and collects its results in the
// background. cmd must already be set up to run as the user.
func StartUserPart(cmd *exec.Cmd) *UserPart {
	u := &UserPart{done: make(chan struct{})}
	stderr := &tail{max: 2048}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		u.err = fmt.Errorf("starting the home scan as you: %w", err)
		close(u.done)
		return u
	}
	go func() {
		defer close(u.done)
		var res map[string]PhaseResult
		decErr := json.NewDecoder(io.LimitReader(out, maxUserPart)).Decode(&res)
		io.Copy(io.Discard, out) // let it finish writing, so Wait returns
		waitErr := cmd.Wait()
		switch {
		case waitErr != nil:
			u.err = fmt.Errorf("the home scan as you failed: %v %s", waitErr, strings.TrimSpace(stderr.String()))
		case decErr != nil:
			u.err = fmt.Errorf("reading the home scan: %w", decErr)
		default:
			u.results = res
		}
	}()
	return u
}

func failedUserPart(err error) *UserPart {
	u := &UserPart{done: make(chan struct{}), err: err}
	close(u.done)
	return u
}

// Result waits for the helper and returns what it found in one phase.
func (u *UserPart) Result(ctx context.Context, id string) (PhaseResult, error) {
	select {
	case <-u.done:
	case <-ctx.Done():
		return PhaseResult{}, ctx.Err()
	}
	if u.err != nil {
		return PhaseResult{}, u.err
	}
	res, ok := u.results[id]
	if !ok {
		return res, fmt.Errorf("the home scan has no results for %s", id)
	}
	if res.Err != "" {
		return res, errors.New(res.Err)
	}
	return res, nil
}

// Results collects what each phase found, for the helper to hand back.
func Results(p *Progress) map[string]PhaseResult {
	out := map[string]PhaseResult{}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ph := range p.Phases {
		res := PhaseResult{
			Done:       ph.Done.Load(),
			Unreadable: ph.Unreadable.Load(),
			Stats:      ph.Stats,
			Note:       ph.Note,
			Skipped:    ph.skipped,
		}
		if ph.Err != nil {
			res.Err = ph.Err.Error()
		}
		for _, f := range p.findings {
			if f.Collector == ph.ID {
				res.Findings = append(res.Findings, f)
			}
		}
		for i, e := range p.entries {
			if p.entryPhase[i] == ph.ID {
				res.Entries = append(res.Entries, e)
			}
		}
		out[ph.ID] = res
	}
	return out
}

// Merge records what this phase found in another process.
func (r *Reporter) Merge(res PhaseResult) {
	r.phase.Done.Add(res.Done)
	r.phase.Unreadable.Add(res.Unreadable)
	for k, v := range res.Stats {
		if r.phase.Stats == nil {
			r.phase.Stats = map[string]int{}
		}
		r.phase.Stats[k] += v
	}
	for _, f := range res.Findings {
		r.Report(f)
	}
	r.progress.mu.Lock()
	for _, e := range res.Entries {
		r.progress.entries = append(r.progress.entries, e)
		r.progress.entryPhase = append(r.progress.entryPhase, r.phase.ID)
	}
	r.progress.mu.Unlock()
}

// tail keeps the last max bytes written to it.
type tail struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// TestUserPart is a finished helper with these results, for tests.
func TestUserPart(results map[string]PhaseResult) *UserPart {
	u := &UserPart{done: make(chan struct{}), results: results}
	close(u.done)
	return u
}
