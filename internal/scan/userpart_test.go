package scan

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/BuFuuu/based/internal/model"
)

func TestUserPartRoundTrip(t *testing.T) {
	// the helper's side: a phase finds things
	helper := &Progress{Phases: []*Phase{{ID: "files.home"}, {ID: "persistence"}}}
	home := &Reporter{phase: helper.Phases[0], progress: helper}
	home.Tick("/home/u/a", "ok")
	home.Unreadable("/home/u/locked")
	home.Report(model.Finding{Kind: model.KindFile, Subject: "/home/u/.x/prog", Title: "binary"})
	home.Note("1 file")
	persist := &Reporter{phase: helper.Phases[1], progress: helper}
	persist.Entry(model.Entry{Mechanism: "autostart", Name: "x", Path: "/home/u/.config/autostart/x", State: "flagged"},
		&model.Finding{Kind: model.KindPersist, Subject: "/home/u/.config/autostart/x", Title: "autostart: x"})
	persist.Entry(model.Entry{Mechanism: "autostart", Name: "y", State: "default"}, nil)

	out := filepath.Join(t.TempDir(), "out.json")
	b, _ := json.Marshal(Results(helper))
	os.WriteFile(out, b, 0o644)

	// root's side: run "the helper" and merge
	u := StartUserPart(exec.Command("cat", out))
	root := &Progress{Phases: []*Phase{{ID: "files.home"}, {ID: "persistence"}}}
	for i, id := range []string{"files.home", "persistence"} {
		res, err := u.Result(context.Background(), id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		(&Reporter{phase: root.Phases[i], progress: root}).Merge(res)
		if id == "files.home" && (len(res.Skipped) != 1 || res.Skipped[0] != "/home/u/locked" || res.Note != "1 file") {
			t.Errorf("files.home: skipped %v, note %q", res.Skipped, res.Note)
		}
	}
	if got := root.Phases[0].Done.Load(); got != 1 {
		t.Errorf("done %d, want 1", got)
	}
	if got := root.Phases[0].Unreadable.Load(); got != 1 {
		t.Errorf("unreadable %d, want 1", got)
	}
	fs, es := root.Findings(), root.Entries()
	if len(fs) != 2 || len(es) != 2 {
		t.Fatalf("got %d findings and %d entries, want 2 and 2", len(fs), len(es))
	}
	if es[0].FindingID == "" || es[0].FindingID != fs[1].ID {
		t.Errorf("the entry lost its finding: %q vs %q", es[0].FindingID, fs[1].ID)
	}
	if fs[0].Collector != "files.home" || fs[1].Collector != "persistence" {
		t.Errorf("collectors %q %q", fs[0].Collector, fs[1].Collector)
	}
}

func TestUserPartFailure(t *testing.T) {
	for name, cmd := range map[string]*exec.Cmd{
		"exit":    exec.Command("sh", "-c", "echo oops >&2; exit 3"),
		"garbage": exec.Command("echo", "not json"),
		"missing": exec.Command("/nonexistent/based"),
	} {
		if _, err := StartUserPart(cmd).Result(context.Background(), "files.home"); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u := StartUserPart(exec.CommandContext(ctx, "sleep", "10"))
	if _, err := u.Result(ctx, "files.home"); err == nil {
		t.Error("cancelled: no error")
	}
}
