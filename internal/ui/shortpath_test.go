package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/BuFuuu/based/internal/model"
)

func TestShortPath(t *testing.T) {
	displayHome = "/home/alice"
	defer func() { displayHome = "" }()
	for _, tc := range []struct {
		in   string
		w    int
		want string
	}{
		{"/tmp/x", 40, "/tmp/x"},
		{"/home/alice/.bashrc", 40, "~/.bashrc"},
		{"/tmp/build-1000/-home-alice-work/490571cd/scratchpad/.cache/dropper.sh", 40, "/tmp/…/scratchpad/.cache/dropper.sh"},
		{"/home/alice/.claude/skills/synced/9a1e6b21/google-workspace/scripts/render_export.py", 40, "~/.claude/…/scripts/render_export.py"},
		{"checkra1n-gui", 40, "checkra1n-gui"},
		{"/a/very-long-file-name-that-does-not-fit-anywhere-at-all.so", 20, "…-anywhere-at-all.so"},
	} {
		got := ShortPath(tc.in, tc.w)
		if ansi.StringWidth(got) > tc.w {
			t.Errorf("%s: %q is wider than %d", tc.in, got, tc.w)
		}
		if tc.want != "" && got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEntryClickCopiesPath(t *testing.T) {
	m, copied := testBrowser(t, 120, 30)
	m.snap.Persist = []model.Entry{{Mechanism: "cron", Name: "0anacron", Path: "/etc/cron.hourly/0anacron", State: "default", Why: "from package cronie"}}
	m.persist.hideDefaults = false
	m.rebuild()
	m.mode = modePersist
	m.View()
	click(m, 40, headerH+1) // heading, then the entry
	if len(*copied) != 1 || (*copied)[0] != "/etc/cron.hourly/0anacron" {
		t.Fatalf("copied %q", *copied)
	}
	if !strings.Contains(m.status, "Copied to clipboard") {
		t.Fatalf("status %q", m.status)
	}
}
