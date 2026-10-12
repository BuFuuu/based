package ui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/store"
)

func testBrowser(t *testing.T, w, h int) (*BrowseModel, *[]string) {
	t.Helper()
	SetupColor(true)
	st := &store.Store{Dir: t.TempDir()}
	now := time.Now()
	snap := &store.Snapshot{ScannedAt: now, Host: "box", Home: "/home/alice"}
	for i, p := range []string{"/usr/local/bin/tool", "/etc/foo.conf", "/home/alice/.local/bin/x"} {
		f := model.Finding{Kind: model.KindFile, Subject: p, Title: "unowned file",
			Flags: []model.Flag{model.FlagUnownedBinary}, Added: now.Add(-time.Duration(i) * time.Hour),
			Facts: map[string]string{"sha256": "abc" + p}}
		f.Finalize()
		snap.Findings = append(snap.Findings, f)
	}
	var copied []string
	clipboard = func(s string) error { copied = append(copied, s); return nil }
	m := NewBrowse(st, snap, TimelineOptions{MinSeverity: model.Low}, "based", false)
	m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return m, &copied
}

func click(m *BrowseModel, x, y int) {
	m.Update(tea.MouseMsg{X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
}

func checkFits(t *testing.T, m *BrowseModel, w, h int) {
	t.Helper()
	lines := strings.Split(m.View(), "\n")
	if len(lines) != h {
		t.Errorf("view has %d lines, want %d", len(lines), h)
	}
	for i, l := range lines {
		if lw := lipgloss.Width(l); lw > w {
			t.Errorf("line %d is %d wide (max %d): %q", i, lw, w, l)
		}
	}
}

func TestBrowseClickCopiesPath(t *testing.T) {
	m, copied := testBrowser(t, 100, 30)
	checkFits(t, m, 100, 30)
	// first list line is the "Today" header, the second the newest item
	click(m, rowSubjectX+2, headerH+1)
	if len(*copied) != 1 || (*copied)[0] != "/usr/local/bin/tool" {
		t.Fatalf("copied %q, want the clicked path", *copied)
	}
}

func TestBrowseDetailAndActions(t *testing.T) {
	m, copied := testBrowser(t, 100, 30)
	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.mode != modeDetail {
		t.Fatal("enter should open the detail view")
	}
	checkFits(t, m, 100, 30)
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	if got := (*copied)[len(*copied)-1]; got != "abc/etc/foo.conf" {
		t.Fatalf("sha256 copy = %q", got)
	}
	// clicking a fact line copies its value
	for i, l := range m.detail {
		if l.Copy == "abc/etc/foo.conf" {
			click(m, 10, i+1-m.dtop)
			break
		}
	}
	if got := (*copied)[len(*copied)-1]; got != "abc/etc/foo.conf" {
		t.Fatalf("fact click copied %q", got)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("p")})
	if got := (*copied)[len(*copied)-1]; !strings.Contains(got, "Subject: /etc/foo.conf") {
		t.Fatalf("prompt copy = %q", got)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.mode != modeList {
		t.Fatal("esc should go back to the list")
	}
}

func TestBrowseNarrowAndOverview(t *testing.T) {
	for _, w := range []int{60, 80, 160} {
		m, _ := testBrowser(t, w, 20)
		checkFits(t, m, w, 20)
		m.Update(tea.KeyMsg{Type: tea.KeyTab})
		checkFits(t, m, w, 20)
	}
}

func TestOverviewDrillDown(t *testing.T) {
	m, _ := testBrowser(t, 100, 40)
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if m.mode != modeOverview {
		t.Fatal("tab should open the overview")
	}
	checkFits(t, m, 100, 40)
	for i, r := range m.folders {
		if r.Path == "/etc" {
			m.fsel = i
		}
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.mode != modeList || m.drill != "/etc" || len(m.rows) != 1 || m.rows[0].Subject != "/etc/foo.conf" {
		t.Fatalf("drill-down: mode %v drill %q rows %d", m.mode, m.drill, len(m.rows))
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.mode != modeOverview || m.drill != "" || len(m.rows) != 3 {
		t.Fatalf("esc should restore the overview and filters: mode %v rows %d", m.mode, len(m.rows))
	}
}

func zoneFor(m *BrowseModel, action string) (zone, bool) {
	m.View()
	for _, z := range m.zones {
		if z.action == action {
			return z, true
		}
	}
	return zone{}, false
}

func TestRescanButtonAndSortToggle(t *testing.T) {
	m, _ := testBrowser(t, 100, 30)
	z, ok := zoneFor(m, "rescan")
	if !ok {
		t.Fatal("no rescan button drawn")
	}
	_, cmd := m.Update(tea.MouseMsg{X: z.x0 + 1, Y: z.y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	if cmd == nil {
		t.Fatal("clicking the rescan button should start a scan")
	}
	if m.opt.ByTime {
		t.Fatal("default sort should be by risk")
	}
	z, _ = zoneFor(m, "sort")
	click(m, z.x0, z.y)
	if !m.opt.ByTime {
		t.Fatal("clicking the sort label should switch to time")
	}
}

func TestPersistenceTab(t *testing.T) {
	m, _ := testBrowser(t, 120, 30)
	flagged := model.Finding{Kind: model.KindPersist, Subject: "/home/alice/.bashrc", Title: "shell startup: ~/.bashrc",
		Flags: []model.Flag{model.FlagAddedLines}}
	flagged.Finalize()
	m.snap.Findings = append(m.snap.Findings, flagged)
	m.snap.Persist = []model.Entry{
		{Mechanism: "shell startup", Name: "~/.profile", Path: "/home/alice/.profile", State: "default", Why: "same as the default"},
		{Mechanism: "shell startup", Name: "~/.bashrc", Path: "/home/alice/.bashrc", State: "flagged", FindingID: flagged.ID},
		{Mechanism: "cron", Name: "0anacron", Path: "/etc/cron.hourly/0anacron", State: "default", Why: "from package cronie"},
	}
	m.rebuild()
	z, _ := zoneFor(m, "tab2")
	click(m, z.x0+1, z.y)
	if m.mode != modePersist {
		t.Fatal("clicking the Persistence tab should open it")
	}
	checkFits(t, m, 120, 30)
	if len(m.persist.entries) != 1 {
		t.Fatalf("only the entry that isn't a default should be listed, got %d", len(m.persist.entries))
	}
	if m.persist.entries[0].Name != "~/.bashrc" {
		t.Fatalf("flagged entries should come first in their group, got %q", m.persist.entries[0].Name)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.mode != modeDetail || m.detailF.ID != flagged.ID {
		t.Fatal("enter on a flagged entry should open its details")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.mode != modePersist {
		t.Fatal("esc should return to the persistence tab")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if len(m.persist.entries) != 3 {
		t.Fatalf("d should show the defaults too, got %d", len(m.persist.entries))
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if len(m.persist.entries) != 1 {
		t.Fatalf("d again should hide them, got %d", len(m.persist.entries))
	}

	// accepting the flagged entry hides it, like in the timeline
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if len(m.persist.entries) != 0 {
		t.Fatalf("an accepted entry should disappear, got %+v", m.persist.entries)
	}
	if strings.Contains(m.View(), "1 not default") {
		t.Fatal("the header should not count an accepted entry as not default")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("v")})
	if len(m.persist.entries) != 1 || m.persist.entries[0].State != "accepted" {
		t.Fatalf("v should show it marked accepted, got %+v", m.persist.entries)
	}
}

func TestReport(t *testing.T) {
	m, _ := testBrowser(t, 100, 30)
	m.snap.Persist = []model.Entry{{Mechanism: "cron", Name: "0anacron", Path: "/etc/cron.hourly/0anacron", State: "default", Why: "from package cronie"}}
	report := RenderReport(m.snap, m.acc)
	for _, f := range m.snap.Findings {
		if !strings.Contains(report, f.ID) {
			t.Errorf("report misses finding %s", f.ID)
		}
	}
	for _, want := range []string{"For AI assistants", "How to read this report", "## Persistence", "0anacron", "~/.local/bin/x"} {
		if !strings.Contains(report, want) {
			t.Errorf("report misses %q", want)
		}
	}
	if strings.Contains(report, "/home/alice") {
		t.Error("report must write the home directory as ~")
	}

	var opened string
	openEditor = func(p string) error { opened = p; return nil }
	z, ok := zoneFor(m, "report")
	if !ok || z.y != 0 {
		t.Fatalf("report link should be in the first header line, got %+v", z)
	}
	m, copied := testBrowser(t, 100, 30)
	z, _ = zoneFor(m, "report")
	click(m, z.x0+2, z.y)
	if len(*copied) == 0 || !strings.HasSuffix((*copied)[len(*copied)-1], ".md") || opened != "" {
		t.Fatalf("clicking the report button should copy its path, copied %q opened %q", *copied, opened)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
	if !strings.HasSuffix(opened, ".md") {
		t.Fatalf("e should open the report, opened %q", opened)
	}
	if z, ok := zoneFor(m, "rescan"); !ok || z.y != 29 {
		t.Fatalf("rescan button should be in the bottom row, got %+v", z)
	}
}

func TestHelpButtonAndKey(t *testing.T) {
	for _, w := range []int{80, 140} {
		m, _ := testBrowser(t, w, 32)
		z, ok := zoneFor(m, "help")
		if !ok || z.y != 0 || z.x1 != w-2 {
			t.Fatalf("width %d: help button at %+v (found %v), want top right", w, z, ok)
		}
		click(m, z.x0, z.y)
		if !m.help {
			t.Fatal("clicking the button should open help")
		}
		checkFits(t, m, w, 32)
		if !strings.Contains(m.View(), "The five tabs") {
			t.Fatal("help screen not shown")
		}
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("h")})
		if m.help {
			t.Fatal("h should close help")
		}
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("h")})
		if !m.help {
			t.Fatal("h should open help")
		}
	}
}

func TestNetworkTab(t *testing.T) {
	m, _ := testBrowser(t, 120, 30)
	flagged := model.Finding{Kind: model.KindNetwork, Subject: "/tmp/x", Title: "connections: x",
		Flags: []model.Flag{model.FlagNetStdio, model.FlagNetUnowned}}
	flagged.Finalize()
	m.snap.Findings = append(m.snap.Findings, flagged)
	m.snap.Network = []model.Entry{
		{Mechanism: "connections", Name: "chromium", Path: "/usr/lib/chromium/chromium", Runs: "12 to 1.2.3.4:443 (internet)", State: "default", Why: "from package chromium (Arch repos)"},
		{Mechanism: "connections", Name: "x", Path: "/tmp/x", Runs: "1 to 5.6.7.8:4444 (internet)", State: "flagged", FindingID: flagged.ID},
		{Mechanism: "listening", Name: "port 631 (root)", Runs: "tcp 127.0.0.1:631", State: "unreadable", Why: "program hidden"},
	}
	m.rebuild()
	for range 3 {
		m.Update(tea.KeyMsg{Type: tea.KeyTab})
	}
	if m.mode != modeNetwork {
		t.Fatalf("three tabs from the timeline should be Network, got %v", m.mode)
	}
	checkFits(t, m, 120, 30)
	if len(m.network.entries) != 2 || m.network.entries[0].Name != "x" {
		t.Fatalf("defaults should be hidden and flagged first, got %+v", m.network.entries)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.mode != modeDetail || m.detailF.ID != flagged.ID {
		t.Fatal("enter on a flagged program should open its details")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.mode != modeNetwork {
		t.Fatal("esc should return to the network tab")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if len(m.network.entries) != 3 || len(m.persist.entries) != 0 {
		t.Fatalf("d should show network defaults only: network %d persist %d", len(m.network.entries), len(m.persist.entries))
	}
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if m.mode != modeList {
		t.Fatal("tab after the last tab should wrap to the timeline")
	}
}

func TestAcceptFolder(t *testing.T) {
	m, _ := testBrowser(t, 140, 30)
	add := func(subj string, flags ...model.Flag) {
		f := model.Finding{Kind: model.KindFile, Subject: subj, Title: "unowned file", Flags: flags, Added: time.Now().Add(time.Minute)}
		f.Finalize()
		m.snap.Findings = append(m.snap.Findings, f)
	}
	add("/home/alice/Projects/app/build/app", model.FlagUnownedBinary)
	add("/home/alice/Projects/app/run.sh", model.FlagUnownedBinary)
	add("/home/alice/Projects/app/build/root-shell", model.FlagUnownedBinary, model.FlagSUID)
	m.opt.ByTime = true
	m.rebuild()
	key := func(s string) { m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}) }

	pick := func(subj string) {
		for i, f := range m.rows {
			if f.Subject == subj {
				m.sel = i
				return
			}
		}
		t.Fatalf("%s not listed", subj)
	}

	// a system binary: its folder is too broad
	pick("/usr/local/bin/tool")
	key("A")
	if m.folderAsk != "" || !m.statusErr {
		t.Fatalf("/usr/local/bin should be refused, asked %q", m.folderAsk)
	}

	// A asks about the file's own folder; A again does not climb, it cancels
	pick("/home/alice/Projects/app/build/app")
	key("A")
	if m.folderAsk != "/home/alice/Projects/app/build" {
		t.Fatalf("asked %q, want the item's folder", m.folderAsk)
	}
	key("A")
	if m.folderAsk != "" || len(m.acc) != 0 {
		t.Fatalf("A again should cancel without accepting, asked %q acc %v", m.folderAsk, m.acc)
	}

	pick("/home/alice/Projects/app/run.sh")
	key("A")
	if m.folderAsk != "/home/alice/Projects/app" {
		t.Fatalf("asked %q, want the project folder", m.folderAsk)
	}
	checkFits(t, m, 140, 30)
	if hide, high := m.folderCount(m.folderAsk); hide != 2 || high != 1 {
		t.Fatalf("count: hide %d high %d, want 2 and 1", hide, high)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.folderAsk != "" {
		t.Fatal("enter should accept and close the question")
	}
	for _, f := range m.rows {
		if strings.HasPrefix(f.Subject, "/home/alice/Projects/app/") && f.Severity < model.High {
			t.Fatalf("%s should be hidden now", f.Subject)
		}
	}

	// still a project file after it changes
	for i := range m.snap.Findings {
		if m.snap.Findings[i].Subject == "/home/alice/Projects/app/run.sh" {
			m.snap.Findings[i].Fingerprint = "rebuilt"
		}
	}
	m.rebuild()
	pick("/home/alice/Projects/app/build/root-shell") // high stays visible

	// a on an item of the folder removes the folder rule
	m.opt.ShowAccepted = true
	m.rebuild()
	pick("/home/alice/Projects/app/run.sh")
	key("a")
	if _, ok := m.acc[store.FolderKey("/home/alice/Projects/app")]; ok {
		t.Fatal("a on a folder-accepted item should remove the folder rule")
	}

	// esc cancels without accepting
	pick("/home/alice/Projects/app/run.sh")
	key("A")
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.folderAsk != "" || len(m.acc) != 0 {
		t.Fatalf("esc should cancel without accepting: %v", m.acc)
	}
}

func TestAcceptedTab(t *testing.T) {
	m, _ := testBrowser(t, 120, 30)
	add := func(subj string) model.Finding {
		f := model.Finding{Kind: model.KindFile, Subject: subj, Title: "unowned file", Flags: []model.Flag{model.FlagUnownedBinary}, Fingerprint: "v1"}
		f.Finalize()
		m.snap.Findings = append(m.snap.Findings, f)
		return f
	}
	a := add("/home/alice/Projects/app/a.out")
	b := add("/opt/thing/run")
	now := time.Now()
	m.acc[store.FolderKey("/home/alice/Projects/app")] = store.Accepted{Fingerprint: "folder", Subject: "/home/alice/Projects/app", At: now}
	m.acc[b.ID] = store.Accepted{Fingerprint: "v0", Subject: b.Subject, At: now} // changed since
	m.acc["gone123"] = store.Accepted{Fingerprint: "x", Subject: "/tmp/old", At: now.Add(-time.Hour)}
	m.rebuild()
	z, _ := zoneFor(m, "tab4")
	click(m, z.x0+1, z.y)
	if m.mode != modeAccepted {
		t.Fatal("clicking the Accepted tab should open it")
	}
	checkFits(t, m, 120, 30)
	var states []string
	for _, e := range m.accepted.entries {
		states = append(states, e.State)
	}
	if strings.Join(states, ",") != "folder,changed,gone" {
		t.Fatalf("states %v, want folder first, then items newest first", states)
	}

	// enter on a folder shows its items, accepted ones included; esc comes back
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.mode != modeList || len(m.rows) != 1 || m.rows[0].ID != a.ID {
		t.Fatalf("folder drill: mode %v rows %d", m.mode, len(m.rows))
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.mode != modeAccepted {
		t.Fatalf("esc should return to the Accepted tab, got %v", m.mode)
	}

	// a undoes the selected accept
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if _, ok := m.acc[store.FolderKey("/home/alice/Projects/app")]; ok || len(m.accepted.entries) != 2 {
		t.Fatalf("a should remove the folder rule, left %d entries", len(m.accepted.entries))
	}
}

func TestAcceptFolderOnPersistenceItem(t *testing.T) {
	m, _ := testBrowser(t, 140, 30)
	f := model.Finding{Kind: model.KindPersist, Subject: "/home/alice/.claude/settings.json", Title: "Claude Code hook: SessionStart",
		Flags: []model.Flag{model.FlagAgentHook, model.FlagRunsFromOdd}}
	f.Finalize()
	m.snap.Findings = append(m.snap.Findings, f)
	m.rebuild()
	for i, r := range m.rows {
		if r.ID == f.ID {
			m.sel = i
		}
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("A")})
	if m.folderAsk != "/home/alice/.claude" {
		t.Fatalf("asked %q (status %q), want the folder the settings file is in", m.folderAsk, m.status)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !store.IsAccepted(m.acc, f) {
		t.Fatal("the folder accept should cover the persistence item")
	}
}

func TestOverviewCountsOnlyUnusual(t *testing.T) {
	m, _ := testBrowser(t, 120, 30)
	edit := model.Finding{Kind: model.KindConfig, Subject: "/etc/pacman.conf", Title: "edited package config",
		Flags: []model.Flag{model.FlagConfigEdited, {Code: "omarchy", Label: "changed by Omarchy itself", Weight: -60}}}
	edit.Finalize()
	m.snap.Findings = append(m.snap.Findings, edit)
	for _, r := range FolderRows(m.snap, m.acc) {
		if r.Path == "/etc" && (r.Items != 1 || r.Normal != 1) {
			t.Fatalf("/etc: %d items, %d normal; want the unowned file counted and Omarchy's edit as normal", r.Items, r.Normal)
		}
	}
}
