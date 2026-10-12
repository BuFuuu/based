package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/store"
)

// The interactive browser. Five tabs (Timeline, Overview, Persistence,
// Network, Accepted) and
// a detail view where every fact is click-to-copy. Clickable things record
// where they were drawn ("zones"), so clicks always match the screen.

type browseMode int

const (
	modeList browseMode = iota
	modeOverview
	modePersist
	modeNetwork
	modeAccepted
	modeDetail
)

var tabNames = []string{"Timeline", "Overview", "Persistence", "Network", "Accepted"}

const (
	headerH     = 6 // logo (2), blank, tabs, counts, blank
	footerH     = 2 // status, keys
	doubleClick = 400 * time.Millisecond
	overviewTop = 2 // lines above the first folder row
	tabsY       = 3 // header line holding the tabs
)

// entryList is a grouped list of entries: the Persistence, Network and
// Accepted tabs.
type entryList struct {
	entries      []model.Entry
	lines        []listLine
	sel, top     int
	hideDefaults bool
}

type listLine struct {
	row   int // index into rows/entries, or -1 for a group heading
	label string
}

// zone is a clickable area drawn in the last frame.
type zone struct {
	y, x0, x1 int
	action    string
}

type statusClearMsg int
type rescannedMsg struct{ err error }

type BrowseModel struct {
	st        *store.Store
	snap      *store.Snapshot
	acc       map[string]store.Accepted
	opt       TimelineOptions
	exe       string
	scanFirst bool
	w, h      int
	mode      browseMode
	zones     []zone

	// timeline
	rows      []model.Finding
	lines     []listLine
	sel, top  int
	searching bool
	hiddenSev int

	// overview
	folders   []FolderRow
	fsel      int
	drill     string          // folder the timeline is narrowed to
	drillFrom browseMode      // tab to return to when leaving it
	savedOpt  TimelineOptions // filters to restore when leaving it

	persist, network, accepted entryList

	// detail
	detailF    model.Finding
	detailFrom browseMode
	detail     []DetailLine
	dtop       int

	help      bool   // the help screen covers the current view
	folderAsk string // folder offered for a folder accept (A), waiting for enter

	lastClick time.Time
	lastIdx   int
	status    string
	statusErr bool
	statusSeq int
}

// NewBrowse creates the browser. With scanFirst it runs a scan on start.
func NewBrowse(st *store.Store, snap *store.Snapshot, opt TimelineOptions, exe string, scanFirst bool) *BrowseModel {
	m := &BrowseModel{st: st, snap: snap, acc: st.Accepted(), opt: opt, exe: exe, scanFirst: scanFirst,
		w: Width(), h: Height(), lastIdx: -1}
	// only what isn't a default is listed; d shows the rest
	m.persist.hideDefaults = true
	m.network.hideDefaults = true
	if snap != nil {
		displayHome = snap.Home
	}
	m.rebuild()
	return m
}

func (m *BrowseModel) Init() tea.Cmd {
	if m.scanFirst || m.snap == nil {
		return m.rescan()
	}
	return nil
}

// ---- data ------------------------------------------------------------------

func (m *BrowseModel) rebuild() {
	if m.snap == nil {
		return
	}
	m.folders = FolderRows(m.snap, m.acc)
	m.fsel = clamp(m.fsel, 0, len(m.folders)-1)

	m.rows, m.hiddenSev, _ = filterFindings(m.snap, m.acc, m.opt)
	m.lines = m.lines[:0]
	group := ""
	for i, f := range m.rows {
		if g := groupLabel(f, m.opt.ByTime); g != group {
			group = g
			m.lines = append(m.lines, listLine{row: -1, label: g})
		}
		m.lines = append(m.lines, listLine{row: i})
	}
	m.sel = clamp(m.sel, 0, len(m.rows)-1)
	m.top = scrollTo(m.lines, m.sel, m.top, m.bodyH())

	m.buildList(&m.persist, m.withAccepts(m.snap.Persist))
	m.buildList(&m.network, m.withAccepts(m.snap.Network))
	m.buildList(&m.accepted, m.acceptedEntries())
}

// acceptedEntries lists what the user accepted: folder rules first, then
// single items, newest first, each with whether the accept still applies.
func (m *BrowseModel) acceptedEntries() []model.Entry {
	keys := make([]string, 0, len(m.acc))
	for k := range m.acc {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		_, di := strings.CutPrefix(keys[i], store.FolderPrefix)
		_, dj := strings.CutPrefix(keys[j], store.FolderPrefix)
		if di != dj {
			return di
		}
		return m.acc[keys[i]].At.After(m.acc[keys[j]].At)
	})
	var out []model.Entry
	for _, k := range keys {
		a := m.acc[k]
		why := "accepted " + a.At.Format("2006-01-02")
		if a.Note != "" {
			why += " · " + a.Note
		}
		if dir, ok := strings.CutPrefix(k, store.FolderPrefix); ok {
			n := 0
			for _, f := range m.snap.Findings {
				if store.FolderCovers(dir, f) {
					n++
				}
			}
			out = append(out, model.Entry{Mechanism: "folders", Name: m.tilde(dir) + "/", Path: dir,
				Runs: count(n, "item") + " hidden", State: "folder", Why: why})
			continue
		}
		e := model.Entry{Mechanism: "items", Name: m.tilde(a.Subject), Path: a.Subject, FindingID: k, State: "accepted", Why: why}
		if f, ok := m.findingByID(k); !ok {
			e.State, e.Runs = "gone", "no longer on the system"
		} else {
			e.Runs = reason(f)
			if f.Fingerprint != a.Fingerprint {
				e.State, e.Runs = "changed", "changed since, shown again"
			}
		}
		out = append(out, e)
	}
	return out
}

func count(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// unaccept removes the accept selected in the Accepted tab.
func (m *BrowseModel) unaccept() tea.Cmd {
	l := &m.accepted
	if l.sel >= len(l.entries) {
		return nil
	}
	e := l.entries[l.sel]
	key := e.FindingID
	if e.State == "folder" {
		key = store.FolderKey(e.Path)
	}
	delete(m.acc, key)
	if err := m.st.SaveAccepted(m.acc); err != nil {
		return m.setStatus(err.Error(), true)
	}
	m.rebuild()
	return m.setStatus("no longer accepted: "+e.Name, false)
}

func (m *BrowseModel) buildList(l *entryList, all []model.Entry) {
	l.entries = persistOrder(all, l.hideDefaults, m.findingByID)
	l.lines = l.lines[:0]
	group := ""
	for i, e := range l.entries {
		if e.Mechanism != group {
			group = e.Mechanism
			l.lines = append(l.lines, listLine{row: -1, label: group})
		}
		l.lines = append(l.lines, listLine{row: i})
	}
	l.sel = clamp(l.sel, 0, len(l.entries)-1)
	l.top = scrollTo(l.lines, l.sel, l.top, m.bodyH())
}

// withAccepts applies the user's accepts to scanned entries, as the
// timeline does: an accepted entry is hidden, or with v marked accepted.
func (m *BrowseModel) withAccepts(all []model.Entry) []model.Entry {
	out := make([]model.Entry, 0, len(all))
	for _, e := range all {
		if e.State == "flagged" {
			if f, ok := m.findingByID(e.FindingID); ok && store.IsAccepted(m.acc, f) {
				if !m.opt.ShowAccepted {
					continue
				}
				e.State, e.Why = "accepted", "accepted by you · "+e.Why
			}
		}
		out = append(out, e)
	}
	return out
}

// list is the entry list of the current tab (Persistence or Network).
func (m *BrowseModel) list() *entryList {
	mode := m.mode
	if mode == modeDetail {
		mode = m.detailFrom
	}
	switch mode {
	case modeNetwork:
		return &m.network
	case modeAccepted:
		return &m.accepted
	}
	return &m.persist
}

// snapEntries returns all entries of the current entry tab, before filtering.
func (m *BrowseModel) snapEntries() []model.Entry {
	switch {
	case m.snap == nil:
		return nil
	case m.list() == &m.network:
		return m.snap.Network
	case m.list() == &m.accepted:
		return m.accepted.entries
	}
	return m.snap.Persist
}

func clamp(v, lo, hi int) int { return max(lo, min(v, max(hi, lo))) }

func (m *BrowseModel) bodyH() int { return max(m.h-headerH-footerH, 3) }

// scrollTo returns a top line that keeps row sel (and its heading) visible.
func scrollTo(lines []listLine, sel, top, height int) int {
	li := 0
	for i, l := range lines {
		if l.row == sel {
			li = i
			break
		}
	}
	first := li
	if first > 0 && lines[first-1].row < 0 {
		first-- // keep the heading above the first row of a group
	}
	if first < top {
		top = first
	}
	if li >= top+height {
		top = li - height + 1
	}
	return clamp(top, 0, len(lines)-1)
}

func (m *BrowseModel) findingByID(id string) (model.Finding, bool) {
	if m.snap == nil || id == "" {
		return model.Finding{}, false
	}
	for _, f := range m.snap.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}

// target is the item the action keys work on in the current view.
func (m *BrowseModel) target() (model.Finding, bool) {
	switch m.mode {
	case modeDetail:
		return m.detailF, true
	case modeList:
		if m.sel < len(m.rows) {
			return m.rows[m.sel], true
		}
	case modePersist, modeNetwork, modeAccepted:
		if l := m.list(); l.sel < len(l.entries) {
			e := l.entries[l.sel]
			if f, ok := m.findingByID(e.FindingID); ok {
				return f, true
			}
			// a default entry: offer the path-based actions
			return model.Finding{Kind: model.KindFile, Subject: e.Path, Title: e.Mechanism + ": " + e.Name}, true
		}
	}
	return model.Finding{}, false
}

// ---- actions ---------------------------------------------------------------

func (m *BrowseModel) setStatus(msg string, isErr bool) tea.Cmd {
	m.status, m.statusErr = msg, isErr
	m.statusSeq++
	seq := m.statusSeq
	return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return statusClearMsg(seq) })
}

func (m *BrowseModel) openDetail(f model.Finding) {
	if m.mode != modeDetail {
		m.detailFrom = m.mode
	}
	m.detailF = f
	m.detail = DetailLines(f, store.IsAccepted(m.acc, f), min(m.w, 120), false)
	m.dtop = 0
	m.mode = modeDetail
}

func (m *BrowseModel) enter() tea.Cmd {
	switch m.mode {
	case modeList:
		if f, ok := m.target(); ok {
			m.openDetail(f)
		}
	case modeOverview:
		return m.enterFolder()
	case modePersist, modeNetwork, modeAccepted:
		l := m.list()
		if l.sel >= len(l.entries) {
			return nil
		}
		e := l.entries[l.sel]
		if e.State == "folder" {
			return m.drillInto(e.Path, true)
		}
		if f, ok := m.findingByID(e.FindingID); ok {
			m.openDetail(f)
			return nil
		}
		return m.setStatus(e.Name+": "+e.Why, false)
	}
	return nil
}

func (m *BrowseModel) back() {
	m.mode = m.detailFrom
}

// enterFolder narrows the timeline to one folder, showing every item there.
func (m *BrowseModel) enterFolder() tea.Cmd {
	if m.fsel >= len(m.folders) {
		return nil
	}
	r := m.folders[m.fsel]
	if r.Items == 0 && r.Normal == 0 {
		return m.setStatus(r.Path+": nothing non-default to show", false)
	}
	return m.drillInto(r.Path, false)
}

// drillInto narrows the timeline to one folder; esc returns to the tab it
// came from. From the Accepted tab it shows the accepted items too.
func (m *BrowseModel) drillInto(path string, withAccepted bool) tea.Cmd {
	if m.drill == "" {
		m.savedOpt, m.drillFrom = m.opt, m.mode
	}
	m.drill = path
	m.opt = TimelineOptions{MinSeverity: m.savedOpt.MinSeverity, ShowAccepted: withAccepted || m.savedOpt.ShowAccepted, ByTime: m.savedOpt.ByTime}
	if withAccepted || m.mode == modeOverview && m.fsel < len(m.folders) && m.folders[m.fsel].Items == 0 {
		m.opt.MinSeverity = model.Info // only normal items there, or an accepted folder: show them all
	}
	if path == "packages" {
		m.opt.Kind = string(model.KindPackage)
	} else {
		m.opt.In = path
	}
	m.mode, m.sel, m.top = modeList, 0, 0
	m.rebuild()
	return nil
}

func (m *BrowseModel) leaveFolder() {
	m.opt, m.drill = m.savedOpt, ""
	m.mode, m.sel, m.top = m.drillFrom, 0, 0
	m.rebuild()
}

func (m *BrowseModel) switchTab(mode browseMode) {
	if m.drill != "" {
		m.opt, m.drill = m.savedOpt, ""
		m.rebuild()
	}
	m.mode = mode
}

func (m *BrowseModel) toggleSort() tea.Cmd {
	m.opt.ByTime = !m.opt.ByTime
	m.sel, m.top = 0, 0
	m.rebuild()
	if m.opt.ByTime {
		return m.setStatus("sorted by time: newest first", false)
	}
	return m.setStatus("sorted by how unusual: most unusual first", false)
}

func (m *BrowseModel) toggleAccepted() tea.Cmd {
	m.opt.ShowAccepted = !m.opt.ShowAccepted
	m.rebuild()
	if m.opt.ShowAccepted {
		return m.setStatus("showing accepted items", false)
	}
	return m.setStatus("hiding accepted items", false)
}

func (m *BrowseModel) toggleDefaults() tea.Cmd {
	l := m.list()
	l.hideDefaults = !l.hideDefaults
	l.sel, l.top = 0, 0
	m.rebuild()
	if l.hideDefaults {
		return m.setStatus("showing only what is not default", false)
	}
	return m.setStatus("showing everything, defaults included", false)
}

// copyReportPath refreshes the report and copies its path, ready to paste
// into an AI assistant.
func (m *BrowseModel) copyReportPath() tea.Cmd {
	if m.snap == nil {
		return m.setStatus("no scan yet", true)
	}
	path, err := WriteReport(m.st, m.snap, m.acc)
	if err != nil {
		return m.setStatus("could not write the report: "+err.Error(), true)
	}
	if err := clipboard(path); err != nil {
		return m.setStatus(err.Error(), true)
	}
	return m.setStatus("copied the path of the report for AI: paste it into your AI assistant · e opens it", false)
}

// openReport refreshes the Markdown report (so accepts are current) and
// opens it in the default editor.
func (m *BrowseModel) openReport() tea.Cmd {
	if m.snap == nil {
		return m.setStatus("no scan yet", true)
	}
	path, err := WriteReport(m.st, m.snap, m.acc)
	if err != nil {
		return m.setStatus("could not write the report: "+err.Error(), true)
	}
	if err := openEditor(path); err != nil {
		return m.setStatus("could not open an editor: "+err.Error(), true)
	}
	return m.setStatus("opened the report for AI in your editor", false)
}

func (m *BrowseModel) rescan() tea.Cmd {
	return tea.ExecProcess(exec.Command(m.exe, "scan"), func(err error) tea.Msg { return rescannedMsg{err} })
}

// rescanRoot suspends the browser so sudo can ask for the password in the
// terminal, then scans with full coverage.
func (m *BrowseModel) rescanRoot() tea.Cmd {
	return tea.ExecProcess(exec.Command(m.exe, "scan", "--sudo"), func(err error) tea.Msg { return rescannedMsg{err} })
}

// action runs one of the item actions shared by all views.
func (m *BrowseModel) action(key string) tea.Cmd {
	f, ok := m.target()
	if !ok {
		return nil
	}
	switch key {
	case "c":
		if f.Kind == model.KindPackage {
			return m.copy(f.Subject, "package name")
		}
		return m.copy(f.Subject, "path")
	case "s":
		h, err := itemHash(f)
		if err != nil {
			return m.setStatus(err.Error(), true)
		}
		return m.copy(h, "sha256")
	case "p":
		return m.copy(Prompt(f, m.snap.Home), "AI prompt")
	case "o":
		dir, err := openFolder(f)
		if err != nil {
			return m.setStatus(err.Error(), true)
		}
		return m.setStatus("opened "+dir, false)
	case "a":
		if f.ID == "" {
			return m.setStatus("this is a default; nothing to accept", false)
		}
		msg := "accepted: hidden until it changes"
		if dir := store.AcceptedFolder(m.acc, f); dir != "" && !m.exactAccept(f) {
			delete(m.acc, store.FolderKey(dir))
			msg = "folder no longer accepted: " + m.tilde(dir)
		} else if store.IsAccepted(m.acc, f) {
			delete(m.acc, f.ID)
			msg = "no longer accepted"
		} else {
			m.acc[f.ID] = store.Accepted{Fingerprint: f.Fingerprint, Subject: f.Subject, At: time.Now()}
		}
		if err := m.st.SaveAccepted(m.acc); err != nil {
			return m.setStatus(err.Error(), true)
		}
		if m.mode == modeDetail {
			m.detail = DetailLines(f, store.IsAccepted(m.acc, f), min(m.w, 120), false)
		}
		m.rebuild()
		return m.setStatus(msg, false)
	}
	return nil
}

func (m *BrowseModel) exactAccept(f model.Finding) bool {
	a, ok := m.acc[f.ID]
	return ok && a.Fingerprint == f.Fingerprint
}

func (m *BrowseModel) tilde(path string) string {
	if m.snap != nil && m.snap.Home != "" && (path == m.snap.Home || strings.HasPrefix(path, m.snap.Home+"/")) {
		return "~" + path[len(m.snap.Home):]
	}
	return path
}

// askFolder asks whether to accept the folder the current item is in. It
// only asks; enter confirms. Top folders and folders shared by many programs
// are refused.
func (m *BrowseModel) askFolder() tea.Cmd {
	f, ok := m.target()
	if !ok {
		return nil
	}
	if !strings.HasPrefix(f.Subject, "/") {
		return m.setStatus("packages have no folder; press a to accept this one", true)
	}
	// a folder is offered itself, anything else the folder it is in
	dir := filepath.Dir(f.Subject)
	if info, err := os.Stat(f.Subject); f.Kind == model.KindTree || strings.HasSuffix(f.Subject, "/") || (err == nil && info.IsDir()) {
		dir = strings.TrimSuffix(f.Subject, "/")
	}
	home := ""
	if m.snap != nil {
		home = m.snap.Home
	}
	if ok, why := store.FolderAllowed(dir, home); !ok {
		return m.setStatus("can't accept the whole folder: "+why, true)
	}
	m.folderAsk = dir
	m.status = ""
	return nil
}

// folderCount counts the open items a folder accept would hide, and the
// high ones it would leave visible.
func (m *BrowseModel) folderCount(dir string) (hide, high int) {
	if m.snap == nil {
		return 0, 0
	}
	for _, f := range m.snap.Findings {
		if store.IsAccepted(m.acc, f) {
			continue
		}
		if store.FolderCovers(dir, f) {
			hide++
		} else if f.Severity >= model.High {
			g := f
			g.Severity = model.Med
			if store.FolderCovers(dir, g) {
				high++
			}
		}
	}
	return hide, high
}

func (m *BrowseModel) acceptFolder() tea.Cmd {
	dir := m.folderAsk
	m.folderAsk = ""
	hide, _ := m.folderCount(dir)
	m.acc[store.FolderKey(dir)] = store.Accepted{Fingerprint: "folder", Subject: dir, At: time.Now()}
	if err := m.st.SaveAccepted(m.acc); err != nil {
		return m.setStatus(err.Error(), true)
	}
	if m.mode == modeDetail {
		m.detail = DetailLines(m.detailF, store.IsAccepted(m.acc, m.detailF), min(m.w, 120), false)
	}
	m.rebuild()
	return m.setStatus(fmt.Sprintf("accepted %s: %d items hidden, also after changes · a on one of them undoes it", m.tilde(dir), hide), false)
}

func (m *BrowseModel) copy(text, what string) tea.Cmd {
	if err := clipboard(text); err != nil {
		return m.setStatus(err.Error(), true)
	}
	shown := text
	switch what {
	case "AI prompt":
		shown = "the AI prompt, paste it into your AI assistant"
	case "path":
		shown = ShortPath(text, max(m.w-30, 30))
	default:
		shown = what + " " + shown
	}
	return m.setStatus("Copied to clipboard: "+TruncRight(strings.ReplaceAll(shown, "\n", " "), max(m.w-30, 30)), false)
}

// ---- input -----------------------------------------------------------------

func (m *BrowseModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		if m.mode == modeDetail {
			m.detail = DetailLines(m.detailF, store.IsAccepted(m.acc, m.detailF), min(m.w, 120), false)
		}
		m.rebuild()
	case statusClearMsg:
		if int(msg) == m.statusSeq {
			m.status = ""
		}
	case rescannedMsg:
		if snap, err := m.st.Latest(); err == nil && snap != nil {
			m.snap, m.acc = snap, m.st.Accepted()
			displayHome = snap.Home
			m.rebuild()
		}
		if m.mode == modeDetail {
			m.mode = m.detailFrom
		}
		if msg.err != nil {
			return m, m.setStatus("scan failed: "+msg.err.Error(), true)
		}
		return m, m.setStatus("scan finished", false)
	case tea.MouseMsg:
		return m, m.mouse(msg)
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *BrowseModel) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	if key == "ctrl+c" {
		return m, tea.Quit
	}
	if m.searching {
		switch k.Type {
		case tea.KeyEnter:
			m.searching = false
		case tea.KeyEsc:
			m.searching, m.opt.Query = false, ""
		case tea.KeyBackspace:
			if r := []rune(m.opt.Query); len(r) > 0 {
				m.opt.Query = string(r[:len(r)-1])
			}
		case tea.KeyRunes, tea.KeySpace:
			m.opt.Query += string(k.Runes)
		}
		m.sel, m.top = 0, 0
		m.rebuild()
		return m, nil
	}

	if m.folderAsk != "" {
		if key == "enter" || key == "y" {
			return m, m.acceptFolder()
		}
		m.folderAsk = "" // any other key, A too, says no
		return m, m.setStatus("nothing accepted", false)
	}
	if key == "A" && !m.help {
		return m, m.askFolder()
	}

	if m.help {
		switch key {
		case "h", "?", "esc", "backspace", "q", "enter":
			m.help = false
		}
		return m, nil
	}
	if key == "h" || key == "?" {
		m.help = true
		return m, nil
	}

	if m.mode == modeDetail {
		maxTop := max(len(m.detail)-(m.h-1-footerH), 0)
		switch key {
		case "esc", "backspace", "left", "q":
			m.back()
		case "up", "k":
			m.dtop = max(m.dtop-1, 0)
		case "down", "j":
			m.dtop = min(m.dtop+1, maxTop)
		case "pgup":
			m.dtop = max(m.dtop-(m.h-4), 0)
		case "pgdown", " ":
			m.dtop = min(m.dtop+(m.h-4), maxTop)
		case "n", "b":
			if m.detailFrom == modeList && len(m.rows) > 0 {
				if key == "n" {
					m.sel = min(m.sel+1, len(m.rows)-1)
				} else {
					m.sel = max(m.sel-1, 0)
				}
				m.openDetail(m.rows[m.sel])
			}
		case "r":
			return m, m.rescan()
		case "R":
			return m, m.rescanRoot()
		case "e":
			return m, m.openReport()
		default:
			return m, m.action(key)
		}
		return m, nil
	}

	// keys shared by the three tabs
	switch key {
	case "tab":
		m.switchTab((m.mode + 1) % browseMode(len(tabNames)))
		return m, nil
	case "shift+tab":
		m.switchTab((m.mode + browseMode(len(tabNames)) - 1) % browseMode(len(tabNames)))
		return m, nil
	case "r":
		return m, m.rescan()
	case "R":
		return m, m.rescanRoot()
	case "e":
		return m, m.openReport()
	case "enter", "right", "l":
		return m, m.enter()
	case "q":
		return m, tea.Quit
	case "esc", "backspace", "left":
		switch {
		case m.mode == modeList && m.opt.Query != "":
			m.opt.Query = ""
			m.rebuild()
		case m.drill != "":
			m.leaveFolder()
		case key == "esc":
			return m, tea.Quit
		}
		return m, nil
	}

	switch m.mode {
	case modeOverview:
		switch key {
		case "up", "k":
			m.fsel = max(m.fsel-1, 0)
		case "down", "j":
			m.fsel = min(m.fsel+1, len(m.folders)-1)
		}
		return m, nil

	case modePersist, modeNetwork, modeAccepted:
		l := m.list()
		if m.mode == modeAccepted && key == "a" {
			return m, m.unaccept()
		}
		switch key {
		case "up", "k":
			l.sel = max(l.sel-1, 0)
		case "down", "j":
			l.sel = min(l.sel+1, len(l.entries)-1)
		case "pgup":
			l.sel = max(l.sel-m.bodyH(), 0)
		case "pgdown":
			l.sel = min(l.sel+m.bodyH(), len(l.entries)-1)
		case "d":
			if m.mode == modeAccepted {
				return m, nil
			}
			return m, m.toggleDefaults()
		case "v":
			return m, m.toggleAccepted()
		default:
			return m, m.action(key)
		}
		l.top = scrollTo(l.lines, l.sel, l.top, m.bodyH())
		return m, nil
	}

	// timeline
	switch key {
	case "up", "k":
		m.sel = max(m.sel-1, 0)
	case "down", "j":
		m.sel = min(m.sel+1, len(m.rows)-1)
	case "pgup":
		m.sel = max(m.sel-m.bodyH(), 0)
	case "pgdown":
		m.sel = min(m.sel+m.bodyH(), len(m.rows)-1)
	case "home", "g":
		m.sel = 0
	case "end", "G":
		m.sel = len(m.rows) - 1
	case "t":
		return m, m.toggleSort()
	case "/":
		m.searching = true
		return m, nil
	case "1", "2", "3", "4":
		m.opt.MinSeverity = model.Severity(4 - int(key[0]-'0'))
		m.sel, m.top = 0, 0
		m.rebuild()
		return m, m.setStatus("showing "+m.opt.MinSeverity.Label()+" and above", false)
	case "v":
		return m, m.toggleAccepted()
	default:
		return m, m.action(key)
	}
	m.top = scrollTo(m.lines, m.sel, m.top, m.bodyH())
	return m, nil
}

func (m *BrowseModel) mouse(e tea.MouseMsg) tea.Cmd {
	if m.help {
		if e.Action == tea.MouseActionPress && e.Button == tea.MouseButtonLeft {
			m.help = false
		}
		return nil
	}
	if m.folderAsk != "" && e.Action == tea.MouseActionPress {
		m.folderAsk = ""
	}
	if e.Button == tea.MouseButtonWheelUp || e.Button == tea.MouseButtonWheelDown {
		d := 3
		if e.Button == tea.MouseButtonWheelUp {
			d = -3
		}
		switch m.mode {
		case modeDetail:
			m.dtop = clamp(m.dtop+d, 0, len(m.detail)-(m.h-1-footerH))
		case modeOverview:
			m.fsel = clamp(m.fsel+d/3, 0, len(m.folders)-1)
		case modePersist, modeNetwork, modeAccepted:
			l := m.list()
			l.sel = clamp(l.sel+d, 0, len(l.entries)-1)
			l.top = scrollTo(l.lines, l.sel, l.top, m.bodyH())
		case modeList:
			m.sel = clamp(m.sel+d, 0, len(m.rows)-1)
			m.top = scrollTo(m.lines, m.sel, m.top, m.bodyH())
		}
		return nil
	}
	if e.Action != tea.MouseActionPress || e.Button != tea.MouseButtonLeft {
		return nil
	}
	if m.help {
		m.help = false
		return nil
	}

	for _, z := range m.zones {
		if e.Y == z.y && e.X >= z.x0 && e.X < z.x1 {
			switch z.action {
			case "rescan":
				return m.rescan()
			case "rescan-root":
				return m.rescanRoot()
			case "report":
				return m.copyReportPath()
			case "sort":
				return m.toggleSort()
			case "defaults":
				return m.toggleDefaults()
			case "back":
				m.back()
			case "help":
				m.help = true
			case "tab0", "tab1", "tab2", "tab3", "tab4":
				m.switchTab(browseMode(z.action[3] - '0'))
			}
			return nil
		}
	}

	// double-click detection on the same row
	clicked := func(idx int) bool {
		again := idx == m.lastIdx && time.Since(m.lastClick) < doubleClick
		m.lastIdx, m.lastClick = idx, time.Now()
		return again
	}
	switch m.mode {
	case modeDetail:
		li := m.dtop + e.Y - 1
		if li >= 0 && li < len(m.detail) && m.detail[li].Copy != "" {
			return m.copy(m.detail[li].Copy, "value")
		}
	case modeOverview:
		i := e.Y - headerH - overviewTop
		if i < 0 || i >= len(m.folders) {
			return nil
		}
		m.fsel = i
		if clicked(1000 + i) {
			return m.enterFolder()
		}
	case modePersist, modeNetwork, modeAccepted:
		l := m.list()
		li := l.top + e.Y - headerH
		if e.Y < headerH || li >= len(l.lines) || l.lines[li].row < 0 {
			return nil
		}
		l.sel = l.lines[li].row
		if clicked(2000 + 1000*int(m.mode) + l.sel) {
			return m.enter()
		}
		// a click copies its path, as in the timeline
		if en := l.entries[l.sel]; en.Path != "" {
			return m.copy(en.Path, "path")
		}
	case modeList:
		li := m.top + e.Y - headerH
		if e.Y < headerH || li >= len(m.lines) || m.lines[li].row < 0 {
			return nil
		}
		m.sel = m.lines[li].row
		again := clicked(m.sel)
		_, subjW := rowColumns(m.w)
		switch {
		case e.X >= rowSubjectX && e.X < rowSubjectX+subjW:
			return m.action("c") // click on the path copies it
		case again:
			return m.enter()
		}
	}
	return nil
}

// ---- view ------------------------------------------------------------------

func (m *BrowseModel) View() string {
	if m.w == 0 {
		return ""
	}
	m.zones = m.zones[:0]
	var lines []string
	switch {
	case m.help:
		lines = m.viewHelp()
	case m.mode == modeDetail:
		lines = m.viewDetail()
	case m.mode == modeOverview:
		lines = append(m.viewHeader(), m.viewOverview()...)
	case m.mode == modePersist || m.mode == modeNetwork || m.mode == modeAccepted:
		lines = append(m.viewHeader(), m.viewEntries()...)
	default:
		lines = append(m.viewHeader(), m.viewList()...)
	}
	body := m.h - footerH
	for len(lines) < body {
		lines = append(lines, "")
	}
	lines = lines[:body]
	lines = append(lines, m.viewStatus(), m.viewKeys(m.h-1))
	for i := range lines {
		lines[i] = TruncRight(lines[i], m.w) // never wrap: it would shift click targets
	}
	return strings.Join(lines, "\n")
}

// place appends a clickable piece to a line being built and records its zone.
func (m *BrowseModel) place(line *string, y int, text, action string) {
	x := lipgloss.Width(*line)
	*line += text
	m.zones = append(m.zones, zone{y: y, x0: x, x1: x + lipgloss.Width(text), action: action})
}

func button(label string) string {
	return lipgloss.NewStyle().Foreground(cBlack).Background(cCyan).Bold(true).Render(" " + label + " ")
}

// placeHelp puts the help button at the right end of line y.
func (m *BrowseModel) placeHelp(line *string, y int) {
	b := lipgloss.NewStyle().Foreground(cBlack).Background(cFg).Bold(true).Render(" h ")
	if gap := m.w - 2 - lipgloss.Width(*line) - lipgloss.Width(b); gap > 0 {
		*line += strings.Repeat(" ", gap)
		m.place(line, y, b, "help")
	}
}

func (m *BrowseModel) viewHeader() []string {
	logo := Logo()
	sub := "no scan yet"
	host := ""
	if m.snap != nil {
		sub = "last scan " + Ago(m.snap.ScannedAt)
		if !m.snap.AsRoot {
			sub += " · user scan (partial, press R to scan as root)"
		}
		host = m.snap.Host
	}

	line0 := "  " + logo[0] + "   " + sTitle.Render("Based") + sDim.Render("  ·  "+host) + "   "
	if m.snap != nil {
		m.place(&line0, 0, button("▤ Report for AI  e"), "report")
	}
	m.placeHelp(&line0, 0)
	line1 := "  " + logo[1] + "   " + sDim.Render(sub)

	// tabs look like buttons, with a key hint so it is obvious they switch
	line2 := "  " + sDim.Render("⇥ ") + lipgloss.NewStyle().Foreground(cBlack).Background(cFg).Bold(true).Render(" tab ") + " "
	for i, name := range tabNames {
		label := " " + name + " "
		if browseMode(i) == m.mode {
			label = lipgloss.NewStyle().Foreground(cBlack).Background(cMagenta).Bold(true).Render("▸" + label)
		} else {
			label = lipgloss.NewStyle().Foreground(cBright).Background(cDim).Render(" " + label)
		}
		m.place(&line2, tabsY, label, fmt.Sprintf("tab%d", i))
		line2 += " "
	}
	line2 += "  "
	switch m.mode {
	case modeList:
		sortLabel := "unusual"
		if m.opt.ByTime {
			sortLabel = "time"
		}
		m.place(&line2, tabsY, sCyan.Render("⇅ t")+sDim.Render(" sort: ")+sFg.Render(sortLabel), "sort")
		info := fmt.Sprintf("  ·  %d items · %s and above", len(m.rows), m.opt.MinSeverity.Label())
		if m.drill != "" {
			info = "  ·  " + "in " + m.drill + fmt.Sprintf(" · %d items · %s and above · 1-4 level", len(m.rows), m.opt.MinSeverity.Label())
		}
		line2 += sDim.Render(info)
		if m.opt.Query != "" || m.searching {
			cursor := ""
			if m.searching {
				cursor = "█"
			}
			line2 += sDim.Render(" · search: ") + sFg.Render(m.opt.Query+cursor)
		}
	case modeAccepted:
		folders := 0
		for _, e := range m.accepted.entries {
			if e.State == "folder" {
				folders++
			}
		}
		line2 += sDim.Render(count(folders, "folder") + " · " + count(len(m.accepted.entries)-folders, "item"))
	case modePersist, modeNetwork:
		flagged := 0
		for _, e := range m.withAccepts(m.snapEntries()) {
			if e.State == "flagged" {
				flagged++
			}
		}
		noun := "entries"
		if m.mode == modeNetwork {
			noun = "programs"
		}
		line2 += sDim.Render(fmt.Sprintf("%d %s · ", len(m.snapEntries()), noun))
		if flagged > 0 {
			line2 += sYellowText(fmt.Sprintf("%d not default", flagged))
		} else {
			line2 += sGreen.Render("all default")
		}
		label := "  ◉ showing defaults"
		if m.list().hideDefaults {
			label = "  ○ defaults hidden"
		}
		m.place(&line2, tabsY, sCyan.Render(label), "defaults")
	}

	counts := ""
	if m.snap != nil {
		counts = countsLine(m.snap, m.acc)
	}
	return []string{line0, line1, "", line2, "  " + counts, ""}
}

func heading(label string, w int) string {
	l := " " + label + " "
	return "  " + sTitle.Render(l) + sRule.Render(strings.Repeat("─", max(w-6-lipgloss.Width(l), 4)))
}

func (m *BrowseModel) viewList() []string {
	if m.snap == nil {
		return []string{"  " + sDim.Render("No scan yet. Press r to scan.")}
	}
	if len(m.rows) == 0 {
		return []string{"  " + sGreen.Render("Nothing to show with these filters.")}
	}
	var out []string
	for i := m.top; i < len(m.lines) && len(out) < m.bodyH(); i++ {
		l := m.lines[i]
		if l.row < 0 {
			out = append(out, heading(l.label, m.w))
			continue
		}
		f := m.rows[l.row]
		text := row(f, m.w, store.IsAccepted(m.acc, f), m.opt.ByTime)
		if l.row == m.sel {
			text = sAccent.Render("▌ ") + strings.TrimPrefix(text, "  ")
		}
		out = append(out, text)
	}
	return out
}

func (m *BrowseModel) viewOverview() []string {
	if m.snap == nil {
		return []string{"  " + sDim.Render("No scan yet. Press r to scan.")}
	}
	out := []string{"  " + sAccent.Render("Everything under /"), FolderTableHeader()}
	for i, r := range m.folders {
		out = append(out, FolderLine(r, m.w, i == m.fsel))
	}
	out = append(out, "", "  "+sDim.Render("✓ scanned  ◐ partly readable  ↪ link  ∿ virtual  ○ not scanned"), "")
	var b strings.Builder
	TrustTable(&b, m.snap)
	return append(out, strings.Split(b.String(), "\n")...)
}

func (m *BrowseModel) viewEntries() []string {
	what, clean := "persistence", "Everything that starts automatically is a default. Press d to see them."
	if m.mode == modeNetwork {
		what, clean = "network", "Every program on the network comes from Arch or Omarchy. Press d to see them."
	}
	if m.snap == nil {
		return []string{"  " + sDim.Render("No scan yet. Press r to scan.")}
	}
	if m.mode == modeAccepted && len(m.accepted.entries) == 0 {
		return []string{"  " + sDim.Render("Nothing accepted yet. Press a on an item you know, or A for its whole folder.")}
	}
	if len(m.snapEntries()) == 0 {
		return []string{"  " + sDim.Render("This scan has no "+what+" data. Press r to rescan.")}
	}
	l := m.list()
	if len(l.entries) == 0 {
		return []string{"  " + sGreen.Render(clean)}
	}
	var out []string
	for i := l.top; i < len(l.lines) && len(out) < m.bodyH(); i++ {
		ln := l.lines[i]
		if ln.row < 0 {
			out = append(out, heading(ln.label, m.w))
			continue
		}
		out = append(out, m.entryLine(l.entries[ln.row], ln.row == l.sel))
	}
	return out
}

// entryLine renders one persistence entry: what it is, what it runs, and
// why it is (or isn't) a default.
func (m *BrowseModel) entryNameW() int { return min(max(m.w/4, 20), 44) }

func (m *BrowseModel) entryLine(e model.Entry, sel bool) string {
	lead := "  "
	if sel {
		lead = sAccent.Render("▌ ")
	}
	nameW := m.entryNameW()
	runsW := min(max(m.w/4, 16), 50)
	var mark, name string
	switch e.State {
	case "flagged":
		sev := model.Low
		if f, ok := m.findingByID(e.FindingID); ok {
			sev = f.Severity
		}
		mark = Badge(sev)
		name = lipgloss.NewStyle().Foreground(SevColor(sev)).Render(Pad(TruncRight(e.Name, nameW), nameW))
	case "unreadable":
		mark = sYellowText("  ?   ")
		name = sDim.Render(Pad(TruncRight(e.Name, nameW), nameW))
	case "folder":
		mark = sGreen.Render("  ▣   ")
		name = sFg.Render(Pad(TruncRight(e.Name, nameW), nameW))
	case "changed":
		mark = sYellowText("  !   ")
		name = sFg.Render(Pad(TruncRight(e.Name, nameW), nameW))
	case "gone":
		mark = sDim.Render("  –   ")
		name = sDim.Render(Pad(TruncRight(e.Name, nameW), nameW))
	default:
		mark = sGreen.Render("  ✓   ")
		name = sFg.Render(Pad(TruncRight(e.Name, nameW), nameW))
	}
	runs := sDim.Render(Pad(TruncRight(e.Runs, runsW), runsW))
	return lead + mark + " " + name + "  " + runs + "  " + sDim.Render(e.Why)
}

func (m *BrowseModel) viewDetail() []string {
	pos := ""
	if m.detailFrom == modeList && len(m.rows) > 0 {
		pos = fmt.Sprintf("item %d of %d", m.sel+1, len(m.rows))
	}
	line := "  "
	m.place(&line, 0, sAccent.Render("‹ back"), "back")
	line += sDim.Render("  esc   " + pos)
	m.placeHelp(&line, 0)
	out := []string{line}
	for i := m.dtop; i < len(m.detail) && len(out) < m.h-footerH; i++ {
		out = append(out, m.detail[i].Text)
	}
	return out
}

func (m *BrowseModel) viewHelp() []string {
	h := func(s string) string { return "  " + sAccent.Render(s) }
	t := func(s string) string { return "    " + sFg.Render(s) }
	k := func(key, label string) string { return "    " + sCyan.Render(Pad(key, 13)) + sFg.Render(label) }
	return []string{
		"",
		"  " + sTitle.Render("Based") + sDim.Render("  ·  help"),
		"",
		h("The idea"),
		t("Omarchy puts a known set of things on your computer."),
		t("Based shows you everything else: what came later, and when."),
		t("It only looks. It never changes or deletes anything."),
		t("It is not an antivirus: it does not scan for virus signatures."),
		"",
		h("An example"),
		t("You install an app from the AUR. It quietly brings along"),
		t("another package you never chose. Based lists that package"),
		t("as new, with the day it came and how unusual it is."),
		t("You press p and ask your AI what it is and why it is there."),
		"",
		h("The five tabs"),
		k("Timeline", "everything new, most unusual first"),
		k("Overview", "every folder, and how much is new in it"),
		k("Persistence", "things that start by themselves"),
		k("Network", "programs that talk to the network right now"),
		k("Accepted", "what you marked as known; undo it here"),
		"",
		h("Getting around"),
		k("tab", "next tab, or click a tab"),
		k("↑ ↓", "move up and down"),
		k("enter", "open an item"),
		k("esc", "go back"),
		k("p", "copy a question about it for your AI"),
		k("a", "accept: you know it, hide it until it changes"),
		k("A", "accept the whole folder it is in (asks first)"),
		k("r", "scan again"),
		k("h", "open or close this help"),
		k("q", "quit"),
	}
}

func (m *BrowseModel) viewStatus() string {
	if m.folderAsk != "" {
		hide, high := m.folderCount(m.folderAsk)
		q := fmt.Sprintf("Accept everything in %s? %d items, also when they change later", m.tilde(m.folderAsk), hide)
		if high > 0 {
			q += fmt.Sprintf(" (%d very unusual stay visible)", high)
		}
		return "  " + sYellowText("? ") + sFg.Render(q) + sDim.Render("   ") +
			sCyan.Render("enter") + sDim.Render(" yes  ") + sCyan.Render("esc") + sDim.Render(" no")
	}
	if m.status == "" {
		return ""
	}
	if m.statusErr {
		return "  " + lipgloss.NewStyle().Foreground(cRed).Render("✗ "+m.status)
	}
	if rest, ok := strings.CutPrefix(m.status, "Copied to clipboard:"); ok {
		return "  " + sGreen.Bold(true).Render("✓ Copied to clipboard:") + sFg.Render(rest)
	}
	return "  " + sGreen.Render("✓ ") + sFg.Render(m.status)
}

// viewKeys is the bottom row: the rescan button, then the keys for this view.
func (m *BrowseModel) viewKeys(y int) string {
	k := func(key, label string) string { return sCyan.Render(key) + " " + sDim.Render(label) }
	var parts []string
	switch {
	case m.help:
		parts = []string{k("h/esc", "close help")}
	case m.mode == modeDetail:
		parts = []string{k("click", "copy value"), k("c", "path"), k("s", "sha256"), k("o", "open folder"),
			k("p", "AI prompt"), k("a", "accept"), k("A", "folder"), k("n/b", "next/prev"), k("esc", "back")}
	case m.mode == modeOverview:
		parts = []string{k("↑↓", "select folder"), k("⏎", "show its items")}
	case m.mode == modeAccepted:
		parts = []string{k("↑↓", "select"), k("⏎", "details / folder items"), k("a", "undo accept"), k("c", "copy path"),
			k("o", "open folder"), sGreen.Render("▣") + sDim.Render(" folder ") + sYellowText("!") + sDim.Render(" changed ") + sDim.Render("– gone")}
	case m.mode == modePersist || m.mode == modeNetwork:
		d := "hide defaults"
		if m.list().hideDefaults {
			d = "show defaults"
		}
		parts = []string{k("↑↓", "select"), k("⏎", "details"), k("c", "copy path"), k("o", "open folder"),
			k("p", "AI prompt"), k("a", "accept"), k("d", d), k("v", "show accepted")}
	default:
		if m.searching {
			parts = []string{k("type", "to filter"), k("enter", "keep"), k("esc", "clear")}
			break
		}
		if m.drill != "" {
			parts = append(parts, k("esc", "back to folders"))
		}
		parts = append(parts, k("⏎", "details"), k("s", "sha256"),
			k("o", "open folder"), k("p", "AI prompt"), k("a", "accept"), k("A", "accept folder"), k("/", "search"), k("1-4", "level"))
	}
	line := "  "
	m.place(&line, y, sCyan.Render("⟳ r")+sDim.Render(" rescan"), "rescan")
	line += "  "
	m.place(&line, y, sYellowText("⟳ R")+sDim.Render(" rescan as root"), "rescan-root")
	return line + "  " + strings.Join(parts, "  ")
}

// persistOrder groups entries by mechanism, riskiest groups first, and puts
// the flagged entries first inside each group.
func persistOrder(all []model.Entry, hideDefaults bool, lookup func(string) (model.Finding, bool)) []model.Entry {
	var groups []string
	byGroup := map[string][]model.Entry{}
	for _, e := range all {
		if hideDefaults && e.State == "default" {
			continue
		}
		if _, ok := byGroup[e.Mechanism]; !ok {
			groups = append(groups, e.Mechanism)
		}
		byGroup[e.Mechanism] = append(byGroup[e.Mechanism], e)
	}
	rank := func(e model.Entry) int {
		switch e.State {
		case "flagged":
			if f, ok := lookup(e.FindingID); ok {
				return 10 + f.Score
			}
			return 10
		case "unreadable":
			return 5
		}
		return 0
	}
	// groups with something flagged come first
	top := func(g string) int {
		best := 0
		for _, e := range byGroup[g] {
			best = max(best, rank(e))
		}
		return best
	}
	for i := 1; i < len(groups); i++ {
		for j := i; j > 0 && top(groups[j]) > top(groups[j-1]); j-- {
			groups[j], groups[j-1] = groups[j-1], groups[j]
		}
	}
	var out []model.Entry
	for _, g := range groups {
		es := byGroup[g]
		for i := 1; i < len(es); i++ { // stable insertion sort by rank
			for j := i; j > 0 && rank(es[j]) > rank(es[j-1]); j-- {
				es[j], es[j-1] = es[j-1], es[j]
			}
		}
		out = append(out, es...)
	}
	return out
}
