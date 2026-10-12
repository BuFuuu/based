package ui

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/store"
)

// TimelineOptions filters the timeline.
type TimelineOptions struct {
	MinSeverity  model.Severity
	Kind         string
	Since        time.Duration
	ShowAccepted bool
	Limit        int
	Query        string
	In           string // only items under this path
	ByTime       bool   // newest first instead of most unusual first
}

// groupLabel is the heading a row is listed under: its day when sorted by
// time, how unusual it is otherwise.
func groupLabel(f model.Finding, byTime bool) string {
	if byTime {
		return dayLabel(f.Added)
	}
	l := f.Severity.Label()
	return strings.ToUpper(l[:1]) + l[1:]
}

// filterFindings applies the options and sorts newest first.
func filterFindings(snap *store.Snapshot, acc map[string]store.Accepted, opt TimelineOptions) (rows []model.Finding, hiddenSev, hiddenAcc int) {
	for _, f := range snap.Findings {
		if !opt.ShowAccepted && store.IsAccepted(acc, f) {
			hiddenAcc++
			continue
		}
		if f.Severity < opt.MinSeverity {
			hiddenSev++
			continue
		}
		if opt.Kind != "" && string(f.Kind) != opt.Kind {
			continue
		}
		if opt.Since > 0 && time.Since(f.Added) > opt.Since {
			continue
		}
		if opt.In != "" && f.Subject != opt.In && !strings.HasPrefix(f.Subject, strings.TrimSuffix(opt.In, "/")+"/") {
			continue
		}
		if opt.Query != "" && !strings.Contains(strings.ToLower(f.Subject+" "+f.Title), strings.ToLower(opt.Query)) {
			continue
		}
		rows = append(rows, f)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if !opt.ByTime && a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Added.After(b.Added)
	})
	return rows, hiddenSev, hiddenAcc
}

// Timeline writes findings newest-first, grouped by day.
func Timeline(out io.Writer, snap *store.Snapshot, acc map[string]store.Accepted, opt TimelineOptions) {
	displayHome = snap.Home
	w := min(Width(), 160)
	rows, hiddenSev, hiddenAcc := filterFindings(snap, acc, opt)
	total := len(rows)
	if opt.Limit > 0 && len(rows) > opt.Limit {
		rows = rows[:opt.Limit]
	}

	header(out, snap, w)
	fmt.Fprintf(out, "  %s\n\n", countsLine(snap, acc))

	if len(rows) == 0 {
		fmt.Fprintf(out, "  %s\n\n", sGreen.Render("Nothing to show with these filters."))
	}
	group := ""
	for _, f := range rows {
		if g := groupLabel(f, opt.ByTime); g != group {
			group = g
			label := " " + g + " "
			fmt.Fprintf(out, "\n  %s%s\n", sTitle.Render(label), sRule.Render(strings.Repeat("─", max(w-6-lipgloss.Width(label), 4))))
		}
		fmt.Fprintln(out, row(f, w, store.IsAccepted(acc, f), opt.ByTime))
	}

	fmt.Fprintln(out)
	var notes []string
	if total > len(rows) {
		notes = append(notes, fmt.Sprintf("%d more (--limit 0 for all)", total-len(rows)))
	}
	if hiddenSev > 0 {
		notes = append(notes, fmt.Sprintf("%s below %s hidden (--all)", Num(hiddenSev), opt.MinSeverity.Label()))
	}
	if hiddenAcc > 0 {
		notes = append(notes, fmt.Sprintf("%d accepted hidden (--accepted)", hiddenAcc))
	}
	if len(notes) > 0 {
		fmt.Fprintf(out, "  %s\n", sDim.Render(strings.Join(notes, " · ")))
	}
	fmt.Fprintf(out, "  %s\n", TrustLegend())
	fmt.Fprintf(out, "  %s %s   %s %s   %s %s\n\n",
		sCyan.Render("based show <id>"), sDim.Render("details"),
		sCyan.Render("based accept <id>"), sDim.Render("mark known-good"),
		sCyan.Render("based scan"), sDim.Render("rescan"))
}

func countsLine(snap *store.Snapshot, acc map[string]store.Accepted) string {
	var counts [4]int
	for _, f := range snap.Findings {
		if !store.IsAccepted(acc, f) {
			counts[f.Severity]++
		}
	}
	var parts []string
	for _, s := range []model.Severity{model.High, model.Med, model.Low, model.Info} {
		parts = append(parts, Dot(s)+" "+sFg.Render(fmt.Sprint(counts[s]))+sDim.Render(" "+s.Label()))
	}
	return strings.Join(parts, "   ")
}

func header(out io.Writer, snap *store.Snapshot, w int) {
	logo := Logo()
	mode := "user scan · " + sYellowText("partial, `based scan --sudo` for full coverage")
	if snap.AsRoot {
		mode = "root scan · full coverage"
	}
	fmt.Fprintf(out, "\n  %s   %s\n", logo[0], sTitle.Render("timeline")+sDim.Render("  ·  "+snap.Host))
	fmt.Fprintf(out, "  %s   %s\n\n", logo[1], sDim.Render("last scan "+Ago(snap.ScannedAt)+" · ")+sDim.Render(mode))
}

func sYellowText(s string) string { return lipgloss.NewStyle().Foreground(cYellow).Render(s) }

// row renders one finding. Grouped by day, the time column shows the hour;
// grouped by risk, it shows the date.
func row(f model.Finding, w int, accepted, byTime bool) string {
	id := sDim.Render(f.ID)
	ts := sDim.Render(Pad(f.Added.Format("Jan 2"), 6))
	if byTime {
		ts = sDim.Render(Pad(f.Added.Format("15:04"), 6))
	}
	icon := lipgloss.NewStyle().Foreground(SevColor(f.Severity)).Render(KindIcon(f.Kind))
	why := f.Title
	if len(f.Flags) > 0 && f.Flags[0].Weight > 0 {
		why = f.Flags[0].Label
		for _, fl := range f.Flags[1:] {
			if fl.Code == "omarchy" {
				why = "by Omarchy · " + why
			}
		}
		if len(f.Flags) > 1 && f.Flags[1].Weight > 0 {
			why += " · " + f.Flags[1].Code
		}
	}
	if f.Kind == model.KindTree || strings.HasSuffix(f.Subject, "/") {
		why = f.Title
		if n := f.Facts["files"]; n != "" {
			why += " · " + n + plural(n, " file", " files")
		}
	}
	whyW, subjW := rowColumns(w)
	subjStyle := sFg
	if f.Severity >= model.Med {
		subjStyle = lipgloss.NewStyle().Foreground(SevColor(f.Severity))
	}
	subj := subjStyle.Render(Pad(ShortPath(f.Subject, subjW), subjW))
	acc := ""
	if accepted {
		acc = sGreen.Render(" ✓")
	}
	return fmt.Sprintf("  %s %s %s %s %s %s %s%s", id, Badge(f.Severity), ts, TrustDots(f.Trust), icon, subj, sDim.Render(TruncRight(why, whyW)), acc)
}

// rowColumns returns the widths of the "why" and subject columns. The
// subject starts at column rowSubjectX.
func rowColumns(w int) (whyW, subjW int) {
	avail := max(w-rowSubjectX-5, 12)             // 5: gap plus the accepted mark
	subjW = min(max(avail*55/100, 24), 46, avail) // paths are shortened in the middle
	return avail - subjW, subjW
}

// rowSubjectX is where the subject begins: "  id badge time dots icon ".
const rowSubjectX = 2 + 8 + 7 + 7 + 5 + 2

func plural(n, one, many string) string {
	if n == "1" {
		return one
	}
	return many
}

func dayLabel(t time.Time) string {
	now := time.Now()
	y1, m1, d1 := now.Date()
	y2, m2, d2 := t.Date()
	today := time.Date(y1, m1, d1, 0, 0, 0, 0, now.Location())
	day := time.Date(y2, m2, d2, 0, 0, 0, 0, now.Location())
	switch days := int(today.Sub(day).Hours() / 24); {
	case days == 0:
		return "Today"
	case days == 1:
		return "Yesterday"
	case days < 7 && days > 0:
		return t.Format("Monday")
	}
	if t.Year() == now.Year() {
		return t.Format("Mon, Jan 2")
	}
	return t.Format("Jan 2, 2006")
}

// DetailLine is one line of the detail view; Copy is what clicking it
// copies (empty if nothing).
type DetailLine struct {
	Text string
	Copy string
}

// Show renders one finding in full.
func Show(out io.Writer, f model.Finding, accepted bool) {
	for _, l := range DetailLines(f, accepted, min(Width(), 110), true) {
		fmt.Fprintln(out, l.Text)
	}
}

// DetailLines builds the detail view. hints adds the command-line hints at
// the end (the interactive view shows key hints instead).
func DetailLines(f model.Finding, accepted bool, w int, hints bool) []DetailLine {
	var lines []DetailLine
	add := func(text, copy string) { lines = append(lines, DetailLine{text, copy}) }
	sect := func(title string) { add("", ""); add("  "+sAccent.Render(title), "") }

	sev := SevColor(f.Severity)
	head := Badge(f.Severity) + "  " + sTitle.Render(f.Title)
	score := sDim.Render(fmt.Sprintf("score %d", f.Score))
	gap := w - 8 - lipgloss.Width(head) - lipgloss.Width(score)
	top := head + strings.Repeat(" ", max(gap, 2)) + score
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(sev).Padding(0, 1).Width(w - 4).
		Render(top + "\n" + lipgloss.NewStyle().Foreground(sev).Bold(true).Render(f.Subject))
	add("", "")
	for i, l := range strings.Split(indent(box, "  "), "\n") {
		copy := ""
		if i > 1 { // the subject lines inside the box
			copy = f.Subject
		}
		add(l, copy)
	}

	sect("Why it's listed")
	if len(f.Flags) == 0 {
		add("    "+sDim.Render("no flags"), "")
	}
	for _, fl := range f.Flags {
		st := sDim
		mark := "·"
		if fl.Weight < 0 {
			st, mark = sGreen, "▼"
		} else if fl.Weight >= 40 {
			st, mark = lipgloss.NewStyle().Foreground(cRed), "▲"
		} else if fl.Weight >= 15 {
			st, mark = lipgloss.NewStyle().Foreground(cYellow), "▲"
		}
		add(fmt.Sprintf("    %s %s  %s", st.Render(mark), st.Render(fmt.Sprintf("%3d", fl.Weight)), sFg.Render(fl.Label)), "")
	}

	sect("Where it comes from")
	var tb strings.Builder
	trustLadder(&tb, f.Trust, w)
	for _, l := range strings.Split(strings.TrimRight(tb.String(), "\n"), "\n") {
		add(l, "")
	}

	sect("Facts")
	facts := [][2]string{
		{"id", f.ID},
		{"kind", string(f.Kind)},
		{"added", fmt.Sprintf("%s  (%s, %s)", f.Added.Format(time.DateTime), f.AddedSource, Ago(f.Added))},
		{"first seen", fmt.Sprintf("%s  (by Based)", f.FirstSeen.Format(time.DateTime))},
	}
	keys := make([]string, 0, len(f.Facts))
	for k := range f.Facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		facts = append(facts, [2]string{k, f.Facts[k]})
	}
	for _, kv := range facts {
		add(fmt.Sprintf("    %s %s", sDim.Render(Pad(kv[0], 16)), sFg.Render(TruncRight(kv[1], w-22))), kv[1])
	}
	if accepted {
		add(fmt.Sprintf("    %s %s", sDim.Render(Pad("status", 16)), sGreen.Render("accepted as known-good")), "")
	}

	if f.Preview != "" {
		title := "Preview"
		if f.Kind == model.KindTree || (f.Kind == model.KindConfig && strings.HasSuffix(f.Subject, "/")) {
			title = "Newest files"
		}
		sect(title)
		for _, l := range strings.Split(f.Preview, "\n") {
			copy := ""
			if title == "Newest files" && len(l) > 18 && l[16:18] == "  " {
				// keep the file name visible: trim long paths from the left
				copy = strings.TrimSuffix(f.Subject, "/") + "/" + l[18:]
				l = sDim.Render(l[:16]) + "  " + TruncLeft(l[18:], w-26)
			} else {
				l = TruncRight(l, w-8)
			}
			add(fmt.Sprintf("    %s %s", sDim.Render("│"), l), copy)
		}
	}

	if hints {
		sect("Investigate with AI")
		add("    "+sCyan.Render(fmt.Sprintf(`claude "$(based show %s --prompt)"`, f.ID)), "")
		if !accepted {
			sect("Known-good?")
			add(fmt.Sprintf("    %s  %s", sCyan.Render("based accept "+f.ID), sDim.Render("hides it until it changes")), "")
		}
		add("", "")
	}
	return lines
}

func section(out io.Writer, title string) {
	fmt.Fprintf(out, "\n  %s\n", sAccent.Render(title))
}

// Plain renders a finding as uncolored text, suitable for an AI prompt. The
// home directory is written as ~ so the user name does not leak.
func Plain(f model.Finding, home string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Subject: %s\nKind: %s\nTitle: %s\nHow unusual: %s (score %d)\n", f.Subject, f.Kind, f.Title, f.Severity.Label(), f.Score)
	fmt.Fprintf(&b, "Trust: %s (%s)\nHow it was checked: %s\n", f.Trust.Label(), f.Trust.Why(), f.Trust.Check())
	fmt.Fprintf(&b, "Added: %s (%s)\nFirst seen by scanner: %s\n", f.Added.Format(time.RFC3339), f.AddedSource, f.FirstSeen.Format(time.RFC3339))
	b.WriteString("Flags:\n")
	for _, fl := range f.Flags {
		fmt.Fprintf(&b, "  - %s (weight %d)\n", fl.Label, fl.Weight)
	}
	keys := make([]string, 0, len(f.Facts))
	for k := range f.Facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b.WriteString("Facts:\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s: %s\n", k, f.Facts[k])
	}
	if f.Preview != "" {
		fmt.Fprintf(&b, "Content preview:\n```\n%s\n```\n", f.Preview)
	}
	out := b.String()
	if home != "" && home != "/" {
		out = strings.ReplaceAll(out, home, "~")
	}
	return out
}

// Prompt wraps Plain in instructions for an AI assistant.
func Prompt(f model.Finding, home string) string {
	if f.Kind == model.KindNetwork {
		return "The Based scanner flagged this program on my Omarchy (Arch Linux + Hyprland) system because of its " +
			"network activity at scan time. Investigate it read-only: check what the program is, which package or user " +
			"installed it, what started it (parent process, service, autostart), where it connects or what it listens on, " +
			"and whether it looks benign or malicious (for example a reverse shell or a beacon). Do not kill, delete or " +
			"modify anything; tell me what you found and what you recommend.\n\n" + Plain(f, home)
	}
	return "The Based scanner flagged this item on my Omarchy (Arch Linux + Hyprland) system as non-default. " +
		"Investigate it read-only: check what it is, which package or program created it, whether it is referenced by " +
		"services, timers, autostart or shell config, and whether it looks benign or malicious. Do not delete or modify " +
		"anything; tell me what you found and what you recommend.\n\n" + Plain(f, home)
}

// ScanSummary prints the result block after a scan.
func ScanSummary(out io.Writer, snap *store.Snapshot, acc map[string]store.Accepted, newIDs map[string]bool) {
	var counts [4]int
	var top []model.Finding
	for _, f := range snap.Findings {
		if store.IsAccepted(acc, f) {
			continue
		}
		counts[f.Severity]++
		if f.Severity >= model.Med {
			top = append(top, f)
		}
	}
	sort.SliceStable(top, func(i, j int) bool {
		if top[i].Severity != top[j].Severity {
			return top[i].Severity > top[j].Severity
		}
		return top[i].Added.After(top[j].Added)
	})
	verdict := sGreen.Bold(true).Render("Nothing very unusual or unusual.")
	if counts[model.High] > 0 {
		verdict = lipgloss.NewStyle().Foreground(cRed).Bold(true).Render(fmt.Sprintf("%d very unusual item(s) to look at.", counts[model.High]))
	} else if counts[model.Med] > 0 {
		verdict = lipgloss.NewStyle().Foreground(cYellow).Bold(true).Render(fmt.Sprintf("%d unusual item(s) worth a look.", counts[model.Med]))
	}
	fmt.Fprintf(out, "  %s\n\n", verdict)
	w := min(Width(), 160)
	for i, f := range top {
		if i == 8 {
			fmt.Fprintf(out, "  %s\n", sDim.Render(fmt.Sprintf("… %d more in the timeline", len(top)-8)))
			break
		}
		line := row(f, w, false, false)
		if newIDs[f.ID] {
			line += lipgloss.NewStyle().Foreground(cMagenta).Bold(true).Render(" new")
		}
		fmt.Fprintln(out, line)
	}
	if len(top) > 0 {
		fmt.Fprintln(out)
	}
	FolderTable(out, snap, acc)
	TrustTable(out, snap)
	if !snap.AsRoot {
		fmt.Fprintf(out, "  %s\n", sDim.Render("Some system files are root-only. Run `based scan --sudo` for full coverage."))
	}
	fmt.Fprintf(out, "  %s %s   %s %s\n\n", sCyan.Render("based"), sDim.Render("timeline"), sCyan.Render("based show <id>"), sDim.Render("details"))
}
