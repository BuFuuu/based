package ui

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"
	"github.com/BuFuuu/based/internal/store"
)

// FolderRow is one entry of / in the overview, plus a "packages" row.
type FolderRow struct {
	Path    string
	State   string // scanned, partial, link, virtual, empty, skipped
	Note    string
	Checked int
	Items   int // at least a bit unusual, as the timeline shows them
	Normal  int // the rest: edits Omarchy or you made, generated files
	Worst   model.Severity
	Cats    map[string]int
}

// What each top-level folder is, so unscanned ones are explained rather
// than silently missing.
var folderNotes = map[string]string{
	"/usr":        "programs and libraries, compared with their packages",
	"/etc":        "system configuration",
	"/opt":        "add-on software",
	"/boot":       "kernel and boot loader",
	"/var":        "logs, caches and app data; unowned data listed, not walked",
	"/home":       "your home only; other users' homes are not scanned",
	"/tmp":        "temporary files, checked for anything runnable",
	"/proc":       "virtual: live process and kernel state, not stored on disk",
	"/sys":        "virtual: kernel and device state, not stored on disk",
	"/dev":        "virtual: devices; /dev/shm is checked for runnable files",
	"/run":        "virtual: runtime state in memory, cleared at boot",
	"/root":       "the root user's home: not covered yet",
	"/mnt":        "mount point for other drives: not scanned",
	"/media":      "mount point for removable drives: not scanned",
	"/srv":        "data served by services: not covered yet",
	"/swap":       "swap space (memory paged to disk): not scanned",
	"/lost+found": "filesystem repair leftovers",
	"/.snapshots": "btrfs snapshots: older copies of the system",
	"packages":    "installed packages outside the Omarchy install",
}

var virtualDirs = map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true}

// FolderRows lists everything under / with what the last scan saw there.
func FolderRows(snap *store.Snapshot, acc map[string]store.Accepted) []FolderRow {
	items := map[string]*FolderRow{}
	get := func(p string) *FolderRow {
		if items[p] == nil {
			items[p] = &FolderRow{Path: p, Cats: map[string]int{}}
		}
		return items[p]
	}
	for _, f := range snap.Findings {
		if store.IsAccepted(acc, f) {
			continue
		}
		top := "packages"
		if f.Kind != model.KindPackage {
			top = scan.TopDir(f.Subject)
		}
		r := get(top)
		if f.Severity < model.Low {
			r.Normal++
			continue
		}
		r.Items++
		r.Cats[category(f)]++
		if f.Severity > r.Worst {
			r.Worst = f.Severity
		}
	}

	var rows []FolderRow
	ents, _ := os.ReadDir("/")
	for _, e := range ents {
		p := "/" + e.Name()
		r := get(p)
		r.Checked = snap.Stats["dir:"+p]
		unread := snap.Stats["unreadable:"+p]
		r.Note = folderNotes[p]
		switch {
		case e.Type()&os.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			r.State, r.Note = "link", "→ /"+strings.TrimPrefix(target, "/")+", checked there"
		case r.Checked > 0 || r.Items > 0 || unread > 0:
			r.State = "scanned"
			if unread > 0 && !snap.AsRoot {
				r.State = "partial"
				r.Note = fmt.Sprintf("%s unreadable as your user: `based scan --sudo`", Num(unread))
			}
			if virtualDirs[p] {
				r.State = "virtual"
			}
		case virtualDirs[p]:
			r.State = "virtual"
		case isEmpty(p):
			r.State = "empty"
			if r.Note == "" {
				r.Note = "empty"
			}
		default:
			r.State = "skipped"
			if r.Note == "" {
				r.Note = "not covered yet"
			}
		}
		rows = append(rows, *r)
	}
	pk := get("packages")
	pk.State, pk.Note = "scanned", folderNotes["packages"]
	pk.Checked = snap.Counts["packages"]
	rows = append(rows, *pk)
	return rows
}

func isEmpty(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()
	names, _ := f.Readdirnames(1)
	return len(names) == 0
}

var stateIcons = map[string]string{
	"scanned": "✓", "partial": "◐", "link": "↪", "virtual": "∿", "empty": "·", "skipped": "○",
}

// FolderLine renders one row; sel marks the selected row in the browser.
func FolderLine(r FolderRow, w int, sel bool) string {
	icon := stateIcons[r.State]
	switch r.State {
	case "scanned":
		icon = sGreen.Render(icon)
	case "partial":
		icon = sYellowText(icon)
	default:
		icon = sDim.Render(icon)
	}
	name := sFg.Render(Pad(r.Path, 13))
	if r.State == "link" || r.State == "empty" || r.State == "skipped" || r.State == "virtual" && r.Checked == 0 {
		name = sDim.Render(Pad(r.Path, 13))
	}
	checked := ""
	if r.Checked > 0 {
		checked = Num(r.Checked)
	}
	count := sDim.Render(fmt.Sprintf("%6s", ""))
	detail := sDim.Render(r.Note)
	if r.Items > 0 {
		count = lipgloss.NewStyle().Foreground(SevColor(r.Worst)).Bold(r.Worst >= model.Med).Render(fmt.Sprintf("%6d", r.Items))
		var cats []string
		for c := range r.Cats {
			cats = append(cats, c)
		}
		sort.Slice(cats, func(i, j int) bool { return r.Cats[cats[i]] > r.Cats[cats[j]] })
		var parts []string
		for _, c := range cats {
			parts = append(parts, fmt.Sprintf("%d %s", r.Cats[c], c))
		}
		detail = sDim.Render(strings.Join(parts, " · "))
	} else if r.State == "scanned" || r.State == "partial" {
		count = sGreen.Render(fmt.Sprintf("%6s", "0"))
		if r.State == "scanned" {
			detail = sGreen.Render("nothing unusual") + sDim.Render(" · "+r.Note)
		}
	}
	if r.Normal > 0 {
		detail += sDim.Render(fmt.Sprintf(" · +%d normal", r.Normal))
	}
	lead := "  "
	if sel {
		lead = sAccent.Render("▌ ")
	}
	line := fmt.Sprintf("%s%s %s %s %s  %s", lead, icon, name, sDim.Render(fmt.Sprintf("%9s", checked)), count, detail)
	return TruncRight(line, w)
}

// FolderTableHeader labels the columns.
func FolderTableHeader() string {
	return "    " + sDim.Render(Pad("folder", 13)+fmt.Sprintf(" %9s %6s  %s", "checked", "items", "what is there"))
}

// FolderTable prints the overview of / after a scan.
func FolderTable(out io.Writer, snap *store.Snapshot, acc map[string]store.Accepted) {
	w := min(Width(), 130)
	fmt.Fprintf(out, "  %s\n", sAccent.Render("Everything under /"))
	fmt.Fprintln(out, FolderTableHeader())
	for _, r := range FolderRows(snap, acc) {
		fmt.Fprintln(out, FolderLine(r, w, false))
	}
	fmt.Fprintf(out, "  %s\n\n", sDim.Render("✓ scanned  ◐ partly readable  ↪ link  ∿ virtual  ○ not scanned · details: based --all --in /etc"))
}
