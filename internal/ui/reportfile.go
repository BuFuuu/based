package ui

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/store"
)

// The Markdown report: everything from one scan in a single file, with
// enough context that an AI assistant can read it cold and help.

// WriteReport renders the report for snap and saves it next to the scan.
func WriteReport(st *store.Store, snap *store.Snapshot, acc map[string]store.Accepted) (string, error) {
	return st.SaveReport(snap, []byte(RenderReport(snap, acc)))
}

// openEditor is swapped out in tests.
var openEditor = OpenInEditor

// OpenInEditor opens a file with Omarchy's default editor (in its own
// window), falling back to xdg-open.
func OpenInEditor(path string) error {
	if p, err := exec.LookPath("omarchy-launch-editor"); err == nil {
		return exec.Command("setsid", p, path).Start()
	}
	return exec.Command("setsid", "xdg-open", path).Start()
}

func RenderReport(snap *store.Snapshot, acc map[string]store.Accepted) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	var open, accepted []model.Finding
	var counts [4]int
	for _, f := range snap.Findings {
		if store.IsAccepted(acc, f) {
			accepted = append(accepted, f)
			continue
		}
		open = append(open, f)
		counts[f.Severity]++
	}
	sort.SliceStable(open, func(i, j int) bool {
		if open[i].Score != open[j].Score {
			return open[i].Score > open[j].Score
		}
		return open[i].Added.After(open[j].Added)
	})

	w("# Based report: %s\n\n", snap.ScannedAt.Format("2006-01-02 15:04"))
	w("> **For AI assistants:** this report lists everything on an Omarchy Linux system (Arch Linux + Hyprland) ")
	w("that is *not* part of the default install, plus everything that starts automatically. It was produced by ")
	w("Based, an offline, read-only tool. Read \"How to read this report\" first. Being listed does not mean ")
	w("malicious: most items are things the user installed or configured on purpose. Your job is to help the user ")
	w("find the few that are not, explain why, and suggest read-only ways to verify before anything is changed.\n\n")

	w("## Scan\n\n")
	mode := "user (partial: root-only files were skipped; rerun with `based scan --sudo` for full coverage)"
	if snap.AsRoot {
		mode = "root (full coverage)"
	}
	w("| | |\n|---|---|\n")
	w("| Scanned | %s (took %s) |\n", snap.ScannedAt.Format(time.RFC1123), snap.Duration)
	w("| Scan as | %s |\n", mode)
	if v := readTrim("/usr/share/omarchy/version"); v != "" {
		w("| Omarchy | %s |\n", v)
	}
	if v := readTrim("/proc/sys/kernel/osrelease"); v != "" {
		w("| Kernel | %s |\n", v)
	}
	files := 0
	for k, v := range snap.Stats {
		if strings.HasPrefix(k, "trust:") {
			files += v
		}
	}
	w("| Files checked | %s |\n", Num(files))
	w("| Open items | %d very unusual · %d unusual · %d a bit unusual · %d normal |\n", counts[model.High], counts[model.Med], counts[model.Low], counts[model.Info])
	w("| Accepted by the user | %d (listed at the end) |\n", len(accepted))
	w("| Paths | the user's home directory is written as `~` |\n\n")

	w("## How to read this report\n\n")
	w("**Baseline.** Files are compared with the pacman package database (which package owns a file and what it ")
	w("should look like), with Omarchy's own templates (`/usr/share/omarchy/config`) and with the paths and services ")
	w("Omarchy's install and migration scripts set up. Anything else is \"non-default\".\n\n")
	w("**How unusual** an item is comes from the sum of its flag weights: 70+ very unusual, 40+ unusual, ")
	w("15+ a bit unusual, below that normal. It measures distance from a default install, not danger: Based ")
	w("is not an antivirus, and a very unusual item can be fine. Each item lists its flags with weights. Negative weights mean \"expected\", ")
	w("for example a file Omarchy's own installer patches.\n\n")
	w("**Trust** (where an item comes from):\n\n")
	w("| Level | Meaning | How it was checked |\n|---|---|---|\n")
	for _, t := range model.AllTrust {
		w("| %s %s | %s | %s |\n", stripDots(t), t.Label(), t.Why(), t.Check())
	}
	w("\nA package file whose content changed is shown as Unknown: the package only vouches for what it shipped.\n\n")
	w("**Limits.** Reference hashes come from the local pacman database, which an attacker with root could also ")
	w("edit. Unowned files have no reference at all. Nothing was looked up online. A compromised system can lie to ")
	w("any program running on it, so treat this as an overview, not proof.\n\n")
	w("## What to do (for AI assistants)\n\n")
	w("Work locally and read-only. Do not rely on this report's verdicts alone; check the items yourself on ")
	w("this machine.\n\n")
	w("1. **Every very unusual and unusual item: inspect it thoroughly.** Look at all of it, not just the flagged part: ")
	w("read the whole file or script (for binaries: `file`, `strings`, `readelf -h -d`; never `ldd` or running it, ")
	w("since that can execute the binary), check its owner, ")
	w("permissions and times (`stat`), which package owns it (`pacman -Qo <path>`) or whether the package's ")
	w("files are intact (`pacman -Qkk <package>`), what refers to it (services, timers, autostart, shell rc, ")
	w("hooks), whether it is running (`ps`, `systemctl status <unit>`, `systemctl --user status <unit>`) and ")
	w("what was installed around its \"added\" time (`/var/log/pacman.log`). Follow anything it downloads, ")
	w("decodes or executes.\n")
	w("2. **A bit unusual items: inspect the ones that look interesting** the same way: anything in a hidden ")
	w("directory, anything that runs automatically, unfamiliar binaries, packages not from Arch or Omarchy, ")
	w("and anything whose name or location does not fit what it claims to be.\n")
	w("3. **Info items** are normal drift (edited configs, extra packages); only look at them if something ")
	w("above points there.\n")
	w("4. **Report back** in plain words: what each item is, whether it looks legitimate and why, and how sure ")
	w("you are. Ask before changing, disabling or deleting anything.\n\n")

	w("## Overview\n\n")
	w("Every entry under `/`, what was checked there and how many non-default items it holds.\n\n")
	w("| Folder | State | Files checked | Items | What |\n|---|---|---|---|---|\n")
	for _, r := range FolderRows(snap, acc) {
		what := r.Note
		if r.Items > 0 {
			what = catSummary(r.Cats)
		}
		checked := ""
		if r.Checked > 0 {
			checked = Num(r.Checked)
		}
		w("| `%s` | %s | %s | %d | %s |\n", r.Path, r.State, checked, r.Items, cell(what))
	}
	w("\n")

	w("## Findings\n\n")
	w("Most unusual first. Very unusual and unusual items are shown in full, a bit unusual ones with their reasons, normal ones as a table.\n\n")
	for _, sev := range []model.Severity{model.High, model.Med, model.Low, model.Info} {
		var group []model.Finding
		for _, f := range open {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		w("### %s (%d)\n\n", groupLabel(model.Finding{Severity: sev}, false), len(group))
		if len(group) == 0 {
			w("None.\n\n")
			continue
		}
		if sev == model.Info {
			w("| id | Item | What | Trust | Added |\n|---|---|---|---|---|\n")
			for _, f := range group {
				w("| %s | `%s` | %s | %s | %s |\n", f.ID, cell(f.Subject), cell(reason(f)), f.Trust.Label(), f.Added.Format("2006-01-02"))
			}
			w("\n")
			continue
		}
		for _, f := range group {
			writeFinding(&b, f, sev >= model.Med)
		}
	}

	w("## Persistence\n\n")
	w("Everything that starts automatically: services, timers, cron, autostart, shell startup files, hooks, ")
	w("plugins, SSH keys, AI agent hooks. **default** entries come with Omarchy, a package or the distribution ")
	w("(the reason is given); **flagged** ones were added later and also appear under Findings with the same id; ")
	w("**unreadable** ones need a root scan.\n\n")
	if len(snap.Persist) == 0 {
		w("Not collected in this scan.\n\n")
	}
	lookup := func(id string) (model.Finding, bool) {
		for _, f := range snap.Findings {
			if f.ID == id {
				return f, true
			}
		}
		return model.Finding{}, false
	}
	group := ""
	for _, e := range persistOrder(snap.Persist, false, lookup) { // flagged groups first
		if e.Mechanism != group {
			if group != "" {
				w("\n")
			}
			group = e.Mechanism
			w("### %s\n\n| State | Name | Runs | Why | Path | Finding |\n|---|---|---|---|---|---|\n", group)
		}
		w("| %s | %s | %s | %s | `%s` | %s |\n", e.State, cell(e.Name), codeCell(e.Runs), cell(e.Why), cell(e.Path), e.FindingID)
	}
	if group != "" {
		w("\n")
	}

	w("## Network\n\n")
	w("Every program with a socket open at scan time, grouped by what it does: **listening** for connections, ")
	w("holding **connections**, or holding **raw sockets**. **default** programs belong to an unchanged package from Arch ")
	w("or Omarchy; **flagged** ones do not, or show signs of a reverse shell, and also appear under Findings; ")
	w("**unreadable** ones belong to another user and need a root scan. This is a snapshot: short or periodic ")
	w("connections (beacons) are only seen if they were open at that moment.\n\n")
	if len(snap.Network) == 0 {
		w("Not collected in this scan.\n\n")
	}
	group = ""
	for _, e := range persistOrder(snap.Network, false, lookup) {
		if e.Mechanism != group {
			if group != "" {
				w("\n")
			}
			group = e.Mechanism
			w("### %s\n\n| State | Program | Sockets | Why | Path | Finding |\n|---|---|---|---|---|---|\n", group)
		}
		w("| %s | %s | %s | %s | `%s` | %s |\n", e.State, cell(e.Name), codeCell(e.Runs), cell(e.Why), cell(e.Path), e.FindingID)
	}
	if group != "" {
		w("\n")
	}

	if len(accepted) > 0 {
		w("## Accepted by the user\n\n")
		w("The user marked these as known-good. They reappear if they change, except files in a folder the user ")
		w("accepted as a whole (a project of theirs): those stay hidden as they change, unless they become very unusual.\n\n")
		var dirs []string
		for k := range acc {
			if dir, ok := strings.CutPrefix(k, store.FolderPrefix); ok {
				dirs = append(dirs, dir)
			}
		}
		sort.Strings(dirs)
		for _, d := range dirs {
			w("- whole folder `%s/`\n", d)
		}
		if len(dirs) > 0 {
			w("\n")
		}
		w("| id | Item | What | Note |\n|---|---|---|---|\n")
		for _, f := range accepted {
			note := acc[f.ID].Note
			if d := store.AcceptedFolder(acc, f); d != "" && acc[f.ID].Fingerprint != f.Fingerprint {
				note = "in accepted folder `" + d + "/`"
			}
			w("| %s | `%s` | %s | %s |\n", f.ID, cell(f.Subject), cell(reason(f)), cell(note))
		}
		w("\n")
	}

	out := b.String()
	if snap.Home != "" && snap.Home != "/" {
		out = strings.ReplaceAll(out, snap.Home, "~")
	}
	return out
}

func writeFinding(b *strings.Builder, f model.Finding, full bool) {
	fmt.Fprintf(b, "#### `%s`\n\n", f.Subject)
	fmt.Fprintf(b, "- **%s** · id `%s` · %s · score %d · trust: %s\n", f.Title, f.ID, f.Kind, f.Score, f.Trust.Label())
	fmt.Fprintf(b, "- added %s (%s) · first seen by Based %s\n", f.Added.Format("2006-01-02 15:04"), f.AddedSource, f.FirstSeen.Format("2006-01-02 15:04"))
	for _, fl := range f.Flags {
		fmt.Fprintf(b, "- flag: %s (weight %d)\n", fl.Label, fl.Weight)
	}
	keys := make([]string, 0, len(f.Facts))
	for k := range f.Facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, "- %s: `%s`\n", k, strings.ReplaceAll(f.Facts[k], "`", "'"))
	}
	if full && f.Preview != "" {
		lines := strings.Split(f.Preview, "\n")
		if len(lines) > 20 {
			lines = append(lines[:20], fmt.Sprintf("… %d more lines", len(lines)-20))
		}
		fmt.Fprintf(b, "\n```\n%s\n```\n", strings.ReplaceAll(strings.Join(lines, "\n"), "```", "'''"))
	}
	b.WriteString("\n")
}

// reason is a one-line "why is this listed".
func reason(f model.Finding) string {
	if len(f.Flags) > 0 && f.Flags[0].Weight > 0 {
		return f.Flags[0].Label
	}
	return f.Title
}

func catSummary(cats map[string]int) string {
	keys := make([]string, 0, len(cats))
	for k := range cats {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return cats[keys[i]] > cats[keys[j]] })
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", cats[k], k))
	}
	return strings.Join(parts, ", ")
}

// cell makes text safe inside a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func codeCell(s string) string {
	if s == "" {
		return ""
	}
	return "`" + strings.ReplaceAll(cell(s), "`", "'") + "`"
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
