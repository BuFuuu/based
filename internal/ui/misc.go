package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BuFuuu/based/internal/store"
)

func Usage(version string) string {
	logo := Logo()
	cmd := func(c, d string) string { return "    " + sCyan.Render(Pad(c, 26)) + sDim.Render(d) + "\n" }
	var b strings.Builder
	b.WriteString("\n  " + logo[0] + "   " + sTitle.Render("what's on your Omarchy that Omarchy didn't put there") + "\n")
	b.WriteString("  " + logo[1] + "   " + sDim.Render("v"+version) + "\n\n")
	b.WriteString("  " + sAccent.Render("Commands") + "\n")
	b.WriteString(cmd("based", "interactive window: timeline, overview, persistence"))
	b.WriteString(cmd("based scan [--sudo]", "scan the system; --sudo for full coverage"))
	b.WriteString(cmd("based timeline --print", "plain list, most unusual first; --sort time, --all, --in /etc"))
	b.WriteString(cmd("based show <id>", "everything known about one item"))
	b.WriteString(cmd("based show <id> --prompt", "ready-made prompt for an AI assistant"))
	b.WriteString(cmd("based accept <id>...", "mark as known-good; reappears if it changes"))
	b.WriteString(cmd("based accept --folder <dir>", "accept a whole project folder, also after changes"))
	b.WriteString(cmd("based accept --list|--undo", "review or revert accepts"))
	b.WriteString(cmd("based open [--scan]", "toggle the floating window (used by the bar icon)"))
	b.WriteString(cmd("based report [--open]", "Markdown report of the last scan, written for AI assistants"))
	b.WriteString("\n  " + sAccent.Render("How unusual") + sDim.Render("  (not how dangerous: Based is not an antivirus)") + "\n")
	b.WriteString("    " + Badge(3) + sFg.Render(" very unusual ") + sDim.Render(" changed package files, programs in /etc, setuid files, live reverse shells") + "\n")
	b.WriteString("    " + Badge(2) + sFg.Render(" unusual      ") + sDim.Render(" unowned programs in system paths or /var, programs in temp dirs") + "\n")
	b.WriteString("    " + Badge(1) + sFg.Render(" a bit unusual") + sDim.Render(" unowned files, your own scripts and binaries, AUR packages") + "\n")
	b.WriteString("    " + Badge(0) + sFg.Render(" normal       ") + sDim.Render(" edited configs, extra packages (shown with --all)") + "\n\n")
	return b.String()
}

func AcceptLine(accepted bool, id, subject string) string {
	if accepted {
		return "  " + sGreen.Render("✓ accepted ") + sDim.Render(id+" ") + sFg.Render(subject)
	}
	return "  " + sYellowText("↺ unaccepted ") + sDim.Render(id+" ") + sFg.Render(subject)
}

func AcceptedList(acc map[string]store.Accepted, snap *store.Snapshot) string {
	if len(acc) == 0 {
		return "  " + sDim.Render("nothing accepted yet") + "\n"
	}
	current := map[string]string{}
	for _, f := range snap.Findings {
		current[f.ID] = f.Fingerprint
	}
	ids := make([]string, 0, len(acc))
	for id := range acc {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return acc[ids[i]].At.After(acc[ids[j]].At) })
	var b strings.Builder
	b.WriteString("\n")
	for _, id := range ids {
		a := acc[id]
		if dir, ok := strings.CutPrefix(id, store.FolderPrefix); ok {
			n := 0
			for _, f := range snap.Findings {
				if store.FolderCovers(dir, f) {
					n++
				}
			}
			fmt.Fprintf(&b, "  %s %s %s %s%s\n", sGreen.Render("▣"), sDim.Render(id), sDim.Render(a.At.Format("2006-01-02")),
				sFg.Render(dir+"/"), sDim.Render(fmt.Sprintf("  whole folder, %d items", n)))
			continue
		}
		state := sGreen.Render("✓")
		if fp, ok := current[id]; !ok {
			state = sDim.Render("–") // gone from the system
		} else if fp != a.Fingerprint {
			state = sYellowText("!") // changed since accepted, visible again
		}
		note := ""
		if a.Note != "" {
			note = sDim.Render("  " + a.Note)
		}
		fmt.Fprintf(&b, "  %s %s %s %s%s\n", state, sDim.Render(id), sDim.Render(a.At.Format("2006-01-02")), sFg.Render(a.Subject), note)
	}
	b.WriteString("\n  " + sDim.Render("✓ hidden   ! changed since accepted (shown again)   – no longer present   ▣ folder (undo: based accept --undo dir:<path>)") + "\n\n")
	return b.String()
}
