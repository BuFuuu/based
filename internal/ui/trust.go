package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/store"
)

func trustColor(t model.Trust) lipgloss.Color {
	switch t {
	case model.TrustOmarchy, model.TrustArch:
		return cGreen
	case model.TrustForeign:
		return cYellow
	}
	return cRed
}

// TrustDots renders trust as four dots: ●●●● Omarchy … ●○○○ unknown.
func TrustDots(t model.Trust) string {
	n := int(t) + 1
	return lipgloss.NewStyle().Foreground(trustColor(t)).Render(strings.Repeat("●", n)) +
		sDim.Render(strings.Repeat("○", 4-n))
}

// TrustLegend is a one-line key for the dots.
func TrustLegend() string {
	var parts []string
	for _, t := range model.AllTrust {
		parts = append(parts, TrustDots(t)+" "+sDim.Render(t.Name()))
	}
	return strings.Join(parts, "   ")
}

// trustLadder shows all levels with the item's own level highlighted, so
// it is clear how much an item can be trusted and why.
func trustLadder(out io.Writer, t model.Trust, w int) {
	for _, lv := range model.AllTrust {
		label := Pad(lv.Label(), 12)
		if lv == t {
			fmt.Fprintf(out, "  %s %s %s %s\n", sTitle.Render("▸"), TrustDots(lv), sTitle.Render(label), sFg.Render(TruncRight(lv.Why(), w-26)))
			continue
		}
		fmt.Fprintf(out, "    %s %s %s\n", sDim.Render(stripDots(lv)), sDim.Render(label), sDim.Render(TruncRight(lv.Why(), w-26)))
	}
	fmt.Fprintf(out, "    %s %s\n", sDim.Render("checked:"), sFg.Render(t.Check()))
}

func stripDots(t model.Trust) string {
	n := int(t) + 1
	return strings.Repeat("●", n) + strings.Repeat("○", 4-n)
}

// TrustTable shows how many files were checked at each trust level and how.
func TrustTable(out io.Writer, snap *store.Snapshot) {
	if len(snap.Stats) == 0 {
		return
	}
	fmt.Fprintf(out, "  %s\n", sAccent.Render("Checked by trust level"))
	for _, t := range model.AllTrust {
		n := snap.Stats["trust:"+t.Name()]
		fmt.Fprintf(out, "    %s %s %s  %s\n", TrustDots(t), sFg.Render(Pad(t.Label(), 12)),
			sFg.Render(fmt.Sprintf("%9s", Num(n))), sDim.Render(t.Check()))
	}
	fmt.Fprintln(out)
}

// category is a short word for what kind of difference a finding is.
func category(f model.Finding) string {
	switch f.Kind {
	case model.KindPersist:
		return "autostart"
	case model.KindNetwork:
		return "network"
	}
	for _, fl := range f.Flags {
		switch fl.Code {
		case "modified", "mode-changed":
			return "changed"
		case "config-edited", "edited-config":
			return "edited"
		case "extra-config":
			return "extra"
		case "foreign-pkg":
			return "foreign"
		case "extra-pkg":
			return "extra"
		case "exec-temp":
			return "runnable"
		}
	}
	for _, fl := range f.Flags {
		if strings.HasPrefix(fl.Code, "unowned") {
			return "unowned"
		}
	}
	return "executables"
}
