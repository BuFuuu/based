package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"

	"github.com/charmbracelet/lipgloss"
)

// TestScanFrameFits renders a mid-scan frame and checks no line overflows.
func TestScanFrameFits(t *testing.T) {
	SetupColor(true)
	p := &scan.Progress{Started: time.Now().Add(-4 * time.Second)}
	for i, n := range []string{"Package database", "System files", "Home directory", "Temp directories", "Packages"} {
		ph := &scan.Phase{ID: fmt.Sprint(i), Title: n}
		p.Phases = append(p.Phases, ph)
	}
	p.Phases[0].State.Store(scan.PhaseDone)
	p.Phases[0].Started = time.Now().Add(-4 * time.Second)
	p.Phases[0].Finished = time.Now().Add(-2 * time.Second)
	p.Phases[0].Note = "974 pkgs · 322,927 files"
	p.Phases[1].State.Store(scan.PhaseRunning)
	p.Phases[1].Started = time.Now().Add(-2 * time.Second)
	p.Phases[1].Estimate = 300000
	p.Phases[1].Done.Store(181234)
	r := scan.TestReporter(p, p.Phases[1])
	for i := 0; i < 20; i++ {
		r.Tick(fmt.Sprintf("/usr/share/icons/Adwaita/symbolic/status/icon-%d.svg", i), "adwaita-icon-theme")
	}
	f := model.Finding{Kind: model.KindFile, Subject: "/usr/local/bin/kworkerd", Title: "unowned executable", Flags: []model.Flag{model.FlagUnownedBinary, model.FlagStatic, model.FlagELF}}
	r.Report(f)
	r.Tick("/usr/share/zoneinfo/Europe/Berlin", "tzdata")
	m := NewScanModel(p, "user alice · omarchy · 2026-10-11 10:30", func() {})
	m.frame = 7
	m.collectHits()
	for _, w := range []int{60, 80, 110, 200} {
		m.width = w
		for i, line := range strings.Split(m.View(), "\n") {
			if lw := lipgloss.Width(line); lw > min(w, 110) {
				t.Errorf("width %d: line %d is %d wide: %q", w, i, lw, line)
			}
		}
	}
}
