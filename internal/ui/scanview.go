package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"
)

const (
	streamLines = 10
	hitLines    = 4
	frameRate   = 33 * time.Millisecond
)

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type tickMsg time.Time
type doneMsg struct{}

// ScanModel is the live scan screen.
type ScanModel struct {
	progress *scan.Progress
	subtitle string
	cancel   func()
	frame    int
	width    int
	done     bool
	aborted  bool
	hits     []scan.Event
}

func NewScanModel(p *scan.Progress, subtitle string, cancel func()) *ScanModel {
	return &ScanModel{progress: p, subtitle: subtitle, cancel: cancel, width: Width()}
}

// Done is sent by the caller when the scan goroutine finishes.
func Done() tea.Msg { return doneMsg{} }

func (m *ScanModel) Aborted() bool { return m.aborted }

func (m *ScanModel) Init() tea.Cmd { return tick() }

func tick() tea.Cmd {
	return tea.Tick(frameRate, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *ScanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			m.aborted = true
			m.cancel()
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tickMsg:
		m.frame++
		m.collectHits()
		return m, tick()
	case doneMsg:
		m.done = true
		return m, tea.Quit
	}
	return m, nil
}

func (m *ScanModel) collectHits() {
	for _, e := range m.progress.Recent(64) {
		if !e.Hit {
			continue
		}
		dup := false
		for _, h := range m.hits {
			if h.Path == e.Path {
				dup = true
				break
			}
		}
		if !dup {
			m.hits = append(m.hits, e)
		}
	}
	if len(m.hits) > hitLines {
		m.hits = m.hits[len(m.hits)-hitLines:]
	}
}

func (m *ScanModel) View() string {
	w := min(m.width, 110)
	var b strings.Builder
	logo := Logo()
	b.WriteString("\n")
	b.WriteString("  " + logo[0] + "   " + sTitle.Render("omarchy integrity scan") + "\n")
	b.WriteString("  " + logo[1] + "   " + sDim.Render(TruncRight(m.subtitle, w-24)) + "\n\n")

	for _, ph := range m.progress.Phases {
		b.WriteString(m.phaseLine(ph, w) + "\n")
	}
	if m.done {
		b.WriteString("\n")
		return b.String()
	}
	b.WriteString("\n")
	b.WriteString(m.stream(w))
	b.WriteString(m.footer(w))
	return b.String()
}

func (m *ScanModel) phaseLine(ph *scan.Phase, w int) string {
	title := Pad(ph.Title, 18)
	switch ph.State.Load() {
	case scan.PhasePending:
		return "  " + sDim.Render("○ "+title)
	case scan.PhaseFailed:
		msg := "aborted"
		if ph.Err != nil {
			msg = ph.Err.Error()
		}
		return "  " + lipgloss.NewStyle().Foreground(cRed).Render("✗ "+title) + " " + sDim.Render(msg)
	case scan.PhaseDone:
		dur := ph.Finished.Sub(ph.Started).Round(10 * time.Millisecond)
		note := ph.Note
		if u := ph.Unreadable.Load(); u > 0 {
			note += fmt.Sprintf(" · %s unreadable", Num(int(u)))
		}
		left := "  " + sGreen.Render("✓ ") + sFg.Render(title) + " " + sDim.Render(TruncRight(note, w-34))
		return Pad(left, w-8) + sDim.Render(fmt.Sprintf("%6s", fmtDur(dur)))
	}
	// running
	done := ph.Done.Load()
	elapsed := time.Since(ph.Started).Seconds()
	rate := ""
	if elapsed > 0.2 {
		rate = Compact(int64(float64(done)/elapsed)) + "/s"
	}
	spin := sCyan.Render(spinner[m.frame%len(spinner)])
	barW := max(w-52, 6) // the rest of the line is ~50 columns
	var bar, pct, count string
	if ph.Estimate > 0 {
		frac := float64(done) / float64(ph.Estimate)
		if frac > 0.99 {
			frac = 0.99
		}
		bar = progressBar(frac, barW)
		pct = fmt.Sprintf("%3d%%", int(frac*100))
		count = Compact(done) + "/" + Compact(int64(ph.Estimate))
	} else {
		bar = bounceBar(m.frame, barW)
		pct = "    "
		count = Compact(done)
	}
	return fmt.Sprintf("  %s %s %s %s %s %s", spin, sBold.Render(title), bar, sFg.Render(pct),
		sDim.Render(Pad(count, 11)), sDim.Render(rate))
}

func progressBar(frac float64, w int) string {
	full := int(frac * float64(w))
	head := ""
	if full < w {
		head = sGreen.Render("╸")
		w--
	}
	return sGreen.Render(strings.Repeat("━", full)) + head + sDim.Render(strings.Repeat("━", max(w-full, 0)))
}

func bounceBar(frame, w int) string {
	seg := 8
	span := w - seg
	pos := frame % (2 * span)
	if pos > span {
		pos = 2*span - pos
	}
	return sDim.Render(strings.Repeat("━", pos)) + sCyan.Render(strings.Repeat("━", seg)) + sDim.Render(strings.Repeat("━", w-seg-pos))
}

// stream renders the box of files rushing past, plus pinned recent hits.
func (m *ScanModel) stream(w int) string {
	inner := w - 6
	events := m.progress.Recent(streamLines)
	var running *scan.Phase
	for _, ph := range m.progress.Phases {
		if ph.State.Load() == scan.PhaseRunning {
			running = ph
		}
	}
	var counter int64
	if running != nil {
		counter = running.Done.Load()
	}
	lines := make([]string, 0, streamLines+hitLines+1)
	for i := 0; i < streamLines; i++ {
		idx := i - (streamLines - len(events))
		if idx < 0 {
			lines = append(lines, "")
			continue
		}
		e := events[idx]
		age := len(events) - 1 - idx // 0 = newest
		addr := fmt.Sprintf("0x%08x", counter-int64(age))
		detail := Pad(TruncRight(e.Detail, 14), 14)
		path := TruncLeft(e.Path, inner-len(addr)-19)
		var line string
		switch {
		case e.Hit:
			st := lipgloss.NewStyle().Foreground(SevColor(e.Severity)).Bold(true)
			line = st.Render(addr+"  "+Pad("▲ "+e.Severity.Label(), 15)) + "  " + st.Render(path)
		case age == 0:
			line = sGreen.Bold(true).Render(addr+"  "+detail+"  "+path) + sGreen.Render(" █")
		case age < 4:
			line = sGreen.Render(addr + "  " + detail + "  " + path)
		default:
			line = sDim.Render(addr + "  " + detail + "  " + path)
		}
		lines = append(lines, line)
	}
	lines = append(lines, sRule.Render(strings.Repeat("─", inner)))
	for i := 0; i < hitLines; i++ {
		if i >= len(m.hits) {
			if i == 0 {
				lines = append(lines, sDim.Render("no hits yet"))
			} else {
				lines = append(lines, "")
			}
			continue
		}
		h := m.hits[len(m.hits)-1-i]
		st := lipgloss.NewStyle().Foreground(SevColor(h.Severity))
		label := Badge(h.Severity)
		path := TruncLeft(h.Path, inner-34)
		lines = append(lines, label+" "+st.Render(Pad(path, inner-33))+" "+sDim.Render(TruncRight(h.Detail, 24)))
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cDim).
		Padding(0, 1).
		Width(w - 4).
		Render(strings.Join(lines, "\n"))
	return indent(titledBox(box, "live"), "  ") + "\n"
}

func (m *ScanModel) footer(w int) string {
	c := m.progress.Counts()
	right := sDim.Render(fmtDur(time.Since(m.progress.Started)) + "  q to abort")
	levels := []model.Severity{model.High, model.Med, model.Low, model.Info}
	var left string
	for _, short := range []bool{false, true} { // words if they fit, else the marks
		var parts []string
		for _, s := range levels {
			name := s.Label()
			if short {
				name = badgeMarks[s]
			}
			parts = append(parts, Dot(s)+" "+sFg.Render(fmt.Sprint(c[s]))+sDim.Render(" "+name))
		}
		left = "  " + strings.Join(parts, "   ")
		if lipgloss.Width(left)+lipgloss.Width(right)+2 <= w {
			break
		}
	}
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	return left + strings.Repeat(" ", max(gap, 2)) + right + "\n"
}

// titledBox writes a label into the top border of a rendered box.
func titledBox(box, label string) string {
	lines := strings.SplitN(box, "\n", 2)
	w := lipgloss.Width(lines[0])
	top := sDim.Render("╭─ ") + sGreen.Render(label) + " " + sDim.Render(strings.Repeat("─", max(w-lipgloss.Width(label)-5, 0))+"╮")
	if len(lines) == 1 {
		return top
	}
	return top + "\n" + lines[1]
}

func fmtDur(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

func indent(s, pre string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = pre + lines[i]
	}
	return strings.Join(lines, "\n")
}
