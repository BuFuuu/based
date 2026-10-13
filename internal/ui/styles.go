// Package ui renders Based in the terminal. It only uses the 16 ANSI palette
// colors, so it follows the active Omarchy terminal theme.
package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"
	"github.com/muesli/termenv"

	"github.com/BuFuuu/based/internal/model"
)

var (
	cRed     = lipgloss.Color("1")
	cGreen   = lipgloss.Color("2")
	cYellow  = lipgloss.Color("3")
	cBlue    = lipgloss.Color("4")
	cMagenta = lipgloss.Color("5")
	cCyan    = lipgloss.Color("6")
	cFg      = lipgloss.Color("7")
	cDim     = lipgloss.Color("8")
	cBlack   = lipgloss.Color("0")
	cBright  = lipgloss.Color("15")

	sBold   = lipgloss.NewStyle().Bold(true)
	sDim    = lipgloss.NewStyle().Foreground(cDim)
	sFg     = lipgloss.NewStyle().Foreground(cFg)
	sGreen  = lipgloss.NewStyle().Foreground(cGreen)
	sCyan   = lipgloss.NewStyle().Foreground(cCyan)
	sAccent = lipgloss.NewStyle().Foreground(cMagenta).Bold(true)
	sTitle  = lipgloss.NewStyle().Foreground(cBright).Bold(true)
	sRule   = lipgloss.NewStyle().Foreground(cDim)
)

// SetupColor forces ANSI output when we are on a terminal (even if output
// later goes through a pager) and disables it for NO_COLOR or pipes.
func SetupColor(force bool) {
	switch {
	case os.Getenv("NO_COLOR") != "":
		lipgloss.SetColorProfile(termenv.Ascii)
	case force || IsTTY():
		lipgloss.SetColorProfile(termenv.ANSI)
	default:
		lipgloss.SetColorProfile(termenv.Ascii)
	}
}

// termOut is the terminal the screens draw on: stdout, or stderr for a root
// scan whose stdout carries its result to the user's process.
var termOut = os.Stdout

// UseTerminal makes the screens draw on f.
func UseTerminal(f *os.File) { termOut = f }

func IsTTY() bool { return term.IsTerminal(termOut.Fd()) }

func Width() int {
	w, _, err := term.GetSize(termOut.Fd())
	if err != nil || w <= 0 {
		return 100
	}
	return w
}

func Height() int {
	_, h, err := term.GetSize(termOut.Fd())
	if err != nil || h <= 0 {
		return 40
	}
	return h
}

func SevColor(s model.Severity) lipgloss.Color {
	switch s {
	case model.High:
		return cRed
	case model.Med:
		return cYellow
	case model.Low:
		return cBlue
	}
	return cDim
}

// badgeMarks are the level icons (Nerd Font, as Omarchy ships it): normal
// (hollow circle), a bit unusual (question), unusual (exclamation), very
// unusual (warning triangle).
var badgeMarks = [...]string{"\uf10c", "\uf059", "\uf06a", "\uf071"}

// Badge renders a level as one coloured icon in a fixed-width cell, so the
// columns after it stay aligned.
func Badge(s model.Severity) string {
	icon := badgeMarks[s]
	switch s {
	case model.High:
		icon = lipgloss.NewStyle().Foreground(cRed).Bold(true).Render(icon)
	case model.Med:
		icon = lipgloss.NewStyle().Foreground(cYellow).Bold(true).Render(icon)
	case model.Low:
		icon = lipgloss.NewStyle().Foreground(cBlue).Render(icon)
	default:
		icon = sDim.Render(icon)
	}
	return "  " + icon + "   "
}

func Dot(s model.Severity) string {
	return lipgloss.NewStyle().Foreground(SevColor(s)).Render("●")
}

var kindIcons = map[model.Kind]string{
	model.KindFile:    "",
	model.KindTree:    "",
	model.KindConfig:  "",
	model.KindPackage: "",
}

func KindIcon(k model.Kind) string {
	if i, ok := kindIcons[k]; ok {
		return i
	}
	return ""
}

// Logo is the small block-letter wordmark.
func Logo() []string {
	return []string{
		sAccent.Render("█▄▄ ▄▀█ █▀ █▀▀ █▀▄"),
		sAccent.Render("█▄█ █▀█ ▄█ ██▄ █▄▀"),
	}
}

// TruncLeft keeps the end of s (the file name) and cuts from the front.
// displayHome is shown as ~ in paths. The browser and timeline set it from
// the scan, which knows the scanned user's home also under sudo.
var displayHome string

// ShortPath fits a path into w columns: home becomes ~, then the first
// folder, an ellipsis and as much of the end as fits, cut at a slash when
// possible: /tmp/…/scratchpad/.cache/dropper.sh.
func ShortPath(p string, w int) string {
	if displayHome != "" && displayHome != "/" && (p == displayHome || strings.HasPrefix(p, displayHome+"/")) {
		p = "~" + p[len(displayHome):]
	}
	if ansi.StringWidth(p) <= w || !strings.Contains(p, "/") {
		return TruncLeft(p, w)
	}
	// head: "/tmp/" or "~/.config/"
	head := ""
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			head = "~/" + rest[:i+1]
		} else {
			head = "~/"
		}
	} else if i := strings.IndexByte(p[1:], '/'); i >= 0 {
		head = p[:i+2]
	}
	budget := w - ansi.StringWidth(head) - 1
	base := p[strings.LastIndexByte(strings.TrimSuffix(p, "/"), '/'):]
	if budget < ansi.StringWidth(base) || budget < 8 {
		return TruncLeft(p, w)
	}
	r := []rune(p[len(head):])
	tail := string(r[max(len(r)-budget, 0):])
	if i := strings.IndexByte(tail, '/'); i > 0 && len(tail)-i >= len(base) {
		tail = tail[i:] // start at a folder boundary
	}
	return head + "…" + tail
}

func TruncLeft(s string, w int) string {
	if w <= 1 {
		return ""
	}
	if ansi.StringWidth(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && ansi.StringWidth(string(r))+1 > w {
		r = r[1:]
	}
	return "…" + string(r)
}

func TruncRight(s string, w int) string {
	if w <= 1 {
		return ""
	}
	return ansi.Truncate(s, w, "…")
}

func Pad(s string, w int) string {
	if d := w - ansi.StringWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

func Ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 60*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
	return t.Format("Jan 2, 2006")
}

func Num(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func Compact(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%dk", n/1000)
	}
	return fmt.Sprint(n)
}
