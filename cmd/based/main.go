// Command based shows everything on an Omarchy system that is not part of
// the default install, newest first, so it can be reviewed (by you or an AI).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BuFuuu/based/internal/collectors"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"
	"github.com/BuFuuu/based/internal/store"
	"github.com/BuFuuu/based/internal/ui"
)

var version = "0.1.0"

func main() {
	args := os.Args[1:]
	cmd := "timeline"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "scan":
		err = cmdScan(args)
	case "timeline", "tl", "ls":
		err = cmdTimeline(args)
	case "show":
		err = cmdShow(args)
	case "accept":
		err = cmdAccept(args)
	case "open":
		err = cmdOpen(args)
	case "report":
		err = cmdReport(args)
	case "version", "--version":
		fmt.Println("based", version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		if len(args) == 0 && len(cmd) >= 4 {
			// `based <id>` is a shortcut for `based show <id>`
			err = cmdShow([]string{cmd})
			break
		}
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "based:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	ui.SetupColor(false)
	fmt.Fprint(w, ui.Usage(version))
}

// parse handles flags placed before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			os.Exit(2)
		}
		if fs.NArg() == 0 {
			return pos
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	deep := fs.Bool("deep", false, "hash every package file instead of checking size and mtime first")
	plain := fs.Bool("plain", false, "no animation, plain progress lines")
	asRoot := fs.Bool("sudo", false, "re-run through sudo for full coverage (sudo's PATH lacks ~/.local/bin)")
	parse(fs, args)
	ui.SetupColor(false)
	if *asRoot && os.Geteuid() != 0 {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		argv := []string{"sudo", exe, "scan"}
		if *deep {
			argv = append(argv, "--deep")
		}
		if *plain {
			argv = append(argv, "--plain")
		}
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			return err
		}
		return syscall.Exec(sudo, argv, os.Environ())
	}
	if p := os.Getenv("BASED_CPUPROFILE"); p != "" {
		if f, err := os.Create(p); err == nil {
			pprof.StartCPUProfile(f)
			defer pprof.StopCPUProfile()
		}
	}

	st, err := store.Open()
	if err != nil {
		return err
	}
	prev, _ := st.Latest()
	prevCounts := map[string]int{}
	if prev != nil {
		prevCounts = prev.Counts
	}
	seen := st.Seen()

	env := scan.NewEnv()
	env.Deep = *deep
	cs := collectors.All()
	progress := scan.NewProgress(cs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	who := "user " + os.Getenv("USER")
	if env.IsRoot {
		who = "root"
	}
	subtitle := fmt.Sprintf("%s · %s · %s", who, hostname(), time.Now().Format("2006-01-02 15:04"))
	if *deep {
		subtitle += " · deep"
	}

	start := time.Now()
	aborted := false
	if ui.IsTTY() && !*plain {
		m := ui.NewScanModel(progress, subtitle, cancel)
		prog := tea.NewProgram(m, tea.WithInput(os.Stdin))
		go func() {
			scan.Run(ctx, env, cs, progress, prevCounts)
			prog.Send(ui.Done())
		}()
		if _, err := prog.Run(); err != nil {
			return err
		}
		aborted = m.Aborted() || ctx.Err() != nil
	} else {
		fmt.Printf("based scan · %s\n", subtitle)
		done := make(chan struct{})
		go func() { scan.Run(ctx, env, cs, progress, prevCounts); close(done) }()
		printed := map[int]bool{}
		for finished := false; !finished; {
			select {
			case <-done:
				finished = true
			case <-time.After(200 * time.Millisecond):
			}
			for i, ph := range progress.Phases {
				if s := ph.State.Load(); (s == scan.PhaseDone || s == scan.PhaseFailed) && !printed[i] {
					printed[i] = true
					status := "ok"
					if s == scan.PhaseFailed {
						status = fmt.Sprint("failed: ", ph.Err)
					}
					fmt.Printf("  %-18s %s  %-60s %s\n", ph.Title, status, ph.Note, ph.Finished.Sub(ph.Started).Round(time.Millisecond))
				}
			}
		}
		aborted = ctx.Err() != nil
	}
	if aborted {
		fmt.Println("  scan aborted, nothing saved")
		return nil
	}

	snap := &store.Snapshot{
		Version:    1,
		ScannedAt:  start,
		Duration:   time.Since(start).Round(time.Millisecond).String(),
		Host:       hostname(),
		AsRoot:     env.IsRoot,
		Counts:     map[string]int{},
		Unreadable: map[string]int{},
		Stats:      map[string]int{},
		Home:       env.Home,
		Findings:   progress.Findings(),
		Persist:    progress.Entries(),
		Network:    progress.NetEntries(),
	}
	for _, ph := range progress.Phases {
		snap.Counts[ph.ID] = int(ph.Done.Load())
		snap.Unreadable[ph.ID] = int(ph.Unreadable.Load())
		for k, v := range ph.Stats {
			snap.Stats[k] += v
		}
	}
	newIDs := map[string]bool{}
	if prev != nil {
		for _, f := range snap.Findings {
			if _, ok := seen[f.ID]; !ok {
				newIDs[f.ID] = true
			}
		}
	}
	if err := st.Save(snap); err != nil {
		return fmt.Errorf("saving snapshot: %w", err)
	}
	ui.ScanSummary(os.Stdout, snap, st.Accepted(), newIDs)
	if path, err := ui.WriteReport(st, snap, st.Accepted()); err == nil {
		fmt.Printf("  Report: %s\n\n", path)
	}
	return nil
}

func loadLatest() (*store.Store, *store.Snapshot, error) {
	st, err := store.Open()
	if err != nil {
		return nil, nil, err
	}
	snap, err := st.Latest()
	if err != nil {
		return nil, nil, err
	}
	if snap == nil {
		return nil, nil, fmt.Errorf("no scan yet, run `based scan` first")
	}
	return st, snap, nil
}

func cmdTimeline(args []string) error {
	fs := flag.NewFlagSet("timeline", flag.ContinueOnError)
	all := fs.Bool("all", false, "include info items (edited configs, extra packages, ...)")
	sev := fs.String("severity", "low", "minimum level: normal, a-bit-unusual, unusual, very-unusual (or info, low, med, high)")
	fs.StringVar(sev, "s", "low", "shorthand for --severity")
	kind := fs.String("kind", "", "only this kind: file, tree, config, package")
	since := fs.String("since", "", "only items added within this window, e.g. 24h, 7d")
	accepted := fs.Bool("accepted", false, "include accepted items")
	limit := fs.Int("limit", 0, "show at most N items (0 = all)")
	query := fs.String("q", "", "only items whose path or title contains this text")
	in := fs.String("in", "", "only items under this path, e.g. /etc or ~/.config")
	print := fs.Bool("print", false, "print the list instead of the interactive browser")
	noPager := fs.Bool("no-pager", false, "with --print: write directly instead of using less")
	asJSON := fs.Bool("json", false, "print findings as JSON")
	scanFirst := fs.Bool("scan", false, "interactive: run a scan first")
	sortBy := fs.String("sort", "unusual", "unusual (most unusual first) or time (newest first)")
	parse(fs, args)
	interactive := ui.IsTTY() && !*print && !*noPager && !*asJSON

	st, err := store.Open()
	if err != nil {
		return err
	}
	snap, err := st.Latest()
	if err != nil {
		return err
	}
	if snap == nil && !interactive {
		return fmt.Errorf("no scan yet, run `based scan` first")
	}
	opt := ui.TimelineOptions{Kind: *kind, ShowAccepted: *accepted, Limit: *limit, Query: *query, In: *in, ByTime: *sortBy == "time"}
	if rest, ok := strings.CutPrefix(opt.In, "~"); ok && snap != nil {
		opt.In = snap.Home + rest
	}
	if *all {
		opt.MinSeverity = model.Info
	} else if s, ok := model.ParseSeverity(*sev); ok {
		opt.MinSeverity = s
	} else {
		return fmt.Errorf("unknown level %q: use normal, a-bit-unusual, unusual or very-unusual", *sev)
	}
	if *since != "" {
		d, err := parseDuration(*since)
		if err != nil {
			return err
		}
		opt.Since = d
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap.Findings)
	}
	ui.SetupColor(false)
	if interactive {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		m := ui.NewBrowse(st, snap, opt, exe, *scanFirst)
		_, err = tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run()
		return err
	}
	var buf bytes.Buffer
	ui.Timeline(&buf, snap, st.Accepted(), opt)
	return page(buf.Bytes(), *noPager, false)
}

// page sends output through less when it does not fit on screen.
func page(out []byte, noPager, force bool) error {
	lines := bytes.Count(out, []byte("\n"))
	if noPager || !ui.IsTTY() || (!force && lines < ui.Height()-1) {
		_, err := os.Stdout.Write(out)
		return err
	}
	less, err := exec.LookPath("less")
	if err != nil {
		_, err := os.Stdout.Write(out)
		return err
	}
	flags := "-RSX"
	if !force {
		flags += "F"
	}
	c := exec.Command(less, flags)
	// Nerd Font icons live in the Private Use Area; tell less they print.
	c.Env = append(os.Environ(), "LESSUTFCHARDEF=e000-f8ff:p,f0000-ffffd:p")
	c.Stdin, c.Stdout, c.Stderr = bytes.NewReader(out), os.Stdout, os.Stderr
	return c.Run()
}

func parseDuration(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	if w, ok := strings.CutSuffix(s, "w"); ok {
		n, err := strconv.Atoi(w)
		if err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// find resolves an id, a unique id prefix, or an exact subject.
func find(snap *store.Snapshot, key string) (model.Finding, error) {
	var matches []model.Finding
	for _, f := range snap.Findings {
		if f.ID == key || f.Subject == key || strings.TrimSuffix(f.Subject, "/") == key {
			return f, nil
		}
		if strings.HasPrefix(f.ID, key) {
			matches = append(matches, f)
		}
	}
	switch len(matches) {
	case 0:
		return model.Finding{}, fmt.Errorf("no item %q in the last scan", key)
	case 1:
		return matches[0], nil
	}
	return model.Finding{}, fmt.Errorf("%q matches %d items, use more characters", key, len(matches))
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print as JSON")
	plain := fs.Bool("plain", false, "print as plain text")
	prompt := fs.Bool("prompt", false, "print an AI investigation prompt")
	ids := parse(fs, args)
	if len(ids) == 0 {
		return fmt.Errorf("usage: based show <id|path>")
	}
	st, snap, err := loadLatest()
	if err != nil {
		return err
	}
	acc := st.Accepted()
	for _, id := range ids {
		f, err := find(snap, id)
		if err != nil {
			return err
		}
		switch {
		case *asJSON:
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(f)
		case *prompt:
			fmt.Println(ui.Prompt(f, snap.Home))
		case *plain:
			fmt.Println(ui.Plain(f, snap.Home))
		default:
			ui.SetupColor(false)
			ui.Show(os.Stdout, f, store.IsAccepted(acc, f))
		}
	}
	return nil
}

func cmdAccept(args []string) error {
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	note := fs.String("note", "", "why this is fine (stored with the accept)")
	undo := fs.Bool("undo", false, "remove the accept again")
	list := fs.Bool("list", false, "list accepted items")
	folder := fs.String("folder", "", "accept everything under this folder, also after it changes (not very unusual items)")
	ids := parse(fs, args)
	ui.SetupColor(false)

	st, snap, err := loadLatest()
	if err != nil {
		return err
	}
	acc := st.Accepted()
	if *list {
		fmt.Print(ui.AcceptedList(acc, snap))
		return nil
	}
	if *folder != "" {
		dir, err := filepath.Abs(*folder)
		if err != nil {
			return err
		}
		if ok, why := store.FolderAllowed(dir, snap.Home); !ok {
			return fmt.Errorf("can't accept the whole folder: %s", why)
		}
		acc[store.FolderKey(dir)] = store.Accepted{Fingerprint: "folder", Subject: dir, At: time.Now(), Note: *note}
		fmt.Println(ui.AcceptLine(true, store.FolderKey(dir), dir+"/"))
		return st.SaveAccepted(acc)
	}
	if len(ids) == 0 {
		return fmt.Errorf("usage: based accept <id>... [--note text] | --folder <path> | --undo <id> | --list")
	}
	for _, id := range ids {
		f, err := find(snap, id)
		if err != nil {
			if a, ok := acc[id]; ok && *undo {
				delete(acc, id)
				fmt.Println(ui.AcceptLine(false, id, a.Subject))
				continue
			}
			return err
		}
		if *undo {
			delete(acc, f.ID)
		} else {
			acc[f.ID] = store.Accepted{Fingerprint: f.Fingerprint, Subject: f.Subject, At: time.Now(), Note: *note}
		}
		fmt.Println(ui.AcceptLine(!*undo, f.ID, f.Subject))
	}
	return st.SaveAccepted(acc)
}

// cmdReport writes the Markdown report for the latest scan.
func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	open := fs.Bool("open", false, "open it in the default editor")
	parse(fs, args)
	st, snap, err := loadLatest()
	if err != nil {
		return err
	}
	path, err := ui.WriteReport(st, snap, st.Accepted())
	if err != nil {
		return err
	}
	fmt.Println(path)
	if *open {
		return ui.OpenInEditor(path)
	}
	return nil
}

// cmdOpen toggles the floating Based window (used by the bar icon): it
// closes the window if it is open, otherwise opens the timeline. With --scan
// it always (re)opens and runs a scan first.
func cmdOpen(args []string) error {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	doScan := fs.Bool("scan", false, "run a scan, then show the timeline")
	parse(fs, args)

	if addr := windowAddress("Based"); addr != "" {
		closeWindow(addr)
		if !*doScan {
			return nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	q := "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
	script := q + " timeline"
	if *doScan {
		script += " --scan"
	}
	// Our own window class with a float+size rule, so the window is wide
	// enough for every key hint. Without Hyprland's Lua API, fall back to
	// org.omarchy.terminal, which Omarchy floats at its standard size.
	appID := "org.omarchy.terminal"
	if sizeWindow("based") {
		appID = "based"
	}
	c := exec.Command("setsid", "uwsm-app", "--", "xdg-terminal-exec",
		"--app-id="+appID, "--title=Based", "-e", "bash", "-c", script)
	return c.Start()
}

// sizeWindow sets a Hyprland rule that floats windows of this class at
// about 1180x760 (or 90% of a smaller screen), centred, replacing the rule
// from the last launch. It reports whether Hyprland accepted it.
func sizeWindow(class string) bool {
	w, h := 1180, 760
	if out, err := exec.Command("hyprctl", "monitors", "-j").Output(); err == nil {
		var mons []struct {
			Width, Height int
			Scale         float64
			Focused       bool
		}
		if json.Unmarshal(out, &mons) == nil {
			for _, m := range mons {
				if m.Focused && m.Scale > 0 {
					w = min(w, int(float64(m.Width)/m.Scale*0.9))
					h = min(h, int(float64(m.Height)/m.Scale*0.9))
				}
			}
		}
	}
	lua := fmt.Sprintf(`if based_size_rule then based_size_rule:set_enabled(false) end; `+
		`based_size_rule = hl.window_rule({ match = { class = "^%s$" }, float = true, center = true, size = { %d, %d } })`,
		class, w, h)
	out, err := exec.Command("hyprctl", "eval", lua).CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "ok"
}

// windowAddress finds a Hyprland window by exact title.
func windowAddress(title string) string {
	out, err := exec.Command("hyprctl", "clients", "-j").Output()
	if err != nil {
		return ""
	}
	var clients []struct {
		Address string `json:"address"`
		Title   string `json:"title"`
	}
	if json.Unmarshal(out, &clients) != nil {
		return ""
	}
	for _, c := range clients {
		if c.Title == title {
			return c.Address
		}
	}
	return ""
}

func closeWindow(addr string) {
	// Hyprland's Lua dispatcher first, then the classic syntax.
	// hyprctl can report errors with exit status 0, so check the output.
	out, err := exec.Command("hyprctl", "dispatch", fmt.Sprintf(`hl.dsp.window.close({ window = "address:%s" })`, addr)).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		exec.Command("hyprctl", "dispatch", "closewindow", "address:"+addr).Run()
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
