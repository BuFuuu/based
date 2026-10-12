package collectors

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"
)

// Persistence lists every place where something starts automatically and
// decides for each whether it is a default:
//
//	systemd units   default if a package ships the enable link, Omarchy's
//	                scripts enable it, or a systemd preset enables it
//	files in /etc   default if a package owns it unchanged, or Omarchy's
//	                scripts create it
//	files in home   default if identical to Omarchy's template; otherwise
//	                the added lines are shown
//
// Everything else is flagged and becomes a finding.
type Persistence struct {
	env          *scan.Env
	r            *scan.Reporter
	presets      map[string][]presetRule // "system" / "user"
	related      map[string]string       // unit -> unit whose Also=/Alias= enables it too
	pkgEnabled   map[string]string       // unit -> package whose install script enables it
	shipped      map[string]string       // script -> trusted package carrying it ("" if none), per scan
	total, flags int
}

type presetRule struct {
	enable  bool
	pattern string
}

func (*Persistence) ID() string                         { return "persistence" }
func (*Persistence) Title() string                      { return "Persistence" }
func (*Persistence) Estimate(_ *scan.Env, prev int) int { return prev }

func (c *Persistence) Collect(ctx context.Context, env *scan.Env, r *scan.Reporter) error {
	if env.Pacman == nil {
		return fmt.Errorf("package database not loaded")
	}
	c.env, c.r = env, r
	c.loadPresets()
	c.loadUnitRelations()
	home := env.Home
	steps := []func(){
		func() { c.systemd("/etc/systemd/system", "system") },
		func() { c.systemd("/etc/systemd/user", "all users") },
		func() { c.systemd(filepath.Join(home, ".config/systemd/user"), "user") },
		func() { c.systemd(filepath.Join(home, ".local/share/systemd/user"), "user") },
		c.cron,
		c.autostart,
		c.hyprland,
		c.shellStartup,
		c.pacmanHooks,
		c.omarchyHooks,
		c.omarchyPlugins,
		c.systemHooks,
		c.ssh,
		c.agents,
		c.git,
		c.sessionEnv,
		c.dbusServices,
		c.launchers,
		c.pythonHooks,
		c.accounts,
	}
	for _, step := range steps {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		step()
	}
	r.Note(fmt.Sprintf("%d entries · %d not default", c.total, c.flags))
	return nil
}

// ---- recording -----------------------------------------------------------

// add records an entry. Without flags it is a default; with flags it is
// flagged and reported as a finding.
func (c *Persistence) add(e model.Entry, flags []model.Flag, preview string) {
	c.total++
	c.r.Tick(e.Path, "autostart")
	if len(flags) > 0 && e.State != "unreadable" {
		if by, ok := c.shippedBy(e.Runs); ok {
			e.Why, flags = by, nil
		}
	}
	if e.State == "unreadable" || len(flags) == 0 {
		if e.State == "" {
			e.State = "default"
		}
		c.r.Entry(e, nil)
		return
	}
	c.flags++
	e.State = "flagged"
	f := model.Finding{
		Kind:    model.KindPersist,
		ID:      model.MakeID(model.KindPersist, e.Path+"\x00"+e.Name),
		Subject: e.Path,
		Title:   e.Mechanism + ": " + e.Name,
		Preview: preview,
	}
	if info, err := os.Lstat(e.Path); err == nil {
		f = withTimes(f, e.Path, info)
	}
	for _, fl := range flags {
		f.AddFlag(fl)
	}
	f.SetFact("mechanism", e.Mechanism)
	f.SetFact("name", e.Name)
	f.SetFact("runs", e.Runs)
	f.SetFact("why listed", e.Why)
	sum := sha256.Sum256([]byte(e.Runs + "\x00" + preview + "\x00" + fingerprintFile(e.Path)))
	f.Fingerprint = hex.EncodeToString(sum[:8])
	if e.Why == "" {
		e.Why = flags[0].Label
	}
	c.r.Entry(e, &f)
}

func withTimes(f model.Finding, path string, info fs.FileInfo) model.Finding {
	base := fileFinding(f.Kind, path, info)
	base.ID, base.Subject, base.Title, base.Preview = f.ID, f.Subject, f.Title, f.Preview
	return base
}

func fingerprintFile(path string) string {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return ""
	}
	if h, err := inspect.SHA256(path); err == nil {
		return h
	}
	return ""
}

func (c *Persistence) unreadable(mech, path string) {
	c.add(model.Entry{Mechanism: mech, Name: path, Path: path, State: "unreadable",
		Why: "not readable as your user: `based scan --sudo`"}, nil, "")
}

// ---- deciding what is default --------------------------------------------

// systemDefault says whether a file outside home is a default: owned by a
// package and unchanged, or created by Omarchy's scripts.
func (c *Persistence) systemDefault(path string) (ok bool, why string, changed bool) {
	if pkg := c.env.Pacman.Owner(path); pkg != nil {
		if c.unchanged(path) {
			return true, "from package " + pkg.Name, false
		}
		return false, "changed from package " + pkg.Name, true
	}
	if script, ok := omarchyPathRef(c.env.OmarchyPath, path); ok {
		return true, "set up by Omarchy (" + script + ")", false
	}
	if src, ok := omarchyCopy(c.env.OmarchyPath, path); ok {
		return true, "installed by Omarchy (copy of " + src + ")", false
	}
	if src, ok := omarchyOverride(c.env.OmarchyPath, path); ok {
		return true, "set by Omarchy (" + src + ")", false
	}
	if t, ok := installedWithOmarchy(path); ok {
		return true, "created while Omarchy was installed (" + t.Format("2006-01-02") + "), unchanged since", false
	}
	if filepath.Dir(path) != "/etc/sudoers.d" {
		return false, "", false
	}
	if user, ok := installerSudoRule(path, archinstallLog); ok {
		return true, "set up by the installer (sudo with password for " + user + ")", false
	}
	return false, "", false
}

const archinstallLog = "/var/log/archinstall/install.log"

// archinstall (which the Omarchy ISO runs) gives the new user sudo by
// writing /etc/sudoers.d/NN_<user> containing "<user> ALL=(ALL) ALL".
var installerSudoName = regexp.MustCompile(`^[0-9]+_([a-z_][a-z0-9_-]*)$`)

// installerSudoRule reports whether path is that rule, unaltered, for a user
// the install log says it enabled. Anything more (NOPASSWD, extra lines,
// another user) is not a default.
func installerSudoRule(path, log string) (string, bool) {
	m := installerSudoName.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return "", false
	}
	user := m[1]
	lines := meaningfulLines(path)
	if len(lines) != 1 || strings.Join(strings.Fields(lines[0]), " ") != user+" ALL=(ALL) ALL" {
		return "", false
	}
	if !bytes.Contains(readFileSmall(log), []byte("Enabling sudo permissions for "+user+"\n")) {
		return "", false
	}
	return user, true
}

// unchanged compares a package file with its record (cheap check first).
func (c *Persistence) unchanged(path string) bool { return packageFileUnchanged(c.env, path) }

func packageFileUnchanged(env *scan.Env, path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return true
	}
	exp, ok := env.Pacman.Expected(path)
	if !ok || exp.SHA256 == "" {
		return true
	}
	if info.Size() == exp.Size && info.ModTime().Unix() == exp.Mtime {
		return true
	}
	sum, err := inspect.SHA256(path)
	return err != nil || sum == exp.SHA256 // unreadable: can't tell, don't alarm
}

// homeDefault says whether a file in home equals its Omarchy template.
func (c *Persistence) homeDefault(path, template string) (bool, string) {
	have, err1 := os.ReadFile(path)
	want, err2 := os.ReadFile(template)
	if err1 == nil && err2 == nil && bytes.Equal(have, want) {
		return true, "same as Omarchy's default"
	}
	if src, ok := omarchyCopy(c.env.OmarchyPath, path); ok {
		return true, "installed by Omarchy (copy of " + src + ")"
	}
	return false, ""
}

// addedLines returns meaningful lines of file that its template lacks.
func addedLines(file, template string) []string {
	have := readLines(file)
	want := map[string]bool{}
	for _, l := range readLines(template) {
		want[strings.TrimSpace(l)] = true
	}
	var out []string
	for _, l := range have {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "--") || want[t] {
			continue
		}
		out = append(out, t)
	}
	return out
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(b), "\n")
}

// oddExec reports whether a command runs a program from an unusual place.
func (c *Persistence) oddExec(cmd string) bool {
	for _, w := range strings.Fields(cmd) {
		w = strings.Trim(w, `"'`)
		w = strings.TrimLeft(w, "-@!+:")
		if !strings.HasPrefix(w, "/") && !strings.HasPrefix(w, "~") && !strings.HasPrefix(w, "$HOME") {
			continue
		}
		w = strings.Replace(strings.Replace(w, "$HOME", c.env.Home, 1), "~", c.env.Home, 1)
		for _, odd := range []string{c.env.Home + "/", "/tmp/", "/var/tmp/", "/dev/shm/", "/opt/"} {
			if strings.HasPrefix(w, odd) {
				return true
			}
		}
		if real, err := filepath.EvalSymlinks(w); err == nil {
			w = real // /bin/sh -> /usr/bin/bash, which a package owns
		}
		if _, err := os.Stat(w); err == nil && c.env.Pacman.Owner(w) == nil && !strings.HasPrefix(w, "/dev/") && !strings.HasPrefix(w, "/proc/") {
			if _, ok := omarchyPathRef(c.env.OmarchyPath, w); !ok {
				return true
			}
		}
		return false // only the program itself matters
	}
	return false
}

// contentFlags adds flags for risky patterns and odd programs.
func (c *Persistence) contentFlags(flags []model.Flag, runs, content string) []model.Flag {
	if c.oddExec(runs) {
		flags = append(flags, model.FlagRunsFromOdd)
	}
	if p := inspect.RiskyPatterns(runs + "\n" + content); len(p) > 0 {
		fl := model.FlagSuspiciousScript
		fl.Label = "risky patterns: " + strings.Join(p, ", ")
		flags = append(flags, fl)
	}
	return flags
}

func headOf(path string, n int) string {
	var out []string
	for _, l := range readLines(path) {
		if len(out) == n {
			break
		}
		out = append(out, l)
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

// ---- systemd -------------------------------------------------------------

var unitSuffixes = []string{".service", ".socket", ".timer", ".path", ".target", ".mount", ".automount"}

func isUnit(name string) bool {
	for _, s := range unitSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func (c *Persistence) loadPresets() {
	c.presets = map[string][]presetRule{}
	for scope, dirs := range map[string][]string{
		"system": {"/etc/systemd/system-preset", "/usr/lib/systemd/system-preset"},
		"user":   {"/etc/systemd/user-preset", "/usr/lib/systemd/user-preset"},
	} {
		files := map[string]string{} // name -> path; /etc wins
		for _, d := range dirs {
			ents, _ := os.ReadDir(d)
			for _, e := range ents {
				if _, seen := files[e.Name()]; !seen {
					files[e.Name()] = filepath.Join(d, e.Name())
				}
			}
		}
		names := make([]string, 0, len(files))
		for n := range files {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			for _, l := range readLines(files[n]) {
				f := strings.Fields(l)
				if len(f) >= 2 && (f[0] == "enable" || f[0] == "disable") {
					c.presets[scope] = append(c.presets[scope], presetRule{f[0] == "enable", f[1]})
				}
			}
		}
	}
}

var installRe = regexp.MustCompile(`(?m)^\s*(Also|Alias)\s*=\s*(.+)$`)

// loadUnitRelations records which units another unit enables alongside
// itself (Also=) or under another name (Alias=), and which units packages
// enable from their install scripts.
func (c *Persistence) loadUnitRelations() {
	c.related, c.pkgEnabled = map[string]string{}, map[string]string{}
	for _, d := range []string{"/usr/lib/systemd/system", "/usr/lib/systemd/user", "/etc/systemd/system", "/etc/systemd/user"} {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if !e.Type().IsRegular() || !isUnit(e.Name()) {
				continue
			}
			for _, m := range installRe.FindAllSubmatch(readFileSmall(filepath.Join(d, e.Name())), -1) {
				for _, u := range strings.Fields(string(m[2])) {
					if _, ok := c.related[u]; !ok {
						c.related[u] = e.Name()
					}
				}
			}
		}
	}
	for _, p := range c.env.Pacman.Packages {
		if !p.HasInstall {
			continue
		}
		script := p.InstallScript()
		if !strings.Contains(script, "enable") {
			continue
		}
		for _, u := range unitRe.FindAllString(script, -1) {
			if _, ok := c.pkgEnabled[u]; !ok {
				c.pkgEnabled[u] = p.Name
			}
		}
	}
}

// defaultEnabled explains why enabling a unit is a default, or returns "".
func (c *Persistence) defaultEnabled(scope string, names []string, depth int) string {
	for _, n := range names {
		if n == "" {
			continue
		}
		if s := c.omarchyScript(n); s != "" {
			return "enabled by Omarchy (" + s + ")"
		}
		if pkg, ok := c.pkgEnabled[n]; ok {
			return "enabled by the install script of package " + pkg
		}
		if c.presetEnables(scope, n) || c.presetEnables(scope, templateName(n)) {
			return "enabled by a systemd preset (distribution default)"
		}
		if parent, ok := c.related[n]; ok && depth < 3 {
			if why := c.defaultEnabled(scope, []string{parent}, depth+1); why != "" {
				return "comes with " + parent + ", " + why
			}
		}
	}
	return ""
}

func (c *Persistence) presetEnables(scope, unit string) bool {
	if scope != "system" {
		scope = "user"
	}
	for _, r := range c.presets[scope] {
		if ok, _ := filepath.Match(r.pattern, unit); ok {
			return r.enable
		}
	}
	return false
}

// templateName turns "getty@tty1.service" into "getty@.service".
func templateName(unit string) string {
	at := strings.Index(unit, "@")
	dot := strings.LastIndex(unit, ".")
	if at < 0 || dot < at {
		return unit
	}
	return unit[:at+1] + unit[dot:]
}

func (c *Persistence) findUnit(name, scope string) string {
	dirs := []string{"/etc/systemd/system", "/usr/lib/systemd/system"}
	if scope != "system" {
		dirs = []string{filepath.Join(c.env.Home, ".config/systemd/user"), filepath.Join(c.env.Home, ".local/share/systemd/user"), "/etc/systemd/user", "/usr/lib/systemd/user"}
	}
	for _, n := range []string{name, templateName(name)} {
		for _, d := range dirs {
			p := filepath.Join(d, n)
			if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() {
				return p
			}
		}
	}
	return ""
}

var execRe = regexp.MustCompile(`(?m)^\s*(ExecStart|ExecStartPre|ExecStartPost)\s*=\s*(.+)$`)

func unitExec(path string) (runs string, asRoot bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var cmds []string
	for _, m := range execRe.FindAllStringSubmatch(string(b), -1) {
		cmds = append(cmds, strings.TrimSpace(m[2]))
	}
	asRoot = !regexp.MustCompile(`(?m)^\s*(User|DynamicUser)\s*=`).Match(b)
	return strings.Join(cmds, " ; "), asRoot
}

func (c *Persistence) systemd(dir, scope string) {
	mech := "systemd (" + scope + ")"
	ents, err := os.ReadDir(dir)
	if err != nil {
		if isPerm(err) {
			c.unreadable(mech, dir)
		}
		return
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			if target == "/dev/null" || !isUnit(e.Name()) {
				continue // masked unit or not a unit
			}
			c.enabled(mech, scope, p, e.Name(), filepath.Base(target), "alias")
		case e.IsDir() && (strings.HasSuffix(e.Name(), ".wants") || strings.HasSuffix(e.Name(), ".requires") || strings.HasSuffix(e.Name(), ".upholds")):
			kids, err := os.ReadDir(p)
			if err != nil {
				c.unreadable(mech, p)
				continue
			}
			for _, k := range kids {
				kp := filepath.Join(p, k.Name())
				target, _ := os.Readlink(kp)
				if target == "/dev/null" {
					continue
				}
				c.enabled(mech, scope, kp, k.Name(), filepath.Base(target), "started by "+strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".wants"), ".requires"))
			}
		case e.IsDir() && strings.HasSuffix(e.Name(), ".d"):
			kids, err := os.ReadDir(p)
			if err != nil {
				c.unreadable(mech, p)
				continue
			}
			for _, k := range kids {
				c.unitFile(mech+" override", scope, filepath.Join(p, k.Name()), strings.TrimSuffix(e.Name(), ".d")+"/"+k.Name())
			}
		case e.Type().IsRegular() && isUnit(e.Name()):
			c.unitFile(mech+" unit file", scope, p, e.Name())
		}
	}
}

// enabled records one enable link.
func (c *Persistence) enabled(mech, scope, link, name, target, how string) {
	unit := c.findUnit(target, scope)
	if unit == "" {
		unit = c.findUnit(name, scope)
	}
	runs, asRoot := unitExec(unit)
	e := model.Entry{Mechanism: mech, Name: name, Path: link, Runs: runs}
	if target != name && target != "" {
		e.Name = name + " → " + target
	}
	if pkg := c.env.Pacman.Owner(link); pkg != nil {
		e.Why = "enabled by package " + pkg.Name
	} else {
		e.Why = c.defaultEnabled(scope, []string{name, target}, 0)
	}
	if e.Why != "" {
		c.add(e, nil, "")
		return
	}
	e.Why = how + ", enabled by you or a program"
	flags := []model.Flag{model.FlagAutostart}
	if unit != "" && c.env.Pacman.Owner(unit) == nil {
		flags = append(flags, model.FlagLocalUnit)
	}
	if scope == "system" && asRoot {
		flags = append(flags, model.FlagRunsAsRoot)
	}
	content := ""
	if unit != "" {
		content = headOf(unit, 60)
	}
	c.add(e, c.contentFlags(flags, runs, content), content)
}

func (c *Persistence) omarchyEnabled(names ...string) bool { return c.omarchyScript(names...) != "" }

func (c *Persistence) omarchyScript(names ...string) string {
	for _, n := range names {
		for _, cand := range []string{n, templateName(n)} {
			if s, ok := omarchyUnit(c.env.OmarchyPath, cand); ok {
				return s
			}
		}
	}
	return ""
}

// unitFile records a unit file or override defined outside /usr.
func (c *Persistence) unitFile(mech, scope, path, name string) {
	runs, asRoot := unitExec(path)
	e := model.Entry{Mechanism: mech, Name: name, Path: path, Runs: runs}
	if strings.HasPrefix(path, c.env.Home) {
		if c.omarchyEnabled(filepath.Base(path)) {
			e.Why = "created by Omarchy"
			c.add(e, nil, "")
			return
		}
	} else if ok, why, changed := c.systemDefault(path); ok {
		e.Why = why
		c.add(e, nil, "")
		return
	} else if changed {
		e.Why = why
	}
	if e.Why == "" {
		e.Why = "defined locally, not shipped by a package"
	}
	flags := []model.Flag{model.FlagLocalUnit}
	if scope == "system" && asRoot && runs != "" {
		flags = append(flags, model.FlagRunsAsRoot)
	}
	content := headOf(path, 60)
	c.add(e, c.contentFlags(flags, runs, content), content)
}

// ---- files that run things --------------------------------------------------

// systemFile records a file under /etc that makes something run.
func (c *Persistence) systemFile(mech, path, runs string, extra ...model.Flag) {
	e := model.Entry{Mechanism: mech, Name: filepath.Base(path), Path: path, Runs: runs}
	ok, why, changed := c.systemDefault(path)
	if ok {
		e.Why = why
		c.add(e, nil, "")
		return
	}
	flags := []model.Flag{model.FlagAutostart}
	if changed {
		flags = []model.Flag{model.FlagChangedFile}
		e.Why = why
	}
	flags = append(flags, extra...)
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && strings.HasPrefix(path, "/etc/") {
		// these folders hold settings; a program here is out of place
		if res := inspect.Inspect(path, info.Size()); res.Type == inspect.TypeELF {
			e.Runs = "compiled program (" + inspect.HumanSize(info.Size()) + ")"
			e.Why = model.FlagEtcProgram.Label
			c.add(e, append(flags, model.FlagEtcProgram, model.FlagELF), res.Preview)
			return
		}
	}
	content := headOf(path, 60)
	c.add(e, c.contentFlags(flags, runs, content), content)
}

func (c *Persistence) eachFile(dir string, fn func(path string)) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if isPerm(err) {
			c.unreadable(mechanismFor(dir), dir)
		}
		return
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		fn(filepath.Join(dir, e.Name()))
	}
}

// mechanismFor names the mechanism a directory belongs to, for entries
// that could not be read.
func mechanismFor(dir string) string {
	switch {
	case strings.Contains(dir, "sudoers"):
		return "sudo rule"
	case strings.Contains(dir, "polkit"):
		return "polkit rule (permissions)"
	case strings.Contains(dir, "cron"):
		return "cron"
	}
	return "other"
}

func meaningful(path string, n int) string {
	var out []string
	for _, l := range readLines(path) {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
		if len(out) == n {
			break
		}
	}
	return strings.Join(out, " ; ")
}

func (c *Persistence) cron() {
	if _, err := os.Stat("/etc/crontab"); err == nil {
		c.systemFile("cron", "/etc/crontab", meaningful("/etc/crontab", 3), model.FlagRunsAsRoot)
	}
	for _, d := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		c.eachFile(d, func(p string) {
			c.systemFile("cron ("+strings.TrimPrefix(d, "/etc/")+")", p, meaningful(p, 3), model.FlagRunsAsRoot)
		})
	}
	if _, err := os.Stat("/var/spool/cron"); err == nil {
		c.eachFile("/var/spool/cron", func(p string) {
			c.systemFile("cron (user crontab)", p, meaningful(p, 3))
		})
	}
}

var desktopExec = regexp.MustCompile(`(?m)^Exec\s*=\s*(.+)$`)

func (c *Persistence) autostart() {
	c.eachFile("/etc/xdg/autostart", func(p string) {
		m := desktopExec.FindStringSubmatch(string(readFileSmall(p)))
		runs := ""
		if m != nil {
			runs = m[1]
		}
		c.systemFile("autostart (all users)", p, runs)
	})
	dir := filepath.Join(c.env.Home, ".config/autostart")
	c.eachFile(dir, func(p string) {
		b := readFileSmall(p)
		runs := ""
		if m := desktopExec.FindSubmatch(b); m != nil {
			runs = string(m[1])
		}
		e := model.Entry{Mechanism: "autostart", Name: filepath.Base(p), Path: p, Runs: runs}
		if ok, why := c.homeDefault(p, filepath.Join(c.env.OmarchyPath, "config/autostart", filepath.Base(p))); ok {
			e.Why = why
			c.add(e, nil, "")
			return
		}
		if regexp.MustCompile(`(?m)^Hidden\s*=\s*true`).Match(b) {
			e.Why = "turns a system autostart entry off"
			c.add(e, nil, "")
			return
		}
		e.Why = "starts with your desktop session"
		c.add(e, c.contentFlags([]model.Flag{model.FlagAutostart}, runs, string(b)), string(b))
	})
}

func readFileSmall(path string) []byte {
	info, err := os.Stat(path)
	if err != nil || info.Size() > 1<<20 {
		return nil
	}
	b, _ := os.ReadFile(path)
	return b
}

var hyprLaunch = regexp.MustCompile(`exec_cmd|exec_on_start|launch_on_start|exec-once|exec\s*=|os\.execute|io\.popen|o\.popen`)

func (c *Persistence) hyprland() {
	// Omarchy's own startup programs, for completeness.
	def := filepath.Join(c.env.OmarchyPath, "default/hypr/autostart.lua")
	if _, err := os.Stat(def); err == nil {
		var runs []string
		for _, l := range readLines(def) {
			if hyprLaunch.MatchString(l) {
				runs = append(runs, strings.TrimSpace(l))
			}
		}
		c.add(model.Entry{Mechanism: "Hyprland startup", Name: "Omarchy defaults", Path: def,
			Runs: strings.Join(runs, " ; "), Why: "part of Omarchy"}, nil, "")
	}
	dir := filepath.Join(c.env.Home, ".config/hypr")
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !(strings.HasSuffix(n, ".lua") || strings.HasSuffix(n, ".conf")) {
			continue
		}
		p := filepath.Join(dir, n)
		tpl := filepath.Join(c.env.OmarchyPath, "config/hypr", n)
		var launches []string
		for _, l := range addedLines(p, tpl) {
			if hyprLaunch.MatchString(l) {
				launches = append(launches, l)
			}
		}
		entry := model.Entry{Mechanism: "Hyprland startup", Name: n, Path: p}
		if len(launches) == 0 {
			if n == "autostart.lua" {
				entry.Why = "no programs added to Omarchy's default"
				c.add(entry, nil, "")
			}
			continue
		}
		entry.Runs = strings.Join(launches, " ; ")
		entry.Why = "you added programs that start with Hyprland"
		c.add(entry, c.contentFlags([]model.Flag{model.FlagAutostart}, entry.Runs, ""), strings.Join(launches, "\n"))
	}
}

func (c *Persistence) shellStartup() {
	home := c.env.Home
	templates := map[string]string{".bashrc": filepath.Join(c.env.OmarchyPath, "default/bashrc")}
	for _, n := range []string{".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".xprofile", ".xinitrc", ".config/fish/config.fish"} {
		p := filepath.Join(home, n)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		tpl := templates[n]
		if tpl == "" {
			tpl = filepath.Join("/etc/skel", n)
		}
		e := model.Entry{Mechanism: "shell startup", Name: "~/" + n, Path: p}
		added := addedLines(p, tpl)
		if len(added) == 0 {
			e.Why = "same as the default"
			c.add(e, nil, "")
			continue
		}
		e.Runs = strings.Join(added, " ; ")
		e.Why = fmt.Sprintf("%d line(s) beyond the default, run in every new shell", len(added))
		fl := model.FlagAddedLines
		c.add(e, c.contentFlags([]model.Flag{fl}, "", strings.Join(added, "\n")), strings.Join(added, "\n"))
	}
	for _, p := range []string{"/etc/profile", "/etc/bash.bashrc", "/etc/environment", "/etc/zsh/zshrc", "/etc/zsh/zprofile"} {
		if _, err := os.Stat(p); err == nil {
			c.systemFile("shell startup (all users)", p, "")
		}
	}
	c.eachFile("/etc/profile.d", func(p string) { c.systemFile("shell startup (all users)", p, "") })
	envd := filepath.Join(home, ".config/environment.d")
	c.eachFile(envd, func(p string) {
		e := model.Entry{Mechanism: "session environment", Name: filepath.Base(p), Path: p, Runs: meaningful(p, 3)}
		if ok, why := c.homeDefault(p, filepath.Join(c.env.OmarchyPath, "config/environment.d", filepath.Base(p))); ok {
			e.Why = why
			c.add(e, nil, "")
			return
		}
		e.Why = "sets variables for your whole session"
		c.add(e, c.contentFlags([]model.Flag{model.FlagAddedLines}, "", headOf(p, 40)), headOf(p, 40))
	})
}

var hookExec = regexp.MustCompile(`(?m)^Exec\s*=\s*(.+)$`)

func (c *Persistence) pacmanHooks() {
	c.eachFile("/etc/pacman.d/hooks", func(p string) {
		runs := ""
		if m := hookExec.FindSubmatch(readFileSmall(p)); m != nil {
			runs = string(m[1])
		}
		c.systemFile("pacman hook (runs as root on updates)", p, runs, model.FlagRunsAsRoot)
	})
}

func (c *Persistence) omarchyHooks() {
	root := filepath.Join(c.env.Home, ".config/omarchy/hooks")
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".sample") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		e := model.Entry{Mechanism: "Omarchy hook", Name: rel, Path: p, Runs: meaningful(p, 2)}
		if ok, why := c.homeDefault(p, filepath.Join(c.env.OmarchyPath, "config/omarchy/hooks", rel)); ok {
			e.Why = why
			c.add(e, nil, "")
			return nil
		}
		e.Why = "runs on the Omarchy event " + strings.TrimSuffix(filepath.Dir(rel), ".d")
		content := headOf(p, 40)
		c.add(e, c.contentFlags([]model.Flag{model.FlagAutostart}, "", content), content)
		return nil
	})
}

func (c *Persistence) omarchyPlugins() {
	dir := filepath.Join(c.env.Home, ".config/omarchy/plugins")
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		var m struct{ Name, Author string }
		json.Unmarshal(readFileSmall(filepath.Join(p, "manifest.json")), &m)
		entry := model.Entry{Mechanism: "Omarchy shell plugin", Name: e.Name(), Path: p, Runs: m.Name,
			Why: "loaded into the Omarchy shell, unsandboxed"}
		c.add(entry, []model.Flag{model.FlagShellPlugin}, "")
	}
}

var udevRun = regexp.MustCompile(`RUN\+?=\s*"([^"]+)"`)

func (c *Persistence) systemHooks() {
	c.eachFile("/etc/udev/rules.d", func(p string) {
		var runs []string
		for _, m := range udevRun.FindAllSubmatch(readFileSmall(p), -1) {
			runs = append(runs, string(m[1]))
		}
		c.systemFile("udev rule (runs on device events)", p, strings.Join(runs, " ; "))
	})
	filepath.WalkDir("/etc/NetworkManager/dispatcher.d", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if isPerm(err) {
				c.unreadable("network hook", p)
			}
			return nil
		}
		if !d.IsDir() {
			c.systemFile("network hook (runs on network changes)", p, meaningful(p, 2), model.FlagRunsAsRoot)
		}
		return nil
	})
	c.eachFile("/etc/modules-load.d", func(p string) { c.systemFile("kernel module at boot", p, meaningful(p, 3)) })
	c.eachFile("/etc/modprobe.d", func(p string) {
		var installs []string
		for _, l := range readLines(p) {
			if t := strings.TrimSpace(l); strings.HasPrefix(t, "install ") {
				installs = append(installs, t)
			}
		}
		if len(installs) > 0 { // plain options are not persistence
			c.systemFile("kernel module hook", p, strings.Join(installs, " ; "), model.FlagRunsAsRoot)
		}
	})
	c.eachFile("/etc/polkit-1/rules.d", func(p string) { c.systemFile("polkit rule (permissions)", p, "") })
	c.eachFile("/etc/sudoers.d", func(p string) {
		var extra []model.Flag
		if bytes.Contains(readFileSmall(p), []byte("NOPASSWD")) {
			extra = append(extra, model.FlagNoPasswd)
		}
		c.systemFile("sudo rule", p, meaningful(p, 3), append([]model.Flag{model.FlagSudoers}, extra...)...)
	})
	if b := readFileSmall("/etc/ld.so.preload"); len(bytes.TrimSpace(b)) > 0 {
		c.add(model.Entry{Mechanism: "library preload", Name: "ld.so.preload", Path: "/etc/ld.so.preload",
			Runs: strings.TrimSpace(string(b)), Why: "loaded into every program"}, []model.Flag{model.FlagPreload}, string(b))
	}
	c.eachFile("/etc/ssh/sshd_config.d", func(p string) {
		c.systemFile("SSH server setting", p, meaningful(p, 3))
	})
}

func (c *Persistence) ssh() {
	keys := filepath.Join(c.env.Home, ".ssh/authorized_keys")
	if lines := meaningfulLines(keys); len(lines) > 0 {
		var names []string
		for _, l := range lines {
			f := strings.Fields(l)
			names = append(names, f[0]+" "+f[len(f)-1])
		}
		c.add(model.Entry{Mechanism: "SSH login", Name: "authorized_keys", Path: keys,
			Runs: fmt.Sprintf("%d key(s) may log in as you", len(lines)), Why: "remote login with these keys"},
			[]model.Flag{model.FlagSSHKeys}, strings.Join(names, "\n"))
	}
	rc := filepath.Join(c.env.Home, ".ssh/rc")
	if _, err := os.Stat(rc); err == nil {
		content := headOf(rc, 40)
		c.add(model.Entry{Mechanism: "SSH login", Name: "~/.ssh/rc", Path: rc, Runs: meaningful(rc, 2),
			Why: "runs on every SSH login"}, c.contentFlags([]model.Flag{model.FlagAutostart}, "", content), content)
	}
}

func meaningfulLines(path string) []string {
	var out []string
	for _, l := range readLines(path) {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	return out
}

func (c *Persistence) agents() {
	// Claude Code: hooks and status line in settings.json, tool servers in ~/.claude.json.
	settings := filepath.Join(c.env.Home, ".claude/settings.json")
	var s struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
		StatusLine struct {
			Command string `json:"command"`
		} `json:"statusLine"`
	}
	if json.Unmarshal(readFileSmall(settings), &s) == nil {
		for event, groups := range s.Hooks {
			for _, g := range groups {
				for _, h := range g.Hooks {
					name := event
					if g.Matcher != "" {
						name += " (" + g.Matcher + ")"
					}
					c.add(model.Entry{Mechanism: "Claude Code hook", Name: name, Path: settings, Runs: h.Command,
						Why: "runs automatically during Claude Code sessions"},
						c.contentFlags([]model.Flag{model.FlagAgentHook}, h.Command, ""), "")
				}
			}
		}
		if s.StatusLine.Command != "" {
			fl := model.FlagAgentHook
			fl.Label = "Claude Code runs this to draw its status line"
			c.add(model.Entry{Mechanism: "Claude Code hook", Name: "status line", Path: settings, Runs: s.StatusLine.Command,
				Why: "runs while Claude Code is open"}, c.contentFlags([]model.Flag{fl}, s.StatusLine.Command, ""), "")
		}
	}
	cfg := filepath.Join(c.env.Home, ".claude.json")
	var cj struct {
		MCP map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
			URL     string   `json:"url"`
		} `json:"mcpServers"`
	}
	if b, err := os.ReadFile(cfg); err == nil && json.Unmarshal(b, &cj) == nil {
		for name, m := range cj.MCP {
			runs := strings.TrimSpace(m.Command + " " + strings.Join(m.Args, " "))
			if runs == "" {
				runs = m.URL
			}
			c.add(model.Entry{Mechanism: "Claude Code tool server", Name: name, Path: cfg, Runs: runs,
				Why: "Claude Code can start or connect to it"}, c.contentFlags([]model.Flag{model.FlagAgentTool}, runs, ""), "")
		}
	}
	// Codex: tool servers and the notify command in config.toml.
	codex := filepath.Join(c.env.Home, ".codex/config.toml")
	f, err := os.Open(codex)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	section := ""
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(l, "[mcp_servers.") && strings.HasSuffix(l, "]"):
			section = strings.TrimSuffix(strings.TrimPrefix(l, "[mcp_servers."), "]")
		case strings.HasPrefix(l, "["):
			section = ""
		case section != "" && strings.HasPrefix(l, "command"):
			_, v, _ := strings.Cut(l, "=")
			runs := strings.Trim(strings.TrimSpace(v), `"`)
			c.add(model.Entry{Mechanism: "Codex tool server", Name: section, Path: codex, Runs: runs,
				Why: "Codex can start it"}, c.contentFlags([]model.Flag{model.FlagAgentTool}, runs, ""), "")
		case section == "" && strings.HasPrefix(l, "notify"):
			_, v, _ := strings.Cut(l, "=")
			c.add(model.Entry{Mechanism: "Codex hook", Name: "notify", Path: codex, Runs: strings.TrimSpace(v),
				Why: "Codex runs it after each turn"}, c.contentFlags([]model.Flag{model.FlagAgentHook}, v, ""), "")
		}
	}
}

var hooksPathRe = regexp.MustCompile(`(?mi)^\s*hookspath\s*=\s*(.+)$`)

func (c *Persistence) git() {
	for _, p := range []string{filepath.Join(c.env.Home, ".gitconfig"), filepath.Join(c.env.Home, ".config/git/config")} {
		if m := hooksPathRe.FindSubmatch(readFileSmall(p)); m != nil {
			runs := strings.TrimSpace(string(m[1]))
			c.add(model.Entry{Mechanism: "git", Name: "core.hooksPath", Path: p, Runs: runs,
				Why: "scripts there run in every repository"}, []model.Flag{model.FlagGitHooksPath}, "")
		}
	}
}

// ---- more places that run code ----------------------------------------------

// sessionEnv covers uwsm's env files, which the Omarchy session sources as
// shell code at login, and fish's conf.d. Omarchy keeps its own uwsm env in
// /usr/share, so anything here was added.
func (c *Persistence) sessionEnv() {
	home := c.env.Home
	var files []string
	for _, n := range []string{"env", "env-hyprland"} {
		files = append(files, filepath.Join(home, ".config/uwsm", n))
	}
	if ents, err := os.ReadDir(filepath.Join(home, ".config/uwsm/env.d")); err == nil {
		for _, e := range ents {
			files = append(files, filepath.Join(home, ".config/uwsm/env.d", e.Name()))
		}
	}
	for _, p := range files {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		lines := meaningfulLines(p)
		e := model.Entry{Mechanism: "session startup (uwsm)", Name: strings.TrimPrefix(p, home+"/.config/"), Path: p,
			Runs: strings.Join(lines, " ; ")}
		if len(lines) == 0 {
			e.Why = "empty"
			c.add(e, nil, "")
			continue
		}
		e.Why = "shell code run when your desktop session starts"
		c.add(e, c.contentFlags([]model.Flag{model.FlagAddedLines}, "", strings.Join(lines, "\n")), headOf(p, 40))
	}
	c.eachFile(filepath.Join(home, ".config/fish/conf.d"), func(p string) {
		lines := meaningfulLines(p)
		e := model.Entry{Mechanism: "shell startup", Name: "~/.config/fish/conf.d/" + filepath.Base(p), Path: p, Runs: strings.Join(lines, " ; ")}
		if len(lines) == 0 {
			e.Why = "empty"
			c.add(e, nil, "")
			return
		}
		e.Why = "run in every new fish shell"
		c.add(e, c.contentFlags([]model.Flag{model.FlagAddedLines}, "", strings.Join(lines, "\n")), headOf(p, 40))
	})
}

// dbusServices lists D-Bus services defined in home: a program asking for
// that bus name (often a common one, like notifications) starts them.
func (c *Persistence) dbusServices() {
	c.eachFile(filepath.Join(c.env.Home, ".local/share/dbus-1/services"), func(p string) {
		b := readFileSmall(p)
		runs := ""
		if m := desktopExec.FindSubmatch(b); m != nil {
			runs = string(m[1])
		}
		e := model.Entry{Mechanism: "D-Bus service", Name: filepath.Base(p), Path: p, Runs: runs,
			Why: "starts when a program asks for this name"}
		if runs == "" {
			e.Why = "starts nothing"
			c.add(e, nil, "")
			return
		}
		c.add(e, c.contentFlags([]model.Flag{model.FlagDBusService}, runs, string(b)), string(b))
	})
}

// launchers lists app launchers in home that replace an installed app's
// launcher with a different command, so opening the app runs something else
// first. New launchers (web apps and the like) are not listed.
func (c *Persistence) launchers() {
	dir := filepath.Join(c.env.Home, ".local/share/applications")
	c.eachFile(dir, func(p string) {
		name := filepath.Base(p)
		sys := filepath.Join("/usr/share/applications", name)
		if !strings.HasSuffix(name, ".desktop") {
			return
		}
		if _, err := os.Stat(sys); err != nil {
			return
		}
		b := readFileSmall(p)
		e := model.Entry{Mechanism: "app launcher override", Name: name, Path: p}
		if m := desktopExec.FindSubmatch(b); m != nil {
			e.Runs = string(m[1])
		}
		if ok, why := c.homeDefault(p, filepath.Join(c.env.OmarchyPath, "applications", name)); ok {
			e.Why = why
			c.add(e, nil, "")
			return
		}
		mine := desktopExec.FindAllSubmatch(b, -1)
		theirs := desktopExec.FindAllSubmatch(readFileSmall(sys), -1)
		same := len(mine) == len(theirs)
		for i := 0; same && i < len(mine); i++ {
			same = bytes.Equal(bytes.TrimSpace(mine[i][1]), bytes.TrimSpace(theirs[i][1]))
		}
		if same || e.Runs == "" || regexp.MustCompile(`(?m)^(NoDisplay|Hidden)\s*=\s*true`).Match(b) {
			e.Why = "same command as the app, only looks or menus differ"
			c.add(e, nil, "")
			return
		}
		e.Why = "opening the app runs this instead of " + sys
		c.add(e, c.contentFlags([]model.Flag{model.FlagLauncher}, e.Runs, string(b)), string(b))
	})
}

// pythonHooks lists .pth files with import lines and usercustomize.py in
// your Python packages: Python runs them every time it starts.
func (c *Persistence) pythonHooks() {
	dirs, _ := filepath.Glob(filepath.Join(c.env.Home, ".local/lib/python*/site-packages"))
	for _, d := range dirs {
		c.eachFile(d, func(p string) {
			name := filepath.Base(p)
			var code []string
			switch {
			case strings.HasSuffix(name, ".pth"):
				for _, l := range readLines(p) {
					if t := strings.TrimSpace(l); strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "import\t") {
						code = append(code, t)
					}
				}
			case name == "usercustomize.py" || name == "sitecustomize.py":
				code = meaningfulLines(p)
			}
			if len(code) == 0 {
				return // plain .pth files only add paths
			}
			e := model.Entry{Mechanism: "Python startup", Name: name, Path: p, Runs: strings.Join(code, " ; "),
				Why: "runs every time Python starts"}
			c.add(e, c.contentFlags([]model.Flag{model.FlagPythonHook}, "", strings.Join(code, "\n")), strings.Join(code, "\n"))
		})
	}
}

// accounts lists who can log in and who may use sudo. Root and you are the
// defaults; any other account with uid 0, a login shell or admin rights is
// listed.
func (c *Persistence) accounts() {
	me := ""
	if info, err := os.Stat(c.env.Home); err == nil {
		me = userName(int(info.Sys().(*syscall.Stat_t).Uid))
	}
	empty := map[string]bool{}
	for _, l := range readLines("/etc/shadow") { // root scans only
		if f := strings.Split(l, ":"); len(f) > 1 && f[1] == "" {
			empty[f[0]] = true
		}
	}
	for _, l := range readLines("/etc/passwd") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		name, uid, shell := f[0], f[2], f[6]
		login := shellNames[filepath.Base(shell)] // git-shell and nologin can't run commands
		var flags []model.Flag
		switch {
		case uid == "0" && name != "root":
			flags = append(flags, model.FlagRootAccount)
		case login && name != "root" && name != me:
			flags = append(flags, model.FlagExtraLogin)
		}
		if empty[name] && login {
			flags = append(flags, model.FlagNoPassword)
		}
		if !login && len(flags) == 0 {
			continue // system accounts
		}
		e := model.Entry{Mechanism: "accounts", Name: name, Path: "/etc/passwd", Runs: "uid " + uid + ", shell " + shell}
		if len(flags) == 0 {
			e.Why = "you"
			if name == "root" {
				e.Why = "the system administrator"
			}
			c.add(e, nil, "")
			continue
		}
		e.Why = flags[0].Label
		c.add(e, flags, l)
	}
	for _, l := range readLines("/etc/group") {
		f := strings.Split(l, ":")
		if len(f) < 4 || (f[0] != "wheel" && f[0] != "sudo" && f[0] != "root") {
			continue
		}
		for _, member := range strings.Split(f[3], ",") {
			if member == "" || member == "root" {
				continue
			}
			e := model.Entry{Mechanism: "accounts", Name: member + " in " + f[0], Path: "/etc/group",
				Runs: "member of " + f[0]}
			if member == me {
				e.Why = "you"
				c.add(e, nil, "")
				continue
			}
			e.Why = model.FlagExtraAdmin.Label
			c.add(e, []model.Flag{model.FlagExtraAdmin}, l)
		}
	}
}

// ---- scripts that trusted programs install ---------------------------------

// shippedBy reports whether everything an entry runs from home or /tmp is a
// script that a program from Arch or Omarchy carries inside itself and
// wrote out, the way herdr installs its Claude Code hook. Only packages
// whose name appears in the script's path are read, and only an exact copy
// counts, so an edited script is listed again.
func (c *Persistence) shippedBy(runs string) (string, bool) {
	var by string
	found := false
	for _, w := range strings.Fields(runs) {
		w = strings.Trim(w, `"'`)
		w = strings.Replace(strings.Replace(w, "$HOME", c.env.Home, 1), "~", c.env.Home, 1)
		if !strings.HasPrefix(w, c.env.Home+"/") && !strings.HasPrefix(w, "/tmp/") {
			continue // system programs are judged elsewhere
		}
		pkg, ok := c.embeddedIn(w)
		if !ok {
			return "", false
		}
		found, by = true, pkg
	}
	if !found {
		return "", false
	}
	return "set up by " + by + ": the script is an exact copy of the one " + strings.SplitN(by, " ", 2)[0] + " ships", true
}

// embeddedIn returns the trusted package whose files contain this script
// byte for byte.
func (c *Persistence) embeddedIn(path string) (string, bool) {
	if by, ok := c.shipped[path]; ok {
		return by, by != ""
	}
	by, ok := c.findEmbedding(path)
	if c.shipped == nil {
		c.shipped = map[string]string{}
	}
	c.shipped[path] = by
	return by, ok
}

func (c *Persistence) findEmbedding(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 64 || info.Size() > 1<<20 {
		return "", false // tiny scripts would match by chance
	}
	script, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	rel := strings.TrimPrefix(path, c.env.Home)
	for _, name := range regexp.MustCompile(`[A-Za-z0-9]+`).FindAllString(rel, -1) {
		pkg := c.env.Pacman.Package(strings.ToLower(name))
		if pkg == nil {
			continue
		}
		trust := c.env.Trust(pkg)
		if trust != model.TrustOmarchy && trust != model.TrustArch {
			continue
		}
		budget := int64(512 << 20)
		for _, f := range pkg.Files {
			if strings.HasSuffix(f, "/") {
				continue
			}
			fi, err := os.Stat(f)
			if err != nil || !fi.Mode().IsRegular() || fi.Size() < info.Size() || fi.Size() > budget {
				continue
			}
			budget -= fi.Size()
			if !packageFileUnchanged(c.env, f) {
				continue // a changed program vouches for nothing
			}
			if b, err := os.ReadFile(f); err == nil && bytes.Contains(b, script) {
				return pkg.Name + " (" + trust.Label() + ")", true
			}
		}
	}
	return "", false
}
