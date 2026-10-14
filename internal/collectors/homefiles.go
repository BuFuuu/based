package collectors

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"
)

// HomeFiles looks at the user's home in two ways:
//  1. ~/.config is compared with Omarchy's shipped templates: extra apps and
//     edited files are listed (info), so the user sees what drifted.
//  2. The rest of home is searched for executables that stand out: compiled
//     binaries, anything executable in hidden directories or ~/.local/bin,
//     and scripts with risky patterns.
type HomeFiles struct {
	checked, extra, edited, execs int
	groups                        map[string]*tree
}

// Directories that hold managed or bulky content. "~/" entries are anchored
// to home; the rest match anywhere. Language and tool managers will get
// their own collector later.
var homeIgnore = []string{
	// ~/.cache is walked (a common drop spot), but not the caches of known tools
	"~/.cache/yay/**", "~/.cache/paru/**", "~/.cache/ms-playwright/**", "~/.cache/mise/**", "~/.cache/go-build/**",
	"~/.cache/pip/**", "~/.cache/uv/**", "~/.cache/pnpm/**", "~/.cache/bun/**", "~/.cache/puppeteer/**",
	"~/.cache/node-gyp/**", "~/.cache/JetBrains/**", "~/.cache/chromium/**", "~/.cache/mozilla/**",
	"~/.cache/thumbnails/**", "~/.cache/fontconfig/**", "~/.cache/huggingface/**", "~/.cache/pre-commit/**",
	"~/.cache/nvim/**", "~/.cache/typescript/**", "~/.cache/deno/**", "~/.cache/electron/**", "~/.cache/zig/**",
	"~/.cache/google-chrome/**", "~/.cache/BraveSoftware/**", "~/.cache/spotify/**", "~/.cache/mesa_shader_cache*/**",
	"~/.local/share/Trash/**", "~/.local/share/mise/**", "~/.local/share/flatpak/**",
	"~/.local/share/nvim/**", "~/.local/state/**", "~/.var/**", "~/.npm/**", "~/.cargo/registry/**",
	"~/.rustup/**", "~/go/pkg/**", "~/.m2/**", "~/.gradle/**", "~/.bun/install/cache/**",
	"~/.mozilla/**", "~/.config/chromium/**", "~/.config/google-chrome/**", "~/.config/BraveSoftware/**",
	"~/.pki/**", "~/.local/share/Steam/**", "~/.steam/**",
	"~/.config/systemd/**", "~/.config/autostart/**", "~/.config/omarchy/hooks/**", "~/.config/omarchy/plugins/**", // persistence
	"node_modules/**", ".git/**", "__pycache__/**", ".venv/**", "venv/**",
}

func (*HomeFiles) ID() string    { return "files.home" }
func (*HomeFiles) Title() string { return "Home directory" }

func (*HomeFiles) Estimate(_ *scan.Env, prev int) int { return prev }

func homeIgnoreSet(home string) *ignoreSet {
	patterns := make([]string, len(homeIgnore))
	for i, g := range homeIgnore {
		if rest, ok := strings.CutPrefix(g, "~/"); ok {
			g = home + "/" + rest
		}
		patterns[i] = g
	}
	return newIgnoreSet(patterns)
}

func (c *HomeFiles) Collect(ctx context.Context, env *scan.Env, r *scan.Reporter) error {
	if env.UserPart != nil {
		return c.fromUserPart(ctx, env, r)
	}
	if env.Home == "" || env.Home == "/" {
		return fmt.Errorf("no home directory")
	}
	ignore := homeIgnoreSet(env.Home)
	c.groups = map[string]*tree{}
	if err := c.configs(ctx, env, r, ignore); err != nil {
		return err
	}
	err := filepath.WalkDir(env.Home, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if isPerm(err) {
				r.Unreadable(path)
			}
			if d != nil && d.IsDir() && path != env.Home {
				return fs.SkipDir
			}
			return nil
		}
		if path == filepath.Join(env.Home, ".config") {
			return fs.SkipDir // handled by configs
		}
		if path != env.Home && ignore.match(path, d.IsDir()) {
			if d.IsDir() {
				if d.Name() == ".git" {
					c.repoHooks(path, r)
				}
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		c.checked++
		r.File(path, model.TrustUnknown)
		if c.homeFile(env, path, info, r) {
			r.Tick(path, "flagged")
		} else {
			r.Tick(path, "ok")
		}
		return nil
	})
	if err != nil && ctx.Err() != nil {
		return err
	}
	for _, t := range c.groups {
		t.close(r)
	}
	r.Note(fmt.Sprintf("%s files · %d extra configs · %d edited · %d executables", num(c.checked), c.extra, c.edited, c.execs))
	return nil
}

// couldRun says whether a file in home is worth reading: only files that
// could run are.
func couldRun(env *scan.Env, path string, info fs.FileInfo) bool {
	return inspect.IsExecutable(info) || inLocalBin(env, path)
}

func inLocalBin(env *scan.Env, path string) bool {
	return strings.HasPrefix(path, filepath.Join(env.Home, ".local/bin")+"/") ||
		strings.HasPrefix(path, filepath.Join(env.Home, "bin")+"/")
}

func (c *HomeFiles) homeFile(env *scan.Env, path string, info fs.FileInfo, r *scan.Reporter) bool {
	if !couldRun(env, path, info) {
		return false
	}
	res := inspect.Inspect(path, info.Size())
	if res.Type == "" {
		// can't open it: a root scan looks at it without following links
		if f, err := os.Open(path); err == nil {
			f.Close()
		} else if isPerm(err) {
			r.Unreadable(path)
			return false
		}
	}
	return c.judge(env, path, info, res, r, func() model.Finding {
		f := fileFinding(model.KindFile, path, info)
		for _, fl := range inspect.ModeFlags(path, info, false) {
			f.AddFlag(fl)
		}
		addContent(&f, path, info)
		return f
	}, func(hidden bool) *tree {
		t := c.group(env, path, info, hidden)
		t.add(path, info)
		return t
	})
}

// judge decides how a file that could run is listed: on its own when it
// stands out, otherwise in a group. finding builds its finding with the
// file's own facts; group adds it to its group (nil: list it on its own).
func (c *HomeFiles) judge(env *scan.Env, path string, info fs.FileInfo, res inspect.Result, r *scan.Reporter,
	finding func() model.Finding, group func(hidden bool) *tree) bool {
	exec := inspect.IsExecutable(info)
	hidden := inspect.IsHidden(path, env.Home)
	inLocalBin := inLocalBin(env, path)
	if res.Type != inspect.TypeELF && res.Type != inspect.TypeScript && !exec {
		return false
	}
	c.execs++
	standsOut := inLocalBin || len(res.Patterns) > 0 || (res.Type == inspect.TypeELF && hidden) || res.Packed
	if !standsOut && group != nil {
		t := group(hidden)
		if res.Type == inspect.TypeELF {
			t.addFlag(model.FlagELF) // compiled programs weigh more than scripts
		}
		return false
	}
	f := finding()
	switch {
	case f.Title != "":
	case inLocalBin:
		f.Title = "user command"
	case res.Type == inspect.TypeELF:
		f.Title = "binary in hidden directory"
	default:
		f.Title = "executable in home"
	}
	if exec {
		f.AddFlag(model.FlagExecutable)
	}
	if hidden {
		f.AddFlag(model.FlagHidden)
	}
	if shadow := shadowsSystem(path); shadow != "" && inLocalBin {
		f.AddFlag(model.Flag{Code: "shadows", Label: "shadows system command " + shadow, Weight: 35})
	}
	r.Report(f)
	return true
}

// fromUserPart takes the home from the helper that scanned it as you
// (see scan.UserPart). Root then looks into what you can't open yourself,
// without following links, and judges it without showing its contents.
func (c *HomeFiles) fromUserPart(ctx context.Context, env *scan.Env, r *scan.Reporter) error {
	res, err := env.UserPart.Result(ctx, c.ID())
	if err != nil {
		return err
	}
	c.groups = map[string]*tree{}
	ignore := homeIgnoreSet(env.Home)
	var skipped []string
	for _, p := range res.Skipped {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if p != filepath.Clean(p) || !strings.HasPrefix(p, env.Home+"/") || !c.locked(ctx, env, p, r, ignore) {
			skipped = append(skipped, p)
			continue
		}
		// root could look in after all
		res.Unreadable--
		if res.Stats != nil {
			res.Stats["unreadable:"+scan.TopDir(p)]--
		}
	}
	res.Skipped = skipped
	r.Merge(res)
	for _, t := range c.groups {
		t.close(r)
	}
	note := res.Note
	if c.checked > 0 {
		note += fmt.Sprintf(" · %s only root can read", num(c.checked))
	}
	r.Note(note)
	return ctx.Err()
}

// locked looks at a file or folder in home that you can't open, as root,
// never following a link: a link planted there can't lead root elsewhere.
// It reports whether it could look.
func (c *HomeFiles) locked(ctx context.Context, env *scan.Env, path string, r *scan.Reporter, ignore *ignoreSet) bool {
	e, err := inspect.StatNoLinks(path)
	if err != nil {
		return false
	}
	defer e.Close()
	switch {
	case e.Info.Mode().IsRegular():
		c.lockedFile(env, e, nil, r)
	case e.Info.IsDir():
		var t *tree
		group := func(hidden bool) *tree {
			if t == nil {
				t = newTree(path, model.KindTree, "programs only root can read, in "+strings.Replace(path, env.Home, "~", 1), model.FlagExecutable)
				c.groups[path+"\x00locked"] = t
			}
			if hidden {
				t.addFlag(model.FlagHidden)
			}
			return t
		}
		inspect.WalkNoLinks(ctx, path,
			func(p string) bool { return !ignore.match(p, true) },
			func(e *inspect.Entry) {
				if !ignore.match(e.Path, false) {
					c.lockedFile(env, e, group, r)
				}
			},
			func(p string, err error) {
				if isPerm(err) {
					r.Unreadable(p)
				}
			})
	default:
		return false
	}
	return true
}

// lockedFile judges one file only root can read. Ordinary programs go to
// group; without a group (a single locked file) every program is listed.
func (c *HomeFiles) lockedFile(env *scan.Env, e *inspect.Entry, group func(bool) *tree, r *scan.Reporter) {
	c.checked++
	r.File(e.Path, model.TrustUnknown)
	defer r.Tick(e.Path, "only root can read")
	if !couldRun(env, e.Path, e.Info) {
		return
	}
	file, err := e.Open()
	if err != nil {
		return
	}
	defer file.Close()
	res := inspect.InspectFile(file, e.Path, e.Info.Size())
	var inGroup func(bool) *tree
	if group != nil {
		inGroup = func(hidden bool) *tree {
			t := group(hidden)
			added, _, _ := e.Times()
			t.addAt(e.Path, e.Info, added)
			return t
		}
	}
	c.judge(env, e.Path, e.Info, res, r, func() model.Finding {
		f := entryFinding(model.KindFile, e)
		for _, fl := range e.ModeFlags(false) {
			f.AddFlag(fl)
		}
		addEntryContent(&f, e, file, res)
		f.Title = "program in your home only root can read"
		f.SetFact("readable by", "root only")
		return f
	}, inGroup)
}

// group returns the aggregate for ordinary executables under the same app
// directory: ~/.claude, ~/Projects, ~/.local/share/<app>, ~/.config/<app>.
func (c *HomeFiles) group(env *scan.Env, path string, info fs.FileInfo, hidden bool) *tree {
	rel, _ := filepath.Rel(env.Home, path)
	parts := strings.Split(rel, "/")
	n := 1
	if (parts[0] == ".local" || parts[0] == ".config") && len(parts) > 3 {
		n = 3
	} else if len(parts) == 1 {
		n = 0
	}
	key := filepath.Join(append([]string{env.Home}, parts[:n]...)...)
	if t, ok := c.groups[key]; ok {
		return t
	}
	flags := []model.Flag{model.FlagExecutable}
	if strings.HasPrefix(parts[0], ".") && n > 0 {
		flags = append(flags, model.FlagHidden)
	}
	t := newTree(key, model.KindTree, "executables in "+strings.Replace(key, env.Home, "~", 1), flags...)
	c.groups[key] = t
	return t
}

// shadowsSystem returns the system path a ~/.local/bin command hides, if any.
func shadowsSystem(path string) string {
	name := filepath.Base(path)
	for _, dir := range []string{"/usr/bin", "/usr/local/bin"} {
		p := filepath.Join(dir, name)
		if _, err := os.Lstat(p); err == nil {
			return p
		}
	}
	return ""
}

// configs diffs ~/.config against $OMARCHY_PATH/config.
func (c *HomeFiles) configs(ctx context.Context, env *scan.Env, r *scan.Reporter, ignore *ignoreSet) error {
	cfg := filepath.Join(env.Home, ".config")
	tpl := filepath.Join(env.OmarchyPath, "config")
	ents, err := os.ReadDir(cfg)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		path := filepath.Join(cfg, e.Name())
		if ignore.match(path, e.IsDir()) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(tpl, e.Name())); err != nil {
			c.extraTree(path, r, ignore)
			continue
		}
		// Omarchy ships this entry: compare file by file.
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				if isPerm(err) {
					r.Unreadable(p)
				}
				return nil
			}
			if ignore.match(p, d.IsDir()) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			c.checked++
			rel, _ := filepath.Rel(cfg, p)
			want, err := os.ReadFile(filepath.Join(tpl, rel))
			f := fileFinding(model.KindConfig, p, info)
			if err != nil {
				c.extra++
				f.Title = "config not in Omarchy defaults"
				f.AddFlag(model.FlagExtraConfig)
			} else {
				if have, err := os.ReadFile(p); err != nil || bytes.Equal(have, want) {
					r.File(p, model.TrustOmarchy)
					r.Tick(p, "default")
					return nil
				}
				c.edited++
				f.Title = "config edited from Omarchy default"
				f.AddFlag(model.FlagEditedConfig)
				f.SetFact("omarchy default", filepath.Join(tpl, rel))
			}
			r.File(p, model.TrustUnknown)
			if inspect.IsExecutable(info) {
				addContent(&f, p, info)
			}
			r.Report(f)
			r.Tick(p, "changed")
			return nil
		})
	}
	return nil
}

// extraTree summarises a ~/.config entry Omarchy does not ship, still
// surfacing risky executables inside it on their own.
func (c *HomeFiles) extraTree(path string, r *scan.Reporter, ignore *ignoreSet) {
	c.extra++
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if !info.IsDir() {
		f := fileFinding(model.KindConfig, path, info)
		f.Title = "config not in Omarchy defaults"
		f.AddFlag(model.FlagExtraConfig)
		r.Report(f)
		r.Tick(path, "extra")
		return
	}
	t := newTree(path, model.KindConfig, "app config not in Omarchy defaults", model.FlagExtraConfig)
	filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if isPerm(err) {
				r.Unreadable(p)
			}
			return nil
		}
		if ignore.match(p, d.IsDir()) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		c.checked++
		r.File(p, model.TrustUnknown)
		t.add(p, info)
		if inspect.IsExecutable(info) {
			res := inspect.Inspect(p, info.Size())
			if res.Type == "" {
				if f, err := os.Open(p); err == nil {
					f.Close()
				} else if isPerm(err) {
					r.Unreadable(p) // a root scan looks at it
				}
			}
			if len(res.Patterns) > 0 || res.Type == inspect.TypeELF {
				f := fileFinding(model.KindFile, p, info)
				f.Title = "executable inside app config"
				f.AddFlag(model.FlagExecutable)
				addContent(&f, p, info)
				r.Report(f)
			}
		}
		r.Tick(p, "extra")
		return nil
	})
	t.close(r)
}

// repoHooks reports git hooks in a repository: they run on commits,
// checkouts and merges. Git's own *.sample files don't run.
func (c *HomeFiles) repoHooks(gitDir string, r *scan.Reporter) {
	dir := filepath.Join(gitDir, "hooks")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || !inspect.IsExecutable(info) || strings.HasSuffix(e.Name(), ".sample") {
			continue
		}
		f := fileFinding(model.KindFile, p, info)
		f.Title = "git hook in a repository"
		f.AddFlag(model.FlagRepoHook)
		addContent(&f, p, info)
		r.Report(f)
	}
}
