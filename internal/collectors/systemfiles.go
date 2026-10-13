package collectors

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/pacman"
	"github.com/BuFuuu/based/internal/scan"
)

// SystemFiles compares system directories against the package database.
// How carefully a file is checked follows its trust level:
//
//	Omarchy / Arch repo files: size, mtime, ctime and permissions are compared
//	  with the package record; the file is only hashed when one looks off.
//	  (ctime cannot be set back by tools like touch, so a content change shows
//	  up even when the mtime was faked.)
//	AUR / foreign files: always hashed against the package record.
//	Unowned files: contents inspected and hashed.
//
// Unowned data under /var is listed for overview only.
type SystemFiles struct {
	checked, modified, unowned int
	omarchyPath                string
	groups                     map[string]*tree // loose unowned /var files and symlinks, per directory
}

func (c *SystemFiles) report(r *scan.Reporter, f model.Finding) {
	markOmarchy(&f, c.omarchyPath)
	r.Report(f)
}

var systemRoots = []string{"/usr", "/etc", "/opt", "/boot", "/var"}

// ctimeSlack allows for install scripts that touch files right after
// extraction.
const ctimeSlack = 10 * 60

// Files the system generates at runtime or from package hooks. They are
// expected to be unowned. Persistence-related paths (systemd enablement
// symlinks, cron) are left to the persistence collector.
var systemIgnore = newIgnoreSet([]string{
	"/etc/machine-id", "/etc/ld.so.cache", "/etc/adjtime", "/etc/hostname",
	"/etc/localtime", "/etc/locale.conf", "/etc/vconsole.conf", "/etc/mtab",
	"/etc/.pwd.lock", "/etc/.updated", "/etc/passwd-", "/etc/shadow-", "/etc/group-", "/etc/gshadow-",
	"/etc/subuid-", "/etc/subgid-", "/etc/os-release",
	"/etc/pacman.d/gnupg/**",
	"/etc/ssl/certs/**",
	"/etc/ca-certificates/extracted/**",
	// covered by the persistence collector
	"/etc/systemd/system/**", "/etc/systemd/user/**", "/etc/udev/rules.d/**", "/etc/pacman.d/hooks/**",
	"/etc/cron.d/**", "/etc/cron.hourly/**", "/etc/cron.daily/**", "/etc/cron.weekly/**", "/etc/cron.monthly/**",
	"/etc/crontab", "/etc/xdg/autostart/**", "/etc/profile.d/**", "/etc/NetworkManager/dispatcher.d/**",
	"/etc/modules-load.d/**", "/etc/sudoers.d/**", "/etc/polkit-1/rules.d/**", "/etc/ssh/sshd_config.d/**",
	"/etc/ld.so.preload",
	"/etc/NetworkManager/system-connections/**",
	"/etc/udev/hwdb.bin",
	"/etc/printcap", "/etc/cups/*.O", // written by cups
	"/etc/X11/xorg.conf.d/00-keyboard.conf", // written by localectl
	"/etc/ssh/ssh_host_*",
	"/usr/lib/modules/*/modules.*",
	"/usr/lib/locale/locale-archive",
	"/usr/lib/udev/hwdb.bin",
	"/usr/lib/gdk-pixbuf-2.0/*/loaders.cache",
	"/usr/lib/gtk-*/*/immodules.cache",
	"/usr/lib/gio/modules/giomodule.cache",
	"/usr/share/applications/mimeinfo.cache",
	"/usr/share/glib-2.0/schemas/gschemas.compiled",
	"/usr/share/icons/*/icon-theme.cache",
	"/usr/share/info/dir",
	"/usr/share/mime/**",
	"fonts.dir", "fonts.scale", ".uuid",
	"__pycache__/**",
	"/var/log/**", "/var/cache/**", "/var/tmp/**", "/var/lib/pacman/**", // logs, caches, temp collector
	"/var/run/**", "/var/lock/**", "/var/lib/systemd/coredump/**", "/var/.updated",
})

func (*SystemFiles) ID() string    { return "files.system" }
func (*SystemFiles) Title() string { return "System files" }

func (*SystemFiles) Estimate(env *scan.Env, prev int) int {
	if prev > 0 {
		return prev
	}
	if env.Pacman == nil {
		return 0
	}
	return env.Pacman.OwnedUnder(systemRoots...)
}

func (c *SystemFiles) Collect(ctx context.Context, env *scan.Env, r *scan.Reporter) error {
	db := env.Pacman
	if db == nil {
		return fmt.Errorf("package database not loaded")
	}
	c.omarchyPath = env.OmarchyPath
	c.groups = map[string]*tree{}
	var cur *tree
	for _, root := range systemRoots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if cur != nil && !cur.contains(path) {
				cur.close(r)
				cur = nil
			}
			if err != nil {
				if isPerm(err) {
					r.Unreadable(path)
				}
				if d != nil && d.IsDir() && path != root {
					return fs.SkipDir
				}
				return nil
			}
			if systemIgnore.match(path, d.IsDir()) {
				if d.IsDir() {
					return fs.SkipDir
				}
				r.Tick(path, "generated")
				return nil
			}
			if d.IsDir() {
				if cur == nil && db.Owner(path) != nil {
					c.ownedDir(path, d, env, r)
				}
				if cur == nil && path != root && db.Owner(path) == nil && strings.HasPrefix(path, "/var/") {
					c.unownedVarDir(path, r)
					return fs.SkipDir
				}
				if cur == nil && path != root && db.Owner(path) == nil {
					flags := []model.Flag{model.FlagUnownedSystem}
					if strings.HasPrefix(path, "/etc/") {
						flags = append(flags, model.FlagUnownedEtc)
					}
					cur = newTree(path, model.KindTree, "unowned directory", flags...)
					cur.mark = func(f *model.Finding) { markOmarchy(f, c.omarchyPath) }
				}
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			c.checked++
			switch {
			case cur != nil:
				r.File(path, model.TrustUnknown)
				cur.add(path, info)
				c.insideTree(path, info, r)
				r.Tick(path, "unowned")
			case db.Owner(path) == nil:
				r.File(path, model.TrustUnknown)
				if strings.HasPrefix(path, "/var/") {
					c.unownedVarFile(path, info, r)
				} else {
					c.unownedFile(path, info, r)
				}
				r.Tick(path, "unowned")
			default:
				pkg := db.Owner(path)
				c.ownedFile(env, pkg, path, info, r)
				r.Tick(path, pkg.Name)
			}
			return nil
		})
		if err != nil && ctx.Err() != nil {
			return err
		}
	}
	cur.close(r)
	for _, t := range c.groups {
		t.close(r)
	}
	r.Note(fmt.Sprintf("%s files · %d modified · %d unowned", num(c.checked), c.modified, c.unowned))
	return nil
}

// unownedVarDir lists a /var directory no package owns without walking it:
// it is runtime data (databases, containers, app state), useful to know
// about but not worth reading file by file.
func (c *SystemFiles) unownedVarDir(path string, r *scan.Reporter) {
	c.unowned++
	f := model.Finding{Kind: model.KindTree, Subject: path + "/", Title: "unowned data directory"}
	f.Added, f.AddedSource, _ = inspect.Times(path)
	f.AddFlag(model.FlagUnownedVar)
	if info, err := os.Lstat(path); err == nil {
		f.SetFact("owner", inspect.Owner(info))
		f.SetFact("mode", inspect.ModeString(info.Mode()))
	}
	if !shareableDir(path) {
		f.SetFact("entries", "not listable by the user this scan reports to")
	} else if ents, err := os.ReadDir(path); err == nil {
		f.SetFact("entries", num(len(ents)))
		var names []string
		for i, e := range ents {
			if i == 15 {
				names = append(names, fmt.Sprintf("… and %d more", len(ents)-15))
				break
			}
			names = append(names, e.Name())
		}
		f.Preview = strings.Join(names, "\n")
	} else if isPerm(err) {
		f.SetFact("entries", "not readable as this user")
	}
	f.SetFact("note", "runtime data, not walked")
	f.Fingerprint = f.Added.String()
	c.report(r, f)
}

// unownedVarFile groups loose data files per directory; executables are
// listed on their own.
func (c *SystemFiles) unownedVarFile(path string, info fs.FileInfo, r *scan.Reporter) {
	c.unowned++
	if !inspect.IsExecutable(info) {
		c.group(path, "unowned data files", model.FlagUnownedVar).add(path, info)
		return
	}
	f := fileFinding(model.KindFile, path, info)
	f.Title = "executable in /var"
	f.AddFlag(model.FlagUnownedVar)
	f.AddFlag(model.FlagExecInVar)
	addContent(&f, path, info)
	c.report(r, f)
}

// group collects loose unowned items of one directory into a single finding.
func (c *SystemFiles) group(path, title string, flag model.Flag) *tree {
	dir := filepath.Dir(path)
	key := dir + "\x00" + title
	t, ok := c.groups[key]
	if !ok {
		t = newTree(dir, model.KindTree, title, flag)
		t.direct = true
		t.mark = func(f *model.Finding) { markOmarchy(f, c.omarchyPath) }
		c.groups[key] = t
	}
	return t
}

func inBinDir(path string) bool {
	dir := filepath.Dir(path)
	return strings.HasSuffix(dir, "/bin") || strings.HasSuffix(dir, "/sbin") ||
		strings.HasPrefix(path, "/usr/lib/systemd/") || strings.HasPrefix(path, "/usr/libexec/")
}

func (c *SystemFiles) unownedFile(path string, info fs.FileInfo, r *scan.Reporter) {
	c.unowned++
	f := fileFinding(model.KindFile, path, info)
	f.Title = "unowned file"
	f.AddFlag(model.FlagUnownedSystem)
	if info.Mode()&fs.ModeSymlink != 0 {
		if !inBinDir(path) {
			// e.g. fontconfig's conf.d links, made by package hooks
			c.group(path, "unowned symlinks", model.Flag{Code: "unowned-link", Label: "symlinks not owned by any package", Weight: 5}).add(path, info)
			return
		}
		f.Title = "unowned command symlink"
		f.Flags = []model.Flag{model.FlagUnownedSystem}
		f.SetFact("target", readlink(path))
		c.report(r, f)
		return
	}
	switch {
	case inspect.IsExecutable(info) && inBinDir(path):
		f.Title = "unowned executable"
		f.AddFlag(model.FlagUnownedBinary)
	case strings.Contains(filepath.Base(path), ".so"):
		f.Title = "unowned library"
		f.AddFlag(model.FlagUnownedLibrary)
	case strings.HasSuffix(path, ".pacnew") || strings.HasSuffix(path, ".pacsave"):
		f.Title = "leftover pacman config"
		f.Flags = []model.Flag{model.FlagConfigEdited}
	case kernelModule.MatchString(path):
		f.Title = "unowned kernel module"
		f.AddFlag(model.FlagKernelModule)
		if dkmsBuilt(path) {
			f.AddFlag(model.FlagDKMS)
		}
	case securityConfig(path):
		f.Title = "unowned security config"
		f.AddFlag(model.FlagSecurityConfig)
	}
	for _, fl := range inspect.ModeFlags(path, info, true) {
		f.AddFlag(fl)
	}
	res := addContent(&f, path, info)
	if strings.HasPrefix(path, "/etc/") {
		f.AddFlag(model.FlagUnownedEtc)
		if res.Type == inspect.TypeELF || inspect.IsExecutable(info) {
			f.Title = "program in /etc"
			f.AddFlag(model.FlagEtcProgram)
		}
	}
	c.report(r, f)
}

// insideTree reports a file inside an unowned directory only when it carries
// flags that matter on their own.
func (c *SystemFiles) insideTree(path string, info fs.FileInfo, r *scan.Reporter) {
	c.unowned++
	flags := inspect.ModeFlags(path, info, true)
	if !info.Mode().IsRegular() {
		return
	}
	var content inspect.Result
	if inspect.IsExecutable(info) {
		content = inspect.Inspect(path, info.Size())
		flags = append(flags, content.Flags()...)
	}
	weight := 0
	for _, fl := range flags {
		if fl.Code != model.FlagELF.Code {
			weight += fl.Weight
		}
	}
	if weight < 35 {
		return
	}
	f := fileFinding(model.KindFile, path, info)
	f.Title = "risky file in unowned directory"
	f.AddFlag(model.FlagUnownedSystem)
	for _, fl := range flags {
		f.AddFlag(fl)
	}
	addContent(&f, path, info)
	c.report(r, f)
}

// vouch marks a package file whose content changed: the package only vouches
// for what it shipped, so the current content is unknown.
func vouch(f *model.Finding, pkgTrust model.Trust) {
	f.Trust = model.TrustUnknown
	f.SetFact("package trust", pkgTrust.Label()+", but only for the content it shipped, which this file no longer has")
}

func unixMode(m fs.FileMode) uint32 {
	v := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	return v
}

// ownedDir checks a package directory's permissions and owner: a system
// folder anyone (or you) can write to lets programs be swapped.
func (c *SystemFiles) ownedDir(path string, d fs.DirEntry, env *scan.Env, r *scan.Reporter) {
	exp, ok := env.Pacman.Expected(path)
	if !ok || exp.Type != "dir" {
		return
	}
	info, err := d.Info()
	if err != nil {
		return
	}
	var flags []model.Flag
	if m := unixMode(info.Mode()); exp.Mode != 0 && m != exp.Mode && m&0o022 != 0 && exp.Mode&0o022 == 0 {
		fl := model.FlagModeChanged
		fl.Label = fmt.Sprintf("folder permissions %04o, package ships %04o: others can write to it", m, exp.Mode)
		flags = append(flags, fl)
	}
	if fl, ok := ownerChanged(info, exp); ok {
		flags = append(flags, fl)
	}
	if len(flags) == 0 {
		return
	}
	pkg := env.Pacman.Owner(path)
	f := fileFinding(model.KindFile, path, info)
	f.Title = "package folder changed"
	f.Trust = env.Trust(pkg)
	for _, fl := range flags {
		f.AddFlag(fl)
	}
	f.SetFact("package", pkg.Name+" "+pkg.Version)
	c.report(r, f)
}

// ownerChanged flags a package file now owned by a normal user. Install
// scripts often hand files to system users (polkitd, git, ...), so only
// uids of real people count.
func ownerChanged(info fs.FileInfo, exp pacman.Entry) (model.Flag, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || exp.Uid < 0 || int(st.Uid) == exp.Uid || st.Uid < 1000 || st.Uid == 65534 {
		return model.Flag{}, false
	}
	fl := model.FlagOwnerChanged
	name, _ := inspect.UserName(st.Uid)
	fl.Label = "now owned by " + name + ", who can change it (package: uid " + fmt.Sprint(exp.Uid) + ")"
	return fl, true
}

// linkSwapped flags a package file that became a link, a link that points
// elsewhere, or a link that became a file.
func linkSwapped(path string, info fs.FileInfo, exp pacman.Entry) (model.Flag, bool) {
	isLink := info.Mode()&fs.ModeSymlink != 0
	fl := model.FlagReplacedLink
	switch {
	case exp.Type == "file" && isLink:
		fl.Label = "package file replaced by a link to " + readlink(path)
	case exp.Type == "link" && isLink && exp.Link != "" && readlink(path) != exp.Link:
		fl.Label = "link points to " + readlink(path) + ", package says " + exp.Link
	case exp.Type == "link" && !isLink && info.Mode().IsRegular():
		fl.Label = "package link replaced by a file"
	default:
		return model.Flag{}, false
	}
	return fl, true
}

func (c *SystemFiles) ownedFile(env *scan.Env, pkg *pacman.Package, path string, info fs.FileInfo, r *scan.Reporter) {
	trust := env.Trust(pkg)
	exp, ok := env.Pacman.Expected(path)
	if ok {
		if fl, swapped := linkSwapped(path, info, exp); swapped {
			c.modified++
			f := fileFinding(model.KindFile, path, info)
			vouch(&f, trust)
			f.Title = "package file swapped"
			f.AddFlag(fl)
			f.SetFact("package", pkg.Name+" "+pkg.Version)
			f.SetFact("target", readlink(path))
			c.report(r, f)
			return
		}
	}
	if !info.Mode().IsRegular() {
		return
	}
	r.File(path, trust)
	if !ok {
		return
	}
	changed := info.Size() != exp.Size || info.ModTime().Unix() != exp.Mtime
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Ctim.Sec > pkg.InstallDate.Unix()+ctimeSlack {
		changed = true // touched after install: content or metadata changed
	}

	if md5, isBackup := pkg.Backup[path]; isBackup {
		if !changed {
			return
		}
		sum, err := inspect.MD5(path)
		if err != nil {
			if isPerm(err) {
				r.Unreadable(path)
			}
			return
		}
		if sum == md5 {
			return
		}
		f := fileFinding(model.KindConfig, path, info)
		vouch(&f, trust)
		f.Title = "edited package config"
		f.Added, f.AddedSource, _ = inspect.Times(path)
		f.AddFlag(model.FlagConfigEdited)
		if securityConfig(path) {
			f.AddFlag(model.FlagSecurityConfig)
		}
		f.SetFact("package", pkg.Name+" "+pkg.Version)
		f.Fingerprint = sum
		c.report(r, f)
		return
	}

	var flags []model.Flag
	if exp.Mode != 0 && unixMode(info.Mode()) != exp.Mode {
		fl := model.FlagModeChanged
		fl.Label = fmt.Sprintf("permissions %04o, package ships %04o", unixMode(info.Mode()), exp.Mode)
		flags = append(flags, fl)
		if info.Mode()&fs.ModeSetuid != 0 && exp.Mode&0o4000 == 0 {
			flags = append(flags, model.FlagSUID)
		}
	}
	if fl, ok := ownerChanged(info, exp); ok {
		flags = append(flags, fl)
	}
	if changed && inspect.RootCaps(path) { // setcap changes the ctime
		flags = append(flags, model.FlagRootCaps)
	}
	var actual string
	if (changed || env.Deep || trust == model.TrustForeign) && exp.SHA256 != "" {
		sum, err := inspect.SHA256(path)
		if err != nil {
			if isPerm(err) {
				r.Unreadable(path)
			}
		} else if sum != exp.SHA256 {
			actual = sum
			flags = append(flags, model.FlagModified)
		}
	}
	if len(flags) == 0 {
		return
	}
	c.modified++
	f := fileFinding(model.KindFile, path, info)
	f.Trust = trust
	if actual != "" {
		vouch(&f, trust)
	}
	f.Title = "package file changed"
	for _, fl := range flags {
		f.AddFlag(fl)
	}
	f.SetFact("package", pkg.Name+" "+pkg.Version)
	f.SetFact("installed", pkg.InstallDate.Format("2006-01-02 15:04"))
	if actual != "" {
		f.SetFact("sha256 expected", exp.SHA256)
	}
	addContent(&f, path, info)
	c.report(r, f)
}

var kernelModule = regexp.MustCompile(`^/usr/lib/modules/.*\.ko(\.(zst|xz|gz))?$`)

// dkmsBuilt reports whether DKMS built the module from a package's source:
// it sits under updates/dkms and DKMS has a tree for it.
func dkmsBuilt(path string) bool {
	if !strings.Contains(path, "/updates/dkms/") {
		return false
	}
	name := strings.SplitN(filepath.Base(path), ".ko", 2)[0]
	ents, _ := os.ReadDir("/var/lib/dkms")
	for _, e := range ents {
		if strings.EqualFold(e.Name(), name) || strings.HasPrefix(name, e.Name()) || strings.HasPrefix(e.Name(), strings.Split(name, "_")[0]) {
			return true
		}
	}
	return false
}

// securityConfig reports files that decide who may log in or use sudo, or
// what every program loads.
func securityConfig(path string) bool {
	for _, p := range []string{"/etc/pam.d/", "/etc/security/", "/etc/ld.so.conf.d/", "/etc/sudoers"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	switch path {
	case "/etc/ssh/sshd_config", "/etc/ld.so.conf", "/etc/nsswitch.conf", "/etc/environment", "/etc/shells":
		return true
	}
	return false
}

// shareableDir reports whether the user a root scan reports to could list
// this folder, so its file names may appear in the result.
func shareableDir(path string) bool {
	d, err := os.Open(path)
	if err != nil {
		return false
	}
	defer d.Close()
	return inspect.Shareable(d)
}
