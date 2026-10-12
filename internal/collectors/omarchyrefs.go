package collectors

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/BuFuuu/based/internal/model"
)

// Omarchy's own installer and migrations patch some package files and drop
// unowned ones (e.g. fixing a shebang, adding a sleep hook). We index every
// system path its scripts mention so those items can be marked as expected
// instead of alarming.
var (
	refsOnce sync.Once
	refs     map[string]string   // absolute path -> script that mentions it
	units    map[string]string   // systemd unit name -> script that mentions it
	byName   map[string][]string // base name -> files Omarchy ships with that name
	pathRe   = regexp.MustCompile(`/(?:usr|etc|opt|boot)/[A-Za-z0-9._+@-]+(?:/[A-Za-z0-9._+@-]+)*`)
	unitRe   = regexp.MustCompile(`[A-Za-z0-9@_.:-]+\.(?:service|socket|timer|path|target|mount)\b`)
	enableRe = regexp.MustCompile(`systemctl[^\n]*?\benable\s+(?:--now\s+)?([A-Za-z0-9@_.-]+)`)
)

func omarchyRefs(omarchyPath string) map[string]string {
	refsOnce.Do(func() {
		refs = map[string]string{}
		units = map[string]string{}
		byName = map[string][]string{}
		for _, dir := range []string{"install", "migrations", "bin", "default", "config"} {
			root := filepath.Join(omarchyPath, dir)
			filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if info, err := d.Info(); err != nil || info.Size() > 1<<20 {
					return nil
				}
				b, err := os.ReadFile(p)
				if err != nil {
					return nil
				}
				rel, _ := filepath.Rel(omarchyPath, p)
				byName[d.Name()] = append(byName[d.Name()], p)
				if dir == "config" {
					return nil // templates: indexed by name only
				}
				for _, u := range unitRe.FindAllString(string(b), -1) {
					if _, ok := units[u]; !ok {
						units[u] = rel
					}
				}
				for _, m := range enableRe.FindAllStringSubmatch(string(b), -1) {
					u := m[1]
					if !strings.Contains(u, ".") {
						u += ".service" // `systemctl enable ufw`
					}
					if _, ok := units[u]; !ok {
						units[u] = rel
					}
				}
				for _, m := range pathRe.FindAllString(string(b), -1) {
					m = strings.TrimRight(m, ".")
					if _, ok := refs[m]; !ok {
						refs[m] = rel
					}
				}
				return nil
			})
		}
	})
	return refs
}

// omarchyUnit returns the Omarchy script that mentions a systemd unit.
func omarchyUnit(omarchyPath, unit string) (string, bool) {
	omarchyRefs(omarchyPath)
	s, ok := units[unit]
	return s, ok
}

// omarchyCopy reports whether a file is identical to one Omarchy ships
// (Omarchy installs some hooks and configs by copying them).
func omarchyCopy(omarchyPath, path string) (string, bool) {
	omarchyRefs(omarchyPath)
	have, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, cand := range byName[filepath.Base(path)] {
		if want, err := os.ReadFile(cand); err == nil && bytes.Equal(have, want) {
			rel, _ := filepath.Rel(omarchyPath, cand)
			return rel, true
		}
	}
	return "", false
}

// omarchyPathRef returns the Omarchy script that mentions a path.
func omarchyPathRef(omarchyPath, path string) (string, bool) {
	s, ok := omarchyRefs(omarchyPath)[path]
	return s, ok
}

// markOmarchy lowers the score of a system finding whose path (or parent
// directory) is managed by Omarchy's own scripts.
func markOmarchy(f *model.Finding, omarchyPath string) {
	r := omarchyRefs(omarchyPath)
	path := strings.TrimSuffix(f.Subject, "/")
	script, ok := r[path]
	if !ok {
		if src, ok := omarchyOverride(omarchyPath, path); ok {
			f.AddFlag(model.Flag{Code: "omarchy", Label: "set by Omarchy (" + src + ")", Weight: -60})
			return
		}
		if t, ok := installedWithOmarchy(path); ok {
			f.AddFlag(model.Flag{Code: "omarchy-install", Label: "created while Omarchy was installed (" + t.Format("2006-01-02") + "), unchanged since", Weight: -60})
		}
		return
	}
	f.AddFlag(model.Flag{Code: "omarchy", Label: "changed by Omarchy itself (" + script + ")", Weight: -60})
	f.SetFact("omarchy script", filepath.Join(omarchyPath, script))
}

// omarchyOverride reports whether an /etc file is identical to the copy
// Omarchy keeps in etc-overrides, where /etc/security/faillock.conf is
// stored as security-faillock.conf.
func omarchyOverride(omarchyPath, path string) (string, bool) {
	rel, ok := strings.CutPrefix(path, "/etc/")
	if !ok {
		return "", false
	}
	name := strings.ReplaceAll(rel, "/", "-")
	src := filepath.Join(omarchyPath, "etc-overrides", name)
	want, err1 := os.ReadFile(src)
	have, err2 := os.ReadFile(path)
	if err1 != nil || err2 != nil || !bytes.Equal(want, have) {
		return "", false
	}
	return "etc-overrides/" + name, true
}
