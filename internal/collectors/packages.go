package collectors

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"
)

// Packages lists packages that are not part of the Omarchy install: anything
// explicitly installed outside Omarchy's package lists (and its dependency
// closure), foreign/AUR packages, and packages whose install scripts look risky.
type Packages struct{}

func (*Packages) ID() string    { return "packages" }
func (*Packages) Title() string { return "Packages" }

func (*Packages) Estimate(env *scan.Env, _ int) int {
	if env.Pacman == nil {
		return 0
	}
	return len(env.Pacman.Packages)
}

func (*Packages) Collect(ctx context.Context, env *scan.Env, r *scan.Reporter) error {
	db := env.Pacman
	if db == nil {
		return fmt.Errorf("package database not loaded")
	}
	def := env.Defaults

	extra, foreign := 0, 0
	for _, p := range db.Packages {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.Tick("pkg:"+p.Name, p.Version)
		isForeign := env.Trust(p) == model.TrustForeign
		isExtra := !def[p.Name] && p.Explicit
		var scriptFlags []string
		if p.HasInstall {
			scriptFlags = inspect.RiskyPatterns(p.InstallScript())
		}
		if !isExtra && !isForeign && len(scriptFlags) == 0 {
			continue
		}
		f := model.Finding{Kind: model.KindPackage, Subject: p.Name, Added: p.InstallDate, AddedSource: "installed", Trust: env.Trust(p)}
		f.Title = "package not in Omarchy install"
		if isExtra {
			extra++
			f.AddFlag(model.FlagExtraPackage)
			// dependencies this package pulled in that Omarchy doesn't need
			own := db.Closure([]string{p.Name})
			var pulled []string
			for n := range own {
				if n != p.Name && !def[n] {
					pulled = append(pulled, n)
				}
			}
			sort.Strings(pulled)
			if len(pulled) > 0 {
				f.SetFact("pulled in", truncList(pulled, 12))
			}
		} else if !p.Explicit {
			f.Title = "dependency package"
		}
		if isForeign {
			foreign++
			f.Title = "package not from Arch or Omarchy"
			f.AddFlag(model.FlagForeignPackage)
		}
		if len(scriptFlags) > 0 {
			fl := model.FlagInstallScript
			fl.Label = "install script: " + strings.Join(scriptFlags, ", ")
			f.AddFlag(fl)
			f.Preview = p.InstallScript()
		}
		f.SetFact("version", p.Version)
		f.SetFact("repo", scan.RepoKind(p.Repo))
		f.SetFact("description", p.Desc)
		f.SetFact("url", p.URL)
		f.SetFact("packager", p.Packager)
		f.SetFact("files", num(len(p.Files)))
		if p.Explicit {
			f.SetFact("reason", "explicitly installed")
		} else {
			f.SetFact("reason", "installed as a dependency")
		}
		if pkgbuild := aurPKGBUILD(env.Home, p.Name); pkgbuild != "" {
			f.SetFact("PKGBUILD", pkgbuild)
		}
		f.Fingerprint = p.Version
		r.Report(f)
	}
	r.Note(fmt.Sprintf("%d extra · %d foreign", extra, foreign))
	return nil
}

func readList(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, strings.Fields(l)[0])
		}
	}
	return out
}

func truncList(xs []string, n int) string {
	if len(xs) <= n {
		return strings.Join(xs, ", ")
	}
	return strings.Join(xs[:n], ", ") + fmt.Sprintf(" +%d more", len(xs)-n)
}

// aurPKGBUILD finds a cached PKGBUILD from yay or paru.
func aurPKGBUILD(home, name string) string {
	for _, dir := range []string{".cache/yay", ".cache/paru/clone"} {
		p := filepath.Join(home, dir, name, "PKGBUILD")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
