package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BuFuuu/based/internal/pacman"
	"github.com/BuFuuu/based/internal/scan"
)

// PacmanDB loads the package database every later phase compares against.
type PacmanDB struct{}

func (*PacmanDB) ID() string    { return "pacman.db" }
func (*PacmanDB) Title() string { return "Package database" }

func (*PacmanDB) Estimate(_ *scan.Env, _ int) int {
	ents, _ := os.ReadDir(filepath.Join(pacman.DefaultRoot, "local"))
	return len(ents) * 2 // one tick per desc/files, one per mtree
}

func (*PacmanDB) Collect(_ context.Context, env *scan.Env, r *scan.Reporter) error {
	db, err := pacman.Load(pacman.DefaultRoot, func(name string) {
		if name == "" {
			r.Tick("mtree", "hashes")
			return
		}
		r.Tick("/var/lib/pacman/local/"+name, "pkg")
	})
	if err != nil {
		return err
	}
	env.Pacman = db
	env.Defaults = omarchyDefaults(env)
	files := 0
	for _, p := range db.Packages {
		files += len(p.Files)
	}
	r.Note(fmt.Sprintf("%s pkgs · %s files", num(len(db.Packages)), num(files)))
	return nil
}

// omarchyDefaults is the Omarchy install: its package lists plus everything
// they pull in.
func omarchyDefaults(env *scan.Env) map[string]bool {
	roots := []string{"base", "omarchy", "linux-omarchy", "linux-omarchy-headers", "omarchy-keyring"}
	roots = append(roots, readList(filepath.Join(env.OmarchyPath, "install", "omarchy-base.packages"))...)
	roots = append(roots, readList(filepath.Join(env.OmarchyPath, "install", "omarchy-other.packages"))...)
	return env.Pacman.Closure(roots)
}
