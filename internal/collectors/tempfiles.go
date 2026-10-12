package collectors

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"
)

// TempFiles reports anything runnable in world-writable temp locations, a
// classic drop zone for payloads.
type TempFiles struct{ found int }

var tempRoots = []string{"/tmp", "/var/tmp", "/dev/shm"}

func (*TempFiles) ID() string                         { return "files.temp" }
func (*TempFiles) Title() string                      { return "Temp directories" }
func (*TempFiles) Estimate(_ *scan.Env, prev int) int { return prev }

func (c *TempFiles) Collect(ctx context.Context, env *scan.Env, r *scan.Reporter) error {
	checked := 0
	for _, root := range tempRoots {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
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
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			checked++
			r.File(path, model.TrustUnknown)
			c.check(path, info, r)
			r.Tick(path, "temp")
			return nil
		})
	}
	r.Note(fmt.Sprintf("%s files · %d runnable", num(checked), c.found))
	return ctx.Err()
}

func (c *TempFiles) check(path string, info fs.FileInfo, r *scan.Reporter) {
	exec := inspect.IsExecutable(info)
	res := inspect.Inspect(path, info.Size())
	if !exec && res.Type != inspect.TypeELF {
		return
	}
	c.found++
	f := fileFinding(model.KindFile, path, info)
	f.Title = "runnable file in temp"
	f.AddFlag(model.FlagExecInTemp)
	if inspect.IsHidden(path, filepath.Dir(filepath.Dir(path))) {
		f.AddFlag(model.FlagHidden)
	}
	for _, fl := range inspect.ModeFlags(path, info, false) {
		f.AddFlag(fl)
	}
	addContent(&f, path, info)
	r.Report(f)
}
