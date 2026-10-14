package collectors

import (
	"context"
	"fmt"
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
		// anyone can write here, so any name may be a planted link: walk
		// without following links
		inspect.WalkNoLinks(ctx, root, func(string) bool { return true },
			func(e *inspect.Entry) {
				checked++
				r.File(e.Path, model.TrustUnknown)
				c.check(e, r)
				r.Tick(e.Path, "temp")
			},
			func(path string, err error) {
				if isPerm(err) {
					r.Unreadable(path)
				}
			})
	}
	r.Note(fmt.Sprintf("%s files · %d runnable", num(checked), c.found))
	return ctx.Err()
}

func (c *TempFiles) check(e *inspect.Entry, r *scan.Reporter) {
	exec := inspect.IsExecutable(e.Info)
	var res inspect.Result
	file, err := e.Open()
	if err == nil {
		defer file.Close()
		res = inspect.InspectFile(file, e.Path, e.Info.Size())
	}
	if !exec && res.Type != inspect.TypeELF {
		return
	}
	c.found++
	f := entryFinding(model.KindFile, e)
	f.Title = "runnable file in temp"
	f.AddFlag(model.FlagExecInTemp)
	if inspect.IsHidden(e.Path, filepath.Dir(filepath.Dir(e.Path))) {
		f.AddFlag(model.FlagHidden)
	}
	for _, fl := range e.ModeFlags(false) {
		f.AddFlag(fl)
	}
	if file != nil {
		addEntryContent(&f, e, file, res)
	}
	r.Report(f)
}
