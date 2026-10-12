package collectors

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"
)

// tree summarises a whole non-default directory as one finding instead of
// thousands. Files inside that carry serious flags are still reported on
// their own. WalkDir visits a subtree contiguously, so one open tree at a
// time is enough.
type tree struct {
	root     string
	kind     model.Kind
	title    string
	flags    []model.Flag
	files    int
	execs    int
	size     int64
	newest   time.Time
	oldest   time.Time
	newestAt string
	recent   []recentFile         // newest files, for the preview
	mark     func(*model.Finding) // optional adjustment before reporting
	direct   bool                 // groups loose files of a directory; dated by its files
}

type recentFile struct {
	path  string
	added time.Time
}

const recentKeep = 15

func newTree(root string, kind model.Kind, title string, flags ...model.Flag) *tree {
	return &tree{root: root, kind: kind, title: title, flags: flags}
}

// addFlag adds a flag to the summary once.
func (t *tree) addFlag(fl model.Flag) {
	for _, have := range t.flags {
		if have.Code == fl.Code {
			return
		}
	}
	t.flags = append(t.flags, fl)
}

func (t *tree) contains(path string) bool {
	return t != nil && strings.HasPrefix(path, t.root+"/")
}

func (t *tree) add(path string, info fs.FileInfo) {
	t.files++
	t.size += info.Size()
	if inspect.IsExecutable(info) {
		t.execs++
	}
	added, _, _ := inspect.Times(path)
	if added.IsZero() {
		added = info.ModTime()
	}
	t.remember(path, added)
	if added.After(t.newest) {
		t.newest, t.newestAt = added, path
	}
	if t.oldest.IsZero() || added.Before(t.oldest) {
		t.oldest = added
	}
}

func (t *tree) remember(path string, added time.Time) {
	if len(t.recent) == recentKeep && !added.After(t.recent[len(t.recent)-1].added) {
		return
	}
	i := sort.Search(len(t.recent), func(i int) bool { return t.recent[i].added.Before(added) })
	t.recent = append(t.recent, recentFile{})
	copy(t.recent[i+1:], t.recent[i:])
	t.recent[i] = recentFile{path, added}
	if len(t.recent) > recentKeep {
		t.recent = t.recent[:recentKeep]
	}
}

// close reports the tree. A tree with no files is skipped.
func (t *tree) close(r *scan.Reporter) {
	if t == nil || t.files == 0 {
		return
	}
	f := model.Finding{Kind: t.kind, Subject: t.root + "/", Title: t.title}
	if !t.direct {
		f.Added, f.AddedSource, _ = inspect.Times(t.root)
	}
	if f.Added.IsZero() {
		f.Added, f.AddedSource = t.newest, "newest file"
	}
	for _, fl := range t.flags {
		f.AddFlag(fl)
	}
	f.SetFact("files", num(t.files))
	f.SetFact("executables", num(t.execs))
	f.SetFact("total size", inspect.HumanSize(t.size))
	f.SetFact("newest file", fmt.Sprintf("%s (%s)", t.newestAt, t.newest.Format(time.DateTime)))
	var lines []string
	for _, rf := range t.recent {
		lines = append(lines, rf.added.Format("2006-01-02 15:04")+"  "+strings.TrimPrefix(rf.path, t.root+"/"))
	}
	if t.files > len(t.recent) {
		lines = append(lines, fmt.Sprintf("… and %s more", num(t.files-len(t.recent))))
	}
	f.Preview = strings.Join(lines, "\n")
	f.Fingerprint = fmt.Sprintf("%d:%d", t.files, t.newest.UnixNano())
	if t.mark != nil {
		t.mark(&f)
	}
	r.Report(f)
}
