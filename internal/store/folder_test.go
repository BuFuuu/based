package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BuFuuu/based/internal/model"
)

func TestFolderAllowed(t *testing.T) {
	home := "/home/alice"
	for dir, want := range map[string]bool{
		"/":                          false,
		"/tmp":                       false,
		"/opt":                       false,
		"/home":                      false,
		"/home/alice":                false,
		"/home/alice/.local/bin":     false,
		"/home/alice/.config":        false,
		"/usr/local/bin":             false,
		"/etc/systemd/system":        false,
		"/opt/myapp":                 true,
		"/tmp/build":                 true,
		"/home/alice/Projects/app":   true,
		"/home/alice/.local/share/x": true,
		"/etc/nginx":                 true,
	} {
		if got, why := FolderAllowed(dir, home); got != want {
			t.Errorf("%s: got %v (%s), want %v", dir, got, why, want)
		}
	}
}

func TestFolderCovers(t *testing.T) {
	f := func(kind model.Kind, subj string, sev model.Severity) model.Finding {
		return model.Finding{Kind: kind, Subject: subj, Severity: sev}
	}
	dir := "/home/alice/Projects/app"
	for _, tc := range []struct {
		f    model.Finding
		want bool
	}{
		{f(model.KindFile, dir+"/build/app", model.Med), true},
		{f(model.KindTree, dir+"/node_modules/", model.Low), true},
		{f(model.KindTree, dir+"/", model.Low), true},
		{f(model.KindFile, dir+"/build/suid", model.High), false},
		{f(model.KindFile, dir+"-old/x", model.Low), false},
		{f(model.KindPersist, dir+"/hook", model.Low), true},
		{f(model.KindNetwork, dir+"/server", model.Low), true},
		{f(model.KindPackage, dir, model.Low), false},
	} {
		if got := FolderCovers(dir, tc.f); got != tc.want {
			t.Errorf("%s %s: got %v, want %v", tc.f.Kind, tc.f.Subject, got, tc.want)
		}
	}
	acc := map[string]Accepted{FolderKey(dir): {Fingerprint: "folder", Subject: dir}}
	if !IsAccepted(acc, f(model.KindFile, dir+"/a.out", model.Low)) {
		t.Error("a file in an accepted folder should count as accepted")
	}
}

func TestWritesReplacePlantedLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("keep"), 0o644)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	st, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	// links at the old predictable temp name and at the file itself
	os.Symlink(target, filepath.Join(st.Dir, "latest.json.tmp"))
	os.Symlink(target, filepath.Join(st.Dir, "accepted.json"))
	if err := st.SaveAccepted(map[string]Accepted{"x": {Fingerprint: "f"}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("a write followed a planted link: target now %q", b)
	}
	if info, _ := os.Lstat(filepath.Join(st.Dir, "accepted.json")); info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("accepted.json should now be a plain file")
	}
}

func TestRootSafe(t *testing.T) {
	dir := t.TempDir() // owned by the test user, not root
	if err := rootSafe(filepath.Join(dir, "based")); err == nil {
		t.Fatal("root must refuse a folder another user owns")
	}
	link := filepath.Join(dir, "link")
	os.Symlink("/etc", link)
	if err := rootSafe(filepath.Join(link, "based")); err == nil {
		t.Fatal("root must refuse a path through a symlink")
	}
	if err := rootSafe("/var/lib/based-test-does-not-exist"); err != nil {
		t.Fatalf("root's own folders should pass: %v", err)
	}
}
