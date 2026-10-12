package store

import (
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
