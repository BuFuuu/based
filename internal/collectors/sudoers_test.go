package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallerSudoRule(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "install.log")
	os.WriteFile(log, []byte("[2026-08-25 11:19:24] - INFO - Enabling sudo permissions for alice\n"), 0o644)

	cases := []struct {
		name, body string
		want       bool
	}{
		{"04_alice", "alice ALL=(ALL) ALL\n", true},
		{"00_alice", "# added\nalice  ALL=(ALL)  ALL\n", true},
		{"04_alice", "alice ALL=(ALL) NOPASSWD: ALL\n", false},
		{"04_alice", "alice ALL=(ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n", false},
		{"04_eve", "eve ALL=(ALL) ALL\n", false},   // not in the install log
		{"04_ali", "ali ALL=(ALL) ALL\n", false},   // prefix of a logged user
		{"04_alice", "eve ALL=(ALL) ALL\n", false}, // name and rule disagree
		{"alice", "alice ALL=(ALL) ALL\n", false},  // not archinstall's naming
	}
	for _, tc := range cases {
		p := filepath.Join(dir, tc.name)
		os.WriteFile(p, []byte(tc.body), 0o644)
		if _, got := installerSudoRule(p, log); got != tc.want {
			t.Errorf("%s %q: got %v, want %v", tc.name, tc.body, got, tc.want)
		}
	}
	os.WriteFile(filepath.Join(dir, "04_alice"), []byte("alice ALL=(ALL) ALL\n"), 0o644)
	if _, ok := installerSudoRule(filepath.Join(dir, "04_alice"), filepath.Join(dir, "missing.log")); ok {
		t.Error("accepted without an install log")
	}
}
