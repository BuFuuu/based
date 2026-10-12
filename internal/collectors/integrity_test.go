package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BuFuuu/based/internal/pacman"
)

func TestLinkSwapped(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	link := filepath.Join(dir, "link")
	os.WriteFile(file, []byte("x"), 0o755)
	os.Symlink("bash", link)
	stat := func(p string) os.FileInfo { info, _ := os.Lstat(p); return info }

	for _, tc := range []struct {
		name string
		path string
		exp  pacman.Entry
		want bool
	}{
		{"file still a file", file, pacman.Entry{Type: "file"}, false},
		{"file became a link", link, pacman.Entry{Type: "file"}, true},
		{"link unchanged", link, pacman.Entry{Type: "link", Link: "bash"}, false},
		{"link retargeted", link, pacman.Entry{Type: "link", Link: "zsh"}, true},
		{"link became a file", file, pacman.Entry{Type: "link", Link: "bash"}, true},
	} {
		if _, got := linkSwapped(tc.path, stat(tc.path), tc.exp); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSecurityConfig(t *testing.T) {
	for p, want := range map[string]bool{
		"/etc/pam.d/system-auth": true, "/etc/sudoers": true, "/etc/sudoers.d/x": true,
		"/etc/ssh/sshd_config": true, "/etc/ld.so.conf.d/evil.conf": true,
		"/etc/hostname": false, "/etc/ssh/ssh_config": false,
	} {
		if got := securityConfig(p); got != want {
			t.Errorf("%s: got %v, want %v", p, got, want)
		}
	}
}

func TestKernelModulePath(t *testing.T) {
	for p, want := range map[string]bool{
		"/usr/lib/modules/6.9.1-arch1/extra/rootkit.ko":           true,
		"/usr/lib/modules/6.9.1-arch1/updates/dkms/nvidia.ko.zst": true,
		"/usr/lib/modules/6.9.1-arch1/modules.dep":                false,
		"/usr/lib/firmware/x.ko":                                  false,
	} {
		if got := kernelModule.MatchString(p); got != want {
			t.Errorf("%s: got %v, want %v", p, got, want)
		}
	}
}
