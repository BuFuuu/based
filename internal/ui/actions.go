package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
)

// clipboard is swapped out in tests.
var clipboard = copyText

// copyText puts s on the Wayland clipboard.
func copyText(s string) error {
	c := exec.Command("wl-copy")
	c.Stdin = strings.NewReader(s)
	if err := c.Run(); err != nil {
		return fmt.Errorf("wl-copy failed: %w", err)
	}
	return nil
}

// openFolder shows the item in the file manager: the file selected inside
// its folder, or a directory opened directly.
func openFolder(f model.Finding) (string, error) {
	target := strings.TrimSuffix(f.Subject, "/")
	if f.Kind == model.KindPackage {
		pkgbuild := f.Facts["PKGBUILD"]
		if pkgbuild == "" {
			return "", fmt.Errorf("packages have no folder (no cached PKGBUILD)")
		}
		target = pkgbuild
	}
	info, err := os.Lstat(target)
	if err != nil {
		return "", fmt.Errorf("%s is gone", target)
	}
	launch := func(args ...string) error {
		if _, err := exec.LookPath("uwsm-app"); err == nil {
			args = append([]string{"uwsm-app", "--"}, args...)
		}
		c := exec.Command("setsid", args...)
		return c.Start()
	}
	if _, err := exec.LookPath("nautilus"); err == nil {
		if info.IsDir() {
			return target, launch("nautilus", target)
		}
		return filepath.Dir(target), launch("nautilus", "--select", target)
	}
	dir := target
	if !info.IsDir() {
		dir = filepath.Dir(target)
	}
	return dir, launch("xdg-open", dir)
}

// itemHash returns the stored sha256, or computes it now.
func itemHash(f model.Finding) (string, error) {
	if h := f.Facts["sha256"]; h != "" {
		return h, nil
	}
	if f.Kind != model.KindFile && f.Kind != model.KindConfig {
		return "", fmt.Errorf("only files have a hash")
	}
	h, err := inspect.SHA256(f.Subject)
	if err != nil {
		return "", fmt.Errorf("cannot read %s (try a --sudo scan)", f.Subject)
	}
	return h, nil
}
