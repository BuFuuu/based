package inspect

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileOnlySharesWhatTheUserCouldRead(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	public := filepath.Join(dir, "public")
	os.WriteFile(secret, []byte("root only"), 0o600)
	os.WriteFile(public, []byte("anyone"), 0o644)
	link := filepath.Join(dir, ".bashrc")
	os.Symlink(secret, link) // planted in the user's home, pointing at a root-only file

	// pretend the files belong to root and the scan reports to someone else
	LimitContentTo(os.Getuid()+12345, nil)
	defer func() { revealUID = -1 }()

	if _, err := ReadFile(secret, 1<<20); !errors.Is(err, ErrNotYours) {
		t.Errorf("secret: err %v, want ErrNotYours", err)
	}
	if _, err := ReadFile(link, 1<<20); !errors.Is(err, ErrNotYours) {
		t.Errorf("a link to the secret must not reveal it: err %v", err)
	}
	if b, err := ReadFile(public, 1<<20); err != nil || string(b) != "anyone" {
		t.Errorf("public: %q %v", b, err)
	}
	if r := Inspect(link, 9); r.Preview != "" || r.Header != nil {
		t.Errorf("Inspect leaked contents: preview %q", r.Preview)
	}

	// the file's owner may see it
	LimitContentTo(os.Getuid(), nil)
	if b, err := ReadFile(secret, 1<<20); err != nil || string(b) != "root only" {
		t.Errorf("owner: %q %v", b, err)
	}
}
