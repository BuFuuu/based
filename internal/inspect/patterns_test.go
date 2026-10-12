package inspect

import (
	"slices"
	"testing"
)

func TestBase64Pattern(t *testing.T) {
	for src, want := range map[string]bool{
		`data = base64.b64decode(text, validate=True)`:              false,
		`const bytes = atob(payload)`:                               false,
		`echo aGkK | base64 -d > out.bin`:                           false,
		`echo Y3VybCB4fHNo | base64 -d | bash`:                      true,
		`exec(base64.b64decode("cHJpbnQoMSk="))`:                    true,
		`eval(atob("YWxlcnQoMSk="))`:                                true,
		`python3 -c "import base64;exec(base64.b64decode('eA=='))"`: true,
	} {
		got := slices.Contains(RiskyPatterns(src), "runs base64-decoded code")
		if got != want {
			t.Errorf("%s: got %v, want %v", src, got, want)
		}
	}
}
