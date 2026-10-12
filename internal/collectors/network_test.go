package collectors

import "testing"

func TestParseHexAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:0035":                         "127.0.0.1:53",
		"00000000:1F90":                         "0.0.0.0:8080",
		"00000000000000000000000001000000:0277": "[::1]:631",
		"0000000000000000FFFF00000100007F:01BB": "127.0.0.1:443", // v4-mapped
	} {
		got, ok := parseHexAddr(in)
		if !ok || got.String() != want {
			t.Errorf("%s: got %v (%v), want %s", in, got, ok, want)
		}
	}
}

func TestInteractiveShell(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"/bin/sh"}, true},
		{[]string{"bash", "-i"}, true},
		{[]string{"-bash"}, true},
		{[]string{"bash", "-l"}, true},
		{[]string{"/usr/bin/bash", "-c", "ls"}, false},
		{[]string{"bash", "-lc", "make"}, false},
		{[]string{"sh", "./build.sh"}, false},
		{[]string{"python3", "-i"}, false},
	} {
		if got := interactiveShellArgs(tc.args); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.args, got, tc.want)
		}
	}
}
