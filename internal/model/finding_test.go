package model

import "testing"

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{
		"high": High, "very-unusual": High, "very unusual": High, "very": High,
		"med": Med, "medium": Med, "unusual": Med,
		"low": Low, "a-bit-unusual": Low, "a_bit_unusual": Low, "bit": Low,
		"info": Info, "normal": Info, "Normal": Info,
	} {
		if got, ok := ParseSeverity(in); !ok || got != want {
			t.Errorf("%q: got %v (%v), want %v", in, got, ok, want)
		}
	}
	if _, ok := ParseSeverity("risky"); ok {
		t.Error("unknown words should be rejected")
	}
}
