// Package model defines the data every collector produces and every view consumes.
package model

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Severity is derived from the summed weight of a finding's flags.
type Severity int

const (
	Info Severity = iota
	Low
	Med
	High
)

var severityNames = [...]string{"info", "low", "med", "high"}

// The words people read. Based is not an antivirus: the level says how far
// an item is from a default install, not how dangerous it is.
var severityLabels = [...]string{"normal", "a bit unusual", "unusual", "very unusual"}

func (s Severity) String() string { return severityNames[s] }

// Label is the level in plain words, e.g. "very unusual".
func (s Severity) Label() string { return severityLabels[s] }

// ParseSeverity accepts the short names (high, med, low, info) and the
// words (very-unusual, unusual, a-bit-unusual, normal).
func ParseSeverity(v string) (Severity, bool) {
	v = strings.ToLower(strings.NewReplacer("-", " ", "_", " ").Replace(v))
	for i, n := range severityNames {
		if n == v || severityLabels[i] == v {
			return Severity(i), true
		}
	}
	switch v {
	case "medium":
		return Med, true
	case "very":
		return High, true
	case "bit", "a bit":
		return Low, true
	}
	return Info, false
}

// SeverityFor maps a score onto a severity band.
func SeverityFor(score int) Severity {
	switch {
	case score >= 70:
		return High
	case score >= 40:
		return Med
	case score >= 15:
		return Low
	}
	return Info
}

// Kind groups findings by what they describe. New collectors add new kinds
// (e.g. "persistence", "network") without touching the views.
type Kind string

const (
	KindFile    Kind = "file"
	KindTree    Kind = "tree" // a whole unowned directory, summarised
	KindConfig  Kind = "config"
	KindPackage Kind = "package"
	KindPersist Kind = "persistence" // something that starts automatically
	KindNetwork Kind = "network"     // a program with open sockets
)

// Flag is one reason an item is interesting. Weight feeds the score.
type Flag struct {
	Code   string `json:"code"`
	Label  string `json:"label"`
	Weight int    `json:"weight"`
}

// Finding is a single non-default item on the system.
type Finding struct {
	ID          string            `json:"id"`
	Kind        Kind              `json:"kind"`
	Collector   string            `json:"collector"`
	Subject     string            `json:"subject"` // path or package name
	Title       string            `json:"title"`
	Flags       []Flag            `json:"flags"`
	Score       int               `json:"score"`
	Severity    Severity          `json:"severity"`
	Trust       Trust             `json:"trust"`
	Added       time.Time         `json:"added"`
	AddedSource string            `json:"added_source"` // btime, ctime, installdate, ...
	FirstSeen   time.Time         `json:"first_seen"`
	Fingerprint string            `json:"fingerprint"` // changes when the item changes; voids an accept
	Facts       map[string]string `json:"facts,omitempty"`
	Preview     string            `json:"preview,omitempty"`
}

// MakeID returns a short id that stays stable across scans for the same subject.
func MakeID(kind Kind, subject string) string {
	h := sha1.Sum([]byte(string(kind) + "\x00" + subject))
	return hex.EncodeToString(h[:])[:7]
}

// Finalize fills in id, score and severity from the flags.
func (f *Finding) Finalize() {
	if f.ID == "" {
		f.ID = MakeID(f.Kind, f.Subject)
	}
	sort.SliceStable(f.Flags, func(i, j int) bool { return f.Flags[i].Weight > f.Flags[j].Weight })
	f.Score = 0
	for _, fl := range f.Flags {
		f.Score += fl.Weight
	}
	f.Score = max(0, min(f.Score, 100))
	f.Severity = SeverityFor(f.Score)
}

func (f *Finding) AddFlag(fl Flag) {
	for _, have := range f.Flags {
		if have.Code == fl.Code {
			return
		}
	}
	f.Flags = append(f.Flags, fl)
}

func (f *Finding) SetFact(k, v string) {
	if v == "" {
		return
	}
	if f.Facts == nil {
		f.Facts = map[string]string{}
	}
	f.Facts[k] = v
}
