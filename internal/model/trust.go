package model

// Trust says where an item comes from. It decides how carefully a file is
// checked and is shown next to every finding.
type Trust int

const (
	TrustUnknown Trust = iota // no package owns it: user files, downloads, build output
	TrustForeign              // AUR, manual build or third-party repo
	TrustArch                 // official Arch repo package you installed
	TrustOmarchy              // part of the Omarchy install
)

var trustInfo = [...]struct{ Name, Label, Why, Check string }{
	TrustUnknown: {"unknown", "Unknown", "no package owns it, so nothing records what it should look like",
		"contents inspected, runnable files hashed"},
	TrustForeign: {"foreign", "AUR/3rd party", "not built or reviewed by Arch: an AUR recipe or a third-party repo",
		"every file hashed against its package"},
	TrustArch: {"arch", "Arch repos", "built and signed by Arch packagers, chosen by you",
		"size, times and permissions vs its package"},
	TrustOmarchy: {"omarchy", "Omarchy", "installed on every Omarchy system, signed by Arch or Omarchy",
		"size, times and permissions vs its package"},
}

func (t Trust) Name() string  { return trustInfo[t].Name }
func (t Trust) Label() string { return trustInfo[t].Label }
func (t Trust) Why() string   { return trustInfo[t].Why }
func (t Trust) Check() string { return trustInfo[t].Check }

// AllTrust lists levels from most to least trusted.
var AllTrust = []Trust{TrustOmarchy, TrustArch, TrustForeign, TrustUnknown}
