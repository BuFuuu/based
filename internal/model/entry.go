package model

// Entry is one place where something starts automatically: an enabled
// service, a cron job, an autostart file, a hook, a line in a shell rc. Every
// entry is listed in the persistence view; the non-default ones also become
// findings so they appear in the timeline and can be accepted.
type Entry struct {
	Mechanism string `json:"mechanism"` // e.g. "systemd (system)", "cron", "shell startup"
	Name      string `json:"name"`
	Path      string `json:"path"`
	Runs      string `json:"runs,omitempty"` // what it executes, when known
	State     string `json:"state"`          // "default", "flagged" or "unreadable"
	Why       string `json:"why"`            // why it is default, or what is unusual
	FindingID string `json:"finding_id,omitempty"`
}
