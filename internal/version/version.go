// Package version carries build identity. Values are set at link time by the
// release build; a plain `go build` reports a development version.
package version

import "runtime/debug"

var (
	// Version is the release tag, injected with -ldflags at build time.
	Version = "dev"
	// Commit is the source revision, injected at build time or read from the
	// embedded build info.
	Commit = ""
	// Date is the build timestamp, injected at build time.
	Date = ""
)

func init() {
	if Commit != "" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			Commit = s.Value
		case "vcs.time":
			if Date == "" {
				Date = s.Value
			}
		}
	}
}

// String renders a short human-readable build identity.
func String() string {
	s := Version
	if Commit != "" {
		if len(Commit) > 12 {
			s += " (" + Commit[:12] + ")"
		} else {
			s += " (" + Commit + ")"
		}
	}
	return s
}
