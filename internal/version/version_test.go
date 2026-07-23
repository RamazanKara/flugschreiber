package version

import (
	"strings"
	"testing"
)

func TestStringCarriesVersionAndShortCommit(t *testing.T) {
	origV, origC := Version, Commit
	t.Cleanup(func() { Version, Commit = origV, origC })

	Version, Commit = "v1.2.3", "0123456789abcdef0123"
	got := String()
	if !strings.HasPrefix(got, "v1.2.3") {
		t.Errorf("String() = %q, want the version first", got)
	}
	if !strings.Contains(got, "0123456789ab") || strings.Contains(got, "cdef0123") {
		t.Errorf("String() = %q, want the commit truncated to 12 characters", got)
	}

	Version, Commit = "dev", ""
	if got := String(); got != "dev" {
		t.Errorf("String() with no commit = %q, want %q", got, "dev")
	}
}
