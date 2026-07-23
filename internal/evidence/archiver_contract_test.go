package evidence

import (
	"testing"

	"github.com/flugschreiber/flugschreiber/internal/archive"
)

// The interface exists so that the evidence core does not import an object
// store client, which means nothing in the production build checks that the
// two method sets still line up. This does, from the test binary, where the
// import costs nothing at runtime: if either side drifts, this stops compiling
// instead of failing in an operator's deployment.
var (
	_ Archiver = (*archive.Dir)(nil)
	_ Archiver = (*archive.Client)(nil)
)

func TestArchiveBackendsSatisfyTheArchiverInterface(t *testing.T) {
	dir, err := archive.NewDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var a Archiver = dir
	if a.Name() != "dir" {
		t.Errorf("Name = %q, want %q", a.Name(), "dir")
	}
}
