package metrics

import (
	"math"
	"strings"
	"testing"
)

// A single +Inf observation would set _sum to +Inf for the lifetime of the
// process, and every rate() over the histogram with it. The typed API never
// produces one, but the histogram is the last line of defence and has to hold
// on its own.
func TestNonFiniteObservationsAreDiscarded(t *testing.T) {
	reg := NewRegistry()
	h := NewHistogram("finite_test_seconds", "test", []float64{1, 10})
	reg.MustRegister(h)

	h.Observe(0.5)
	h.Observe(math.Inf(1))
	h.Observe(math.Inf(-1))
	h.Observe(math.NaN())
	h.Observe(2)

	var b strings.Builder
	if _, err := reg.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	if !strings.Contains(out, "finite_test_seconds_count 2") {
		t.Errorf("count should reflect only the finite observations:\n%s", out)
	}
	if strings.Contains(out, "Inf") && !strings.Contains(out, `le="+Inf"`) {
		t.Errorf("a non-finite value reached the exposition:\n%s", out)
	}
	if !strings.Contains(out, "finite_test_seconds_sum 2.5") {
		t.Errorf("sum should be 2.5:\n%s", out)
	}
}
