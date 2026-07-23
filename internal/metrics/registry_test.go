package metrics

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// render is the assertion surface for most of these tests: everything this
// package promises is a property of the bytes a scrape returns.
func render(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return b.String()
}

// samples parses an exposition body into series line to value.
func samples(t *testing.T, body string) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			t.Fatalf("sample line has no value: %q", line)
		}
		out[line[:i]] = line[i+1:]
	}
	return out
}

func TestExpositionIsByteIdenticalRegardlessOfInsertionOrder(t *testing.T) {
	build := func(order []string) string {
		r := NewRegistry()
		reqs := NewCounterVec("zeta_requests_total", "Requests.", "endpoint", "method")
		lat := NewHistogramVec("alpha_seconds", "Latency.", []float64{1, 2}, "endpoint")
		up := NewGauge("mid_gauge", "A gauge.")
		// Registration order differs between the two builds as well, so the
		// test covers family ordering and series ordering at once.
		for _, c := range []Collector{reqs, lat, up} {
			r.MustRegister(c)
		}
		up.Set(42)
		for _, v := range order {
			reqs.WithLabelValues(v, "POST").Inc()
			lat.WithLabelValues(v).Observe(1.5)
		}
		return render(t, r)
	}

	forward := build([]string{"chat", "completion", "embedding"})
	backward := build([]string{"embedding", "chat", "completion"})
	if forward != backward {
		t.Errorf("insertion order changed the exposition:\n--- forward ---\n%s\n--- backward ---\n%s", forward, backward)
	}

	r := NewRegistry()
	c := NewCounterVec("stable_total", "Stable.", "a")
	r.MustRegister(c)
	for _, v := range []string{"x", "y", "z"} {
		c.WithLabelValues(v).Inc()
	}
	if first, second := render(t, r), render(t, r); first != second {
		t.Errorf("two renders of the same state differ:\n%s\n%s", first, second)
	}
}

func TestFamiliesSortByNameAndSeriesByLabelValues(t *testing.T) {
	r := NewRegistry()
	b := NewCounter("b_total", "B.")
	a := NewCounterVec("a_total", "A.", "one", "two")
	r.MustRegister(b)
	r.MustRegister(a)
	b.Inc()
	a.WithLabelValues("z", "1").Inc()
	a.WithLabelValues("a", "2").Inc()
	a.WithLabelValues("a", "1").Inc()

	want := `# HELP a_total A.
# TYPE a_total counter
a_total{one="a",two="1"} 1
a_total{one="a",two="2"} 1
a_total{one="z",two="1"} 1
# HELP b_total B.
# TYPE b_total counter
b_total 1
`
	if got := render(t, r); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestLabelValuesAndHelpAreEscaped(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"backslash", `a\b`, `a\\b`},
		{"double quote", `say "hi"`, `say \"hi\"`},
		{"newline", "line\nbreak", `line\nbreak`},
		{"all three at once", "a\\\"\n", `a\\\"\n`},
		{"carriage return is not special", "a\rb", "a\rb"},
		{"nothing to escape", "chat", "chat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			c := NewCounterVec("escape_total", "Escapes.", "value")
			r.MustRegister(c)
			c.WithLabelValues(tt.value).Inc()

			want := `escape_total{value="` + tt.want + `"} 1`
			if got := render(t, r); !strings.Contains(got, want) {
				t.Errorf("got:\n%s\nwant a line: %s", got, want)
			}
		})
	}

	r := NewRegistry()
	r.MustRegister(NewCounter("help_total", "A help string with a \\ and a\nbreak, but a \" needs no escape."))
	want := `# HELP help_total A help string with a \\ and a\nbreak, but a " needs no escape.` + "\n"
	if got := render(t, r); !strings.Contains(got, want) {
		t.Errorf("got:\n%s\nwant a line: %s", got, want)
	}
}

func TestHistogramBucketsAreCumulative(t *testing.T) {
	bounds := []float64{0.1, 0.5, 1}
	tests := []struct {
		name         string
		observations []float64
		want         []string // le=0.1, le=0.5, le=1, le=+Inf
	}{
		{"empty histogram is all zero", nil, []string{"0", "0", "0", "0"}},
		{"one small observation reaches every bucket above it", []float64{0.05}, []string{"1", "1", "1", "1"}},
		{"an overflow appears only in +Inf", []float64{10}, []string{"0", "0", "0", "1"}},
		{"a boundary value counts in its own bucket, le is inclusive", []float64{0.5}, []string{"0", "1", "1", "1"}},
		{"observations accumulate upwards", []float64{0.05, 0.2, 0.7, 3}, []string{"1", "2", "3", "4"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			h := NewHistogram("dur_seconds", "Duration.", bounds)
			r.MustRegister(h)
			for _, v := range tt.observations {
				h.Observe(v)
			}

			got := samples(t, render(t, r))
			for i, le := range []string{"0.1", "0.5", "1", "+Inf"} {
				key := `dur_seconds_bucket{le="` + le + `"}`
				if got[key] != tt.want[i] {
					t.Errorf("%s = %q, want %q", key, got[key], tt.want[i])
				}
			}
			if got[`dur_seconds_count`] != tt.want[3] {
				t.Errorf("_count = %q, want %q (it must equal the +Inf bucket)", got["dur_seconds_count"], tt.want[3])
			}
		})
	}
}

func TestHistogramBucketsNeverDecreaseAndInfEqualsCount(t *testing.T) {
	r := NewRegistry()
	h := NewHistogramVec("ttfb_seconds", "TTFB.", TTFBBuckets(), "endpoint")
	r.MustRegister(h)

	series := h.WithLabelValues("chat")
	for i := range 500 {
		series.Observe(float64(i) / 1000)
	}

	var previous uint64
	var last string
	for _, line := range strings.Split(render(t, r), "\n") {
		if !strings.HasPrefix(line, "ttfb_seconds_bucket") {
			continue
		}
		value := line[strings.LastIndexByte(line, ' ')+1:]
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			t.Fatalf("bucket value %q: %v", value, err)
		}
		if n < previous {
			t.Errorf("bucket counts decreased at %q: %d after %d", line, n, previous)
		}
		previous, last = n, line
	}
	if !strings.Contains(last, `le="+Inf"`) {
		t.Errorf("last bucket line is %q, want the +Inf bucket last", last)
	}
	if previous != 500 {
		t.Errorf("+Inf bucket = %d, want 500 to equal the observation count", previous)
	}
}

func TestConcurrentWritersAreCountedExactly(t *testing.T) {
	const (
		goroutines = 64
		iterations = 500
	)

	r := NewRegistry()
	counter := NewCounterVec("hammer_total", "Hammered.", "worker_class")
	hist := NewHistogramVec("hammer_seconds", "Hammered.", []float64{0.5, 1}, "worker_class")
	r.MustRegister(counter)
	r.MustRegister(hist)

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Two label values so that series creation races too, not just
			// increments on an already-created series.
			class := strconv.Itoa(g % 2)
			for range iterations {
				counter.WithLabelValues(class).Inc()
				hist.WithLabelValues(class).Observe(0.25)
			}
		}()
	}
	// Scraping while writers run is the normal case, and it must not race.
	for range 20 {
		render(t, r)
	}
	wg.Wait()

	got := samples(t, render(t, r))
	const perClass = goroutines / 2 * iterations
	for _, class := range []string{"0", "1"} {
		if want := strconv.Itoa(perClass); got[`hammer_total{worker_class="`+class+`"}`] != want {
			t.Errorf("counter for class %s = %q, want %s", class, got[`hammer_total{worker_class="`+class+`"}`], want)
		}
		if want := strconv.Itoa(perClass); got[`hammer_seconds_count{worker_class="`+class+`"}`] != want {
			t.Errorf("histogram count for class %s = %q, want %s", class, got[`hammer_seconds_count{worker_class="`+class+`"}`], want)
		}
		inf := got[`hammer_seconds_bucket{worker_class="`+class+`",le="+Inf"}`]
		if inf != got[`hammer_seconds_count{worker_class="`+class+`"}`] {
			t.Errorf("+Inf bucket %q disagrees with _count %q for class %s", inf, got[`hammer_seconds_count{worker_class="`+class+`"}`], class)
		}
		if want := strconv.FormatFloat(0.25*perClass, 'g', -1, 64); got[`hammer_seconds_sum{worker_class="`+class+`"}`] != want {
			t.Errorf("histogram sum for class %s = %q, want %s", class, got[`hammer_seconds_sum{worker_class="`+class+`"}`], want)
		}
	}
}

func TestFamilyWithNoSeriesStillEmitsHelpAndType(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(NewCounterVec("quiet_total", "Nothing happened yet.", "endpoint"))

	want := "# HELP quiet_total Nothing happened yet.\n# TYPE quiet_total counter\n"
	if got := render(t, r); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRegisterRejectsUnusableFamilies(t *testing.T) {
	tests := []struct {
		name      string
		collector Collector
		wantErr   string
	}{
		{"digit first in name", NewCounter("1_total", "H."), "not a valid metric name"},
		{"dash in name", NewCounter("a-b", "H."), "not a valid metric name"},
		{"empty name", NewCounter("", "H."), "has no name"},
		{"series without a family", NewCounterVec("v_total", "H.", "a").WithLabelValues("x"), "has no name"},
		{"invalid label name", NewCounterVec("ok_total", "H.", "a-b"), "not a valid label name"},
		{"reserved label prefix", NewCounterVec("ok_total", "H.", "__name"), "not a valid label name"},
		{"duplicate label", NewCounterVec("ok_total", "H.", "a", "a"), "declared twice"},
		{"histogram claiming le", NewHistogramVec("ok_seconds", "H.", []float64{1}, "le"), "cannot declare a label named le"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewRegistry().Register(tt.collector)
			if err == nil {
				t.Fatalf("Register accepted %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestRegisterRejectsADuplicateName(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(NewCounter("dup_total", "First."))
	if err := r.Register(NewCounter("dup_total", "Second.")); err == nil {
		t.Fatal("Register accepted a second family with the same name")
	}
}

func TestMustRegisterPanicsOnAFamilyRegisterRejects(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustRegister accepted a family Register rejects")
		}
	}()
	NewRegistry().MustRegister(NewCounter("1_bad_name", "Starts with a digit."))
}

func TestGaugeAddMovesInBothDirectionsUnderConcurrency(t *testing.T) {
	g := NewGauge("g", "G.")
	g.Set(10)
	g.Add(-2.5)
	if got := g.Value(); got != 7.5 {
		t.Errorf("Value = %v, want 7.5 (Add must accept a negative delta)", got)
	}

	// Add is a compare-and-swap loop, so a lost update only shows up when
	// several goroutines contend for the same word.
	g.Set(0)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				g.Add(0.5)
			}
		}()
	}
	wg.Wait()
	if got, want := g.Value(), 32*500*0.5; got != want {
		t.Errorf("Value = %v, want %v (an update was lost)", got, want)
	}
}

func TestLabelValueCountMismatchPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("WithLabelValues accepted the wrong number of values")
		}
		if !strings.Contains(r.(string), "takes 2 label values") {
			t.Errorf("panic message %q does not say how many values are expected", r)
		}
	}()
	NewCounterVec("mismatch_total", "H.", "a", "b").WithLabelValues("only-one")
}

func TestNonFiniteAndNaNValuesUseExpositionSpellings(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		want  string
	}{
		{"positive infinity", math.Inf(1), "+Inf"},
		{"negative infinity", math.Inf(-1), "-Inf"},
		{"not a number", math.NaN(), "NaN"},
		{"an integral value keeps no decimal point", 42, "42"},
		{"a large integral value does not go exponential", 67108864, "67108864"},
		{"a fraction round-trips", 0.0005, "0.0005"},
		{"a large fraction keeps its shortest round-trip form", 1.5e21, "1.5e+21"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			g := NewGauge("value_gauge", "A value.")
			r.MustRegister(g)
			g.Set(tt.value)

			if want := "value_gauge " + tt.want + "\n"; !strings.Contains(render(t, r), want) {
				t.Errorf("got %q, want it to contain %q", render(t, r), want)
			}
		})
	}
}

func TestNaNObservationIsDiscardedRatherThanPoisoningTheSum(t *testing.T) {
	h := NewHistogram("nan_seconds", "H.", []float64{1})
	h.Observe(1)
	h.Observe(math.NaN())

	if h.Count() != 1 {
		t.Errorf("Count = %d, want 1", h.Count())
	}
	if h.Sum() != 1 {
		t.Errorf("Sum = %v, want 1", h.Sum())
	}
}

func TestSeriesWithSeparatorLikeLabelValuesStayDistinct(t *testing.T) {
	// A naive key built by joining values would merge these two series.
	r := NewRegistry()
	c := NewCounterVec("key_total", "H.", "a", "b")
	r.MustRegister(c)
	c.WithLabelValues("x:y", "z").Add(1)
	c.WithLabelValues("x", "y:z").Add(2)

	got := samples(t, render(t, r))
	if got[`key_total{a="x:y",b="z"}`] != "1" || got[`key_total{a="x",b="y:z"}`] != "2" {
		t.Errorf("series were merged: %v", got)
	}
}

func TestHandlerSendsTheVersionedContentType(t *testing.T) {
	r := NewRegistry()
	c := NewCounter("served_total", "Served.")
	r.MustRegister(c)
	c.Inc()

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if got := rec.Header().Get("Content-Type"); got != ContentType {
		t.Errorf("Content-Type = %q, want %q", got, ContentType)
	}
	if !strings.Contains(rec.Body.String(), "served_total 1\n") {
		t.Errorf("body does not contain the sample:\n%s", rec.Body.String())
	}
	if got, want := rec.Header().Get("Content-Length"), strconv.Itoa(rec.Body.Len()); got != want {
		t.Errorf("Content-Length = %q, want %q", got, want)
	}
}

func TestBadBucketBoundsPanicAtConstruction(t *testing.T) {
	tests := []struct {
		name   string
		bounds []float64
	}{
		{"no buckets", nil},
		{"descending", []float64{1, 0.5}},
		{"duplicated boundary", []float64{1, 1}},
		{"an explicit +Inf boundary", []float64{1, math.Inf(1)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("NewHistogram accepted bounds %v", tt.bounds)
				}
			}()
			NewHistogram("bad_seconds", "H.", tt.bounds)
		})
	}
}
