package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// ContentType is the media type of the exposition format this package renders.
// Prometheus selects its parser from the version parameter, so it is always
// sent rather than left as bare text/plain.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Metric type names as they appear on a # TYPE line.
const (
	typeCounter   = "counter"
	typeGauge     = "gauge"
	typeHistogram = "histogram"
)

// Desc identifies one metric family.
type Desc struct {
	// Name is the family name, without the _bucket, _sum or _count suffix a
	// histogram adds.
	Name string
	// Help is the one-line description rendered on the # HELP line.
	Help string
	// Type is the exposition type: counter, gauge or histogram.
	Type string
	// Labels are the family's label names, in the order WithLabelValues
	// expects their values.
	Labels []string
}

// Collector is a metric family that can render itself in the text exposition
// format. The interface is closed on purpose: exposition is only correct if
// every family agrees on escaping and on series ordering, and a registry that
// accepted foreign implementations could not promise either.
type Collector interface {
	desc() Desc
	appendSeries(dst []byte) []byte
}

// Registry owns a set of metric families and renders them.
//
// Rendering is deterministic. Families are sorted by name and the series
// within a family by their label values, so two scrapes of the same state
// produce byte-identical output. Unstable output cannot be diffed by an
// operator or asserted on by a test, which is how hand-rolled exporters end up
// unverified.
type Registry struct {
	mu         sync.Mutex
	collectors map[string]Collector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{collectors: make(map[string]Collector)}
}

// Register adds a family. It reports an error rather than panicking so that a
// caller assembling metrics from configuration can surface the problem.
func (r *Registry) Register(c Collector) error {
	d := c.desc()
	if d.Name == "" {
		return fmt.Errorf("metrics: register: metric has no name (a series returned by WithLabelValues cannot be registered on its own)")
	}
	if !validMetricName(d.Name) {
		return fmt.Errorf("metrics: register: %q is not a valid metric name (letters, digits, underscore and colon, not starting with a digit)", d.Name)
	}
	for i, l := range d.Labels {
		if !validLabelName(l) {
			return fmt.Errorf("metrics: register %s: %q is not a valid label name (letters, digits and underscore, not starting with a digit or __)", d.Name, l)
		}
		if slices.Contains(d.Labels[:i], l) {
			return fmt.Errorf("metrics: register %s: label %q is declared twice", d.Name, l)
		}
		if d.Type == typeHistogram && l == "le" {
			return fmt.Errorf("metrics: register %s: a histogram cannot declare a label named le, the bucket boundary uses it", d.Name)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.collectors[d.Name]; ok {
		return fmt.Errorf("metrics: register: %s is already registered", d.Name)
	}
	r.collectors[d.Name] = c
	return nil
}

// MustRegister registers c and panics if that fails. Registration happens once
// at start-up from constant descriptions, so a failure there is a bug in this
// binary and not a runtime condition worth propagating.
func (r *Registry) MustRegister(c Collector) {
	if err := r.Register(c); err != nil {
		panic(err.Error())
	}
}

// WriteTo renders the registry in the text exposition format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(r.render())
	return int64(n), err
}

// Handler serves the registry over HTTP.
//
// Expose it on a listener of its own rather than on the proxy's port. The
// metrics of an OpenAI-compatible upstream also live at /metrics, and shadowing
// the upstream's own endpoint from a transparent proxy would be a surprising
// thing for this tool to do.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body := r.render()
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if req.Method != http.MethodHead {
			w.Write(body)
		}
	})
}

func (r *Registry) render() []byte {
	r.mu.Lock()
	cs := make([]Collector, 0, len(r.collectors))
	for _, c := range r.collectors {
		cs = append(cs, c)
	}
	r.mu.Unlock()

	slices.SortFunc(cs, func(a, b Collector) int {
		return strings.Compare(a.desc().Name, b.desc().Name)
	})

	buf := make([]byte, 0, 4096)
	for _, c := range cs {
		d := c.desc()
		// A family with no observations yet still emits its HELP and TYPE
		// lines. The shape of a scrape then does not depend on whether traffic
		// has arrived, which is what lets a dashboard be built before it has.
		buf = append(buf, "# HELP "...)
		buf = append(buf, d.Name...)
		buf = append(buf, ' ')
		buf = appendEscapedHelp(buf, d.Help)
		buf = append(buf, '\n', '#', ' ', 'T', 'Y', 'P', 'E', ' ')
		buf = append(buf, d.Name...)
		buf = append(buf, ' ')
		buf = append(buf, d.Type...)
		buf = append(buf, '\n')
		buf = c.appendSeries(buf)
	}
	return buf
}

// Counter is a monotonically increasing count.
//
// It counts in whole units because everything Flugschreiber counts is whole:
// requests, tokens, records, uploads. An integer counter renders exactly at
// any magnitude, where a float64 counter silently stops incrementing past
// 2^53.
type Counter struct {
	d Desc
	n atomic.Uint64
}

// NewCounter returns an unlabelled counter family.
func NewCounter(name, help string) *Counter {
	return &Counter{d: Desc{Name: name, Help: help, Type: typeCounter}}
}

// Inc adds one.
func (c *Counter) Inc() { c.n.Add(1) }

// Add adds n.
func (c *Counter) Add(n uint64) { c.n.Add(n) }

// Value returns the current count.
func (c *Counter) Value() uint64 { return c.n.Load() }

func (c *Counter) desc() Desc { return c.d }

func (c *Counter) appendSeries(dst []byte) []byte {
	dst = append(dst, c.d.Name...)
	dst = append(dst, ' ')
	dst = strconv.AppendUint(dst, c.n.Load(), 10)
	return append(dst, '\n')
}

// Gauge is a value that can go up and down.
type Gauge struct {
	d    Desc
	bits atomic.Uint64
}

// NewGauge returns an unlabelled gauge family.
func NewGauge(name, help string) *Gauge {
	return &Gauge{d: Desc{Name: name, Help: help, Type: typeGauge}}
}

// Set replaces the value.
func (g *Gauge) Set(v float64) { g.bits.Store(math.Float64bits(v)) }

// Add adds v, which may be negative.
func (g *Gauge) Add(v float64) {
	for {
		old := g.bits.Load()
		next := math.Float64bits(math.Float64frombits(old) + v)
		if g.bits.CompareAndSwap(old, next) {
			return
		}
	}
}

// Value returns the current value.
func (g *Gauge) Value() float64 { return math.Float64frombits(g.bits.Load()) }

func (g *Gauge) desc() Desc { return g.d }

func (g *Gauge) appendSeries(dst []byte) []byte {
	dst = append(dst, g.d.Name...)
	dst = append(dst, ' ')
	dst = appendFloat(dst, g.Value())
	return append(dst, '\n')
}

// Histogram counts observations into cumulative buckets and tracks their sum.
//
// Observation and snapshot both take a mutex. The lock-free alternative can
// report a +Inf bucket that disagrees with _count, because the two atomics are
// read at different instants, and a histogram whose buckets do not sum to its
// count is one a quantile estimator reads as corrupt. One uncontended mutex
// per observation is not measurable next to a model inference.
type Histogram struct {
	d           Desc
	bounds      []float64
	boundLabels []string

	mu     sync.Mutex
	counts []uint64
	sum    float64
	count  uint64
}

// NewHistogram returns an unlabelled histogram family. Bounds are the
// inclusive upper edges of the buckets, ascending; the implicit +Inf bucket is
// added by the renderer.
func NewHistogram(name, help string, bounds []float64) *Histogram {
	h := newHistogram(checkBounds(name, bounds))
	h.d = Desc{Name: name, Help: help, Type: typeHistogram}
	return h
}

func newHistogram(bounds []float64, boundLabels []string) *Histogram {
	return &Histogram{
		bounds:      bounds,
		boundLabels: boundLabels,
		counts:      make([]uint64, len(bounds)+1),
	}
}

// Observe records one value. A NaN is discarded: it belongs in no bucket and
// would poison _sum for the lifetime of the process.
func (h *Histogram) Observe(v float64) {
	if math.IsNaN(v) {
		return
	}
	i, _ := slices.BinarySearch(h.bounds, v)

	h.mu.Lock()
	h.counts[i]++
	h.count++
	h.sum += v
	h.mu.Unlock()
}

// Count returns the number of observations.
func (h *Histogram) Count() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// Sum returns the sum of all observations.
func (h *Histogram) Sum() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sum
}

func (h *Histogram) desc() Desc { return h.d }

func (h *Histogram) appendSeries(dst []byte) []byte {
	return h.appendPoint(dst, h.d.Name, nil, nil)
}

// appendPoint renders one histogram series. Buckets are cumulative: the value
// of the bucket labelled le="b" is the number of observations less than or
// equal to b, so it includes every bucket below it and the +Inf bucket is
// necessarily equal to _count.
func (h *Histogram) appendPoint(dst []byte, name string, labelNames, labelValues []string) []byte {
	h.mu.Lock()
	counts := slices.Clone(h.counts)
	sum, count := h.sum, h.count
	h.mu.Unlock()

	var cumulative uint64
	for i, label := range h.boundLabels {
		cumulative += counts[i]
		dst = append(dst, name...)
		dst = append(dst, "_bucket"...)
		dst = appendLabels(dst, labelNames, labelValues, "le", label)
		dst = append(dst, ' ')
		dst = strconv.AppendUint(dst, cumulative, 10)
		dst = append(dst, '\n')
	}
	dst = append(dst, name...)
	dst = append(dst, "_bucket"...)
	dst = appendLabels(dst, labelNames, labelValues, "le", "+Inf")
	dst = append(dst, ' ')
	dst = strconv.AppendUint(dst, count, 10)
	dst = append(dst, '\n')

	dst = append(dst, name...)
	dst = append(dst, "_sum"...)
	dst = appendLabels(dst, labelNames, labelValues, "", "")
	dst = append(dst, ' ')
	dst = appendFloat(dst, sum)
	dst = append(dst, '\n')

	dst = append(dst, name...)
	dst = append(dst, "_count"...)
	dst = appendLabels(dst, labelNames, labelValues, "", "")
	dst = append(dst, ' ')
	dst = strconv.AppendUint(dst, count, 10)
	return append(dst, '\n')
}

// vec is the shared machinery of a labelled family: a set of series keyed by
// their label values, created on first use.
type vec[T any] struct {
	d     Desc
	newFn func() *T

	mu     sync.RWMutex
	series map[string]*point[T]
}

type point[T any] struct {
	values []string
	metric *T
}

func (v *vec[T]) init(d Desc, newFn func() *T) {
	v.d = d
	v.newFn = newFn
	v.series = make(map[string]*point[T])
}

func (v *vec[T]) desc() Desc { return v.d }

func (v *vec[T]) with(values []string) *T {
	if len(values) != len(v.d.Labels) {
		// A label count mismatch is a wiring bug that cannot be recovered from
		// at runtime and would otherwise produce a silently wrong series.
		panic(fmt.Sprintf("metrics: %s takes %d label values (%s), got %d",
			v.d.Name, len(v.d.Labels), strings.Join(v.d.Labels, ", "), len(values)))
	}
	key := seriesKey(values)

	v.mu.RLock()
	p, ok := v.series[key]
	v.mu.RUnlock()
	if ok {
		return p.metric
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if p, ok := v.series[key]; ok {
		return p.metric
	}
	p = &point[T]{values: slices.Clone(values), metric: v.newFn()}
	v.series[key] = p
	return p.metric
}

// points returns the series ordered by their label values.
func (v *vec[T]) points() []*point[T] {
	v.mu.RLock()
	out := make([]*point[T], 0, len(v.series))
	for _, p := range v.series {
		out = append(out, p)
	}
	v.mu.RUnlock()

	slices.SortFunc(out, func(a, b *point[T]) int { return slices.Compare(a.values, b.values) })
	return out
}

// CounterVec is a counter family with labels.
type CounterVec struct{ vec[Counter] }

// NewCounterVec returns a counter family with the given label names.
func NewCounterVec(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{}
	c.init(Desc{Name: name, Help: help, Type: typeCounter, Labels: labels},
		func() *Counter { return &Counter{} })
	return c
}

// WithLabelValues returns the series for these label values, creating it on
// first use. The number of values must match the family's label names.
func (c *CounterVec) WithLabelValues(values ...string) *Counter { return c.with(values) }

func (c *CounterVec) appendSeries(dst []byte) []byte {
	for _, p := range c.points() {
		dst = append(dst, c.d.Name...)
		dst = appendLabels(dst, c.d.Labels, p.values, "", "")
		dst = append(dst, ' ')
		dst = strconv.AppendUint(dst, p.metric.Value(), 10)
		dst = append(dst, '\n')
	}
	return dst
}

// GaugeVec is a gauge family with labels.
type GaugeVec struct{ vec[Gauge] }

// NewGaugeVec returns a gauge family with the given label names.
func NewGaugeVec(name, help string, labels ...string) *GaugeVec {
	g := &GaugeVec{}
	g.init(Desc{Name: name, Help: help, Type: typeGauge, Labels: labels},
		func() *Gauge { return &Gauge{} })
	return g
}

// WithLabelValues returns the series for these label values, creating it on
// first use.
func (g *GaugeVec) WithLabelValues(values ...string) *Gauge { return g.with(values) }

func (g *GaugeVec) appendSeries(dst []byte) []byte {
	for _, p := range g.points() {
		dst = append(dst, g.d.Name...)
		dst = appendLabels(dst, g.d.Labels, p.values, "", "")
		dst = append(dst, ' ')
		dst = appendFloat(dst, p.metric.Value())
		dst = append(dst, '\n')
	}
	return dst
}

// HistogramVec is a histogram family with labels. Every series shares the same
// bucket boundaries, which is what makes the family aggregatable across labels.
type HistogramVec struct {
	vec[Histogram]
	bounds      []float64
	boundLabels []string
}

// NewHistogramVec returns a histogram family with the given bucket boundaries
// and label names.
func NewHistogramVec(name, help string, bounds []float64, labels ...string) *HistogramVec {
	h := &HistogramVec{}
	h.bounds, h.boundLabels = checkBounds(name, bounds)
	h.init(Desc{Name: name, Help: help, Type: typeHistogram, Labels: labels},
		func() *Histogram { return newHistogram(h.bounds, h.boundLabels) })
	return h
}

// WithLabelValues returns the series for these label values, creating it on
// first use.
func (h *HistogramVec) WithLabelValues(values ...string) *Histogram { return h.with(values) }

func (h *HistogramVec) appendSeries(dst []byte) []byte {
	for _, p := range h.points() {
		dst = p.metric.appendPoint(dst, h.d.Name, h.d.Labels, p.values)
	}
	return dst
}

// checkBounds validates bucket boundaries and pre-renders their le labels.
// Buckets are fixed at construction, so a bad set is a bug that should stop the
// process at start-up rather than produce a histogram nobody can read.
func checkBounds(name string, bounds []float64) ([]float64, []string) {
	if len(bounds) == 0 {
		panic("metrics: " + name + ": a histogram needs at least one bucket boundary")
	}
	out := slices.Clone(bounds)
	labels := make([]string, len(out))
	for i, b := range out {
		if math.IsNaN(b) || math.IsInf(b, 0) {
			panic(fmt.Sprintf("metrics: %s: bucket boundary %d is not finite (+Inf is added by the renderer)", name, i))
		}
		if i > 0 && b <= out[i-1] {
			panic(fmt.Sprintf("metrics: %s: bucket boundaries must ascend, %g follows %g", name, b, out[i-1]))
		}
		labels[i] = string(appendFloat(nil, b))
	}
	return out, labels
}

// seriesKey builds an unambiguous map key from label values. The values are
// length-prefixed rather than joined by a separator, because a label value may
// contain any byte and a separator collision would merge two distinct series.
func seriesKey(values []string) string {
	if len(values) == 0 {
		return ""
	}
	var b strings.Builder
	for _, v := range values {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	return b.String()
}

// appendLabels renders {name="value",...}. tailName, when set, is emitted last
// and carries a histogram's le boundary.
func appendLabels(dst []byte, names, values []string, tailName, tailValue string) []byte {
	if len(names) == 0 && tailName == "" {
		return dst
	}
	dst = append(dst, '{')
	for i, n := range names {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, n...)
		dst = append(dst, '=', '"')
		dst = appendEscapedLabelValue(dst, values[i])
		dst = append(dst, '"')
	}
	if tailName != "" {
		if len(names) > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, tailName...)
		dst = append(dst, '=', '"')
		dst = appendEscapedLabelValue(dst, tailValue)
		dst = append(dst, '"')
	}
	return append(dst, '}')
}

// appendEscapedHelp escapes a HELP string. Only the backslash and the line
// feed are special there; a double quote is not.
func appendEscapedHelp(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

// appendEscapedLabelValue escapes a label value: backslash, double quote and
// line feed, per the text exposition format.
func appendEscapedLabelValue(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			dst = append(dst, '\\', '\\')
		case '"':
			dst = append(dst, '\\', '"')
		case '\n':
			dst = append(dst, '\\', 'n')
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

// appendFloat renders a sample value. The three non-finite values have
// spellings of their own in the exposition format.
//
// A whole number is rendered as a whole number. Go's %g switches to exponent
// notation above a million, which turns an evidence directory of 67108864
// bytes into 6.7108864e+07 and makes two scrapes tedious to compare by eye.
// Both spellings parse identically.
func appendFloat(dst []byte, v float64) []byte {
	switch {
	case math.IsNaN(v):
		return append(dst, "NaN"...)
	case math.IsInf(v, 1):
		return append(dst, "+Inf"...)
	case math.IsInf(v, -1):
		return append(dst, "-Inf"...)
	case v == math.Trunc(v) && math.Abs(v) < 1<<53:
		return strconv.AppendInt(dst, int64(v), 10)
	}
	return strconv.AppendFloat(dst, v, 'g', -1, 64)
}

func validMetricName(s string) bool {
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == ':':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return s != ""
}

func validLabelName(s string) bool {
	// The __ prefix is reserved for labels Prometheus itself attaches.
	if s == "" || strings.HasPrefix(s, "__") {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
