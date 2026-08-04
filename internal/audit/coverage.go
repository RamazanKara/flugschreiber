// Package audit reads an evidence log and answers questions about it: what was
// captured and at what fidelity, and what one session actually looked like.
//
// It is deliberately separate from the documentation generator. That package
// answers "what should this document say"; this one answers "what is in the
// log, and what is missing from it".
package audit

import (
	"fmt"
	"sort"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// DefaultGapThreshold is how long a stretch with no records has to be before it
// is worth reporting. A busy proxy writes constantly, so a quiet hour is a
// signal: either nothing was happening, or the proxy was not running and
// traffic went somewhere else.
const DefaultGapThreshold = time.Hour

// LifecycleEvent is one recorded change to the evidence itself, surfaced for a
// reader rather than counted.
type LifecycleEvent struct {
	Seq       uint64 `json:"seq"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"event_type"`
	Actor     string `json:"actor,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Coverage is what a log says about its own completeness.
type Coverage struct {
	Dir      string `json:"dir"`
	Records  int    `json:"records"`
	First    string `json:"first_record,omitempty"`
	Last     string `json:"last_record,omitempty"`
	Duration string `json:"observed_duration,omitempty"`

	ByEventType []Tally `json:"by_event_type,omitempty"`

	// Lifecycle lists the events that change what the log holds or attests to:
	// erasures, key rotations, repairs, salt boundaries and any other
	// system_event or config_change. They are rare and consequential, and an
	// auditor should see them rather than have them averaged into a type tally.
	Lifecycle     []LifecycleEvent `json:"lifecycle,omitempty"`
	ByContentMode []Tally          `json:"by_content_mode,omitempty"`
	ByEndpoint    []Tally          `json:"by_endpoint,omitempty"`
	ByModel       []Tally          `json:"by_model,omitempty"`
	ByStatusClass []Tally          `json:"by_status_class,omitempty"`

	Inference int `json:"inference_records"`
	Streamed  int `json:"streamed_records"`
	Failed    int `json:"failed_records"`

	// Completeness counts how many inference records carry each piece of
	// metadata. A field that is present on only some records is a gap worth
	// knowing about before an auditor finds it.
	WithUsage     int `json:"inference_with_token_usage"`
	WithSession   int `json:"inference_with_session_id"`
	WithClient    int `json:"inference_with_client_identity"`
	WithModelName int `json:"inference_with_model_name"`

	DistinctSessions int `json:"distinct_sessions"`
	DistinctClients  int `json:"distinct_clients"`

	Gaps         []Gap  `json:"gaps,omitempty"`
	GapThreshold string `json:"gap_threshold,omitempty"`

	ChainVerified bool   `json:"chain_verified"`
	ChainProblems int    `json:"chain_problems"`
	Pruned        bool   `json:"pruned"`
	Checkpoints   int    `json:"checkpoints"`
	HeadHash      string `json:"head_hash,omitempty"`
}

// Tally is one observed value with its share of the total.
type Tally struct {
	Name    string  `json:"name"`
	Count   int     `json:"count"`
	Percent float64 `json:"percent"`
}

// Gap is a stretch of time in which nothing was recorded.
type Gap struct {
	After    string `json:"after"`
	Before   string `json:"before"`
	Duration string `json:"duration"`
	AfterSeq uint64 `json:"after_seq"`
}

// Percent returns part as a percentage of total, rounded to one decimal.
func Percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(int(float64(part)*1000/float64(total)+0.5)) / 10
}

// Analyse walks an evidence directory and reports its coverage.
//
// It reports on what the log contains. It cannot report on traffic that never
// reached the proxy, and callers must not present its output as proof that all
// model traffic was captured. Making the proxy unavoidable is a network
// control, not something this function can observe.
func Analyse(dir string, gapThreshold time.Duration) (*Coverage, error) {
	if gapThreshold <= 0 {
		gapThreshold = DefaultGapThreshold
	}

	c := &Coverage{Dir: dir, GapThreshold: gapThreshold.String()}

	verified, err := evidence.Verify(dir)
	if err != nil {
		return nil, err
	}
	c.ChainVerified = verified.OK()
	c.ChainProblems = len(verified.Problems)
	c.HeadHash = verified.HeadHash

	eventTypes := map[string]int{}
	modes := map[string]int{}
	endpoints := map[string]int{}
	models := map[string]int{}
	statuses := map[string]int{}
	sessions := map[string]struct{}{}
	clients := map[string]struct{}{}

	var prevTime time.Time
	var prevSeq uint64

	err = evidence.Walk(dir, func(e evidence.Entry) error {
		ev := e.Event
		c.Records++
		eventTypes[ev.EventType]++

		if c.First == "" {
			c.First = e.Record.Timestamp
		}
		c.Last = e.Record.Timestamp

		if ts, perr := time.Parse(time.RFC3339Nano, e.Record.Timestamp); perr == nil {
			if !prevTime.IsZero() && ts.Sub(prevTime) >= gapThreshold {
				c.Gaps = append(c.Gaps, Gap{
					After:    prevTime.Format(time.RFC3339),
					Before:   ts.Format(time.RFC3339),
					Duration: ts.Sub(prevTime).Round(time.Second).String(),
					AfterSeq: prevSeq,
				})
			}
			prevTime = ts
		}
		prevSeq = e.Record.Seq

		if ev.SessionID != "" {
			sessions[ev.SessionID] = struct{}{}
		}
		if ev.ClientHash != "" {
			clients[ev.ClientHash] = struct{}{}
		}

		switch ev.EventType {
		case evidence.EventSystemEvent, evidence.EventConfigChange, evidence.EventIncident:
			c.Lifecycle = append(c.Lifecycle, LifecycleEvent{
				Seq:       e.Record.Seq,
				Timestamp: e.Record.Timestamp,
				Type:      ev.EventType,
				Actor:     ev.Actor,
				Severity:  ev.Severity,
				Note:      ev.Note,
			})
		}

		if ev.EventType != evidence.EventInference {
			return nil
		}
		c.Inference++

		if ev.Content != nil && ev.Content.Mode != "" {
			modes[ev.Content.Mode]++
		} else {
			modes["none recorded"]++
		}
		if ev.Endpoint != "" {
			endpoints[ev.Endpoint]++
		}
		if name := servedOrRequested(ev); name != "" {
			models[name]++
			c.WithModelName++
		}
		if ev.Status != 0 {
			statuses[statusClass(ev.Status)]++
		}
		if ev.Stream {
			c.Streamed++
		}
		if ev.Status >= 400 || ev.Error != "" {
			c.Failed++
		}
		if ev.Usage != nil {
			c.WithUsage++
		}
		if ev.SessionID != "" {
			c.WithSession++
		}
		if ev.ClientHash != "" {
			c.WithClient++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	c.DistinctSessions = len(sessions)
	c.DistinctClients = len(clients)

	c.ByEventType = tally(eventTypes, c.Records)
	c.ByContentMode = tally(modes, c.Inference)
	c.ByEndpoint = tally(endpoints, c.Inference)
	c.ByModel = tally(models, c.Inference)
	c.ByStatusClass = tally(statuses, c.Inference)

	if c.First != "" && c.Last != "" {
		first, e1 := time.Parse(time.RFC3339Nano, c.First)
		last, e2 := time.Parse(time.RFC3339Nano, c.Last)
		if e1 == nil && e2 == nil {
			c.Duration = last.Sub(first).Round(time.Second).String()
		}
	}
	return c, nil
}

func servedOrRequested(ev evidence.Event) string {
	if ev.ModelServed != "" {
		return ev.ModelServed
	}
	return ev.ModelRequested
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return fmt.Sprintf("%d", status)
	}
}

// tally orders by descending count then by name, so two runs over the same log
// produce identical output.
func tally(m map[string]int, total int) []Tally {
	out := make([]Tally, 0, len(m))
	for name, count := range m {
		out = append(out, Tally{Name: name, Count: count, Percent: Percent(count, total)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}
