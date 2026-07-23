package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// Count is one observed value and how often it was seen.
type Count struct {
	Name  string
	Count int
}

// ModelStat aggregates traffic for one requested/served model pair. The pair
// matters: an upstream that quietly serves a different model than the one the
// application asked for is exactly the kind of thing an audit needs to surface.
type ModelStat struct {
	Requested        string
	Served           string
	Requests         int
	Streamed         int
	Errors           int
	PromptTokens     int
	CompletionTokens int
}

// ParamRange records the spread of a numeric generation parameter.
type ParamRange struct {
	Name  string
	Min   float64
	Max   float64
	Count int
}

func (p ParamRange) String() string {
	if p.Min == p.Max {
		return trimFloat(p.Min)
	}
	return trimFloat(p.Min) + " to " + trimFloat(p.Max)
}

// Summary is everything the documentation generator learned from the evidence
// log. Every field here is observed, never assumed.
type Summary struct {
	Dir         string
	GeneratedAt time.Time

	Records   int
	Inference int
	FirstTime string
	LastTime  string

	ChainVerified bool
	ChainProblems []evidence.Problem
	HeadHash      string
	Segments      []string

	// Attestation state, copied from verification so the documentation can say
	// what actually protects the log rather than describing a design.
	Checkpoints         int
	CheckpointsVerified int
	Attested            bool
	KeyID               string
	Pruned              bool
	PrunedThroughSeq    uint64

	// Anchoring state. Timestamps is how many RFC 3161 tokens the directory
	// holds; TimestampedCheckpoints is how many of them were matched to the
	// checkpoint they claim to cover. The two differ when a token is filed
	// against a checkpoint that is not there, which is worth saying out loud
	// rather than rounding to the friendlier number.
	Timestamps             int
	TimestampedCheckpoints int

	// Bytes is the size of the evidence segments on disk, which is what a size
	// cap is measured against.
	Bytes int64

	// Encrypted counts records whose content is sealed, and Erased those whose
	// key an erasure has destroyed. The documentation has to state both: a
	// reader who is not told will read the missing text as content that was
	// never captured.
	Encrypted int
	Erased    int

	// Human oversight, tallied so Article 14 sections can state what was
	// recorded instead of opening with a blank TODO.
	Interventions int
	ByDecision    []Count

	// Incidents, tallied so the Article 73 post-market section can pre-fill
	// what was reported instead of a blank TODO.
	Incidents  int
	BySeverity []Count

	Endpoints     []Count
	Upstreams     []Count
	ContentModes  []Count
	FinishReasons []Count
	Statuses      []Count
	ToolsOffered  []Count
	ToolsCalled   []Count
	EventTypes    []Count
	Params        []ParamRange
	Models        []ModelStat

	Streamed         int
	Errors           int
	DistinctClients  int
	DistinctSessions int

	PromptTokens     int
	CompletionTokens int

	LatencyP50 float64
	LatencyP95 float64
	TTFBP50    float64
}

// Observed reports whether there is any traffic to describe.
func (s *Summary) Observed() bool { return s.Inference > 0 }

// Substituted reports whether any upstream served a different model than the
// caller asked for. That divergence is worth calling out in documentation: it
// means the identifier the application believes it is using is not the one
// that produced the output.
func (s *Summary) Substituted() bool {
	for _, m := range s.Models {
		if m.Requested != "" && m.Served != "" && m.Requested != m.Served {
			return true
		}
	}
	return false
}

// Window renders the observation period as a human-readable range.
func (s *Summary) Window() string {
	if s.FirstTime == "" {
		return "no records"
	}
	if s.FirstTime == s.LastTime {
		return s.FirstTime
	}
	return s.FirstTime + " to " + s.LastTime
}

// Summarise reads an evidence directory and aggregates it. It also runs a full
// integrity check, because a summary of a log nobody verified is not evidence.
func Summarise(dir string, now time.Time) (*Summary, error) {
	s := &Summary{Dir: dir, GeneratedAt: now.UTC()}

	verified, err := evidence.Verify(dir)
	if err != nil {
		return nil, err
	}
	s.ChainVerified = verified.OK()
	s.ChainProblems = verified.Problems
	s.HeadHash = verified.HeadHash
	s.Segments = verified.Segments
	s.Checkpoints = verified.Checkpoints
	s.CheckpointsVerified = verified.CheckpointsVerified
	s.Attested = verified.Attested
	s.KeyID = verified.KeyID
	s.Pruned = verified.Pruned
	s.PrunedThroughSeq = verified.PrunedThroughSeq
	s.Timestamps = verified.Timestamps
	s.TimestampedCheckpoints = verified.TimestampedCheckpoints

	// A segment that cannot be stat'ed is left out of the total rather than
	// failing the report: the size is context for a retention decision, and the
	// chain verification above is what actually has to be exact.
	if segs, segErr := evidence.Segments(dir); segErr == nil {
		for _, seg := range segs {
			if info, statErr := os.Stat(seg.Path); statErr == nil {
				s.Bytes += info.Size()
			}
		}
	}

	// Erasure is derived from the keystore rather than from the record, because
	// the chain hashes each record as written and nothing may go back and stamp
	// it. With no keystore the sealed records are reported as sealed, which is
	// what an exported bundle should say.
	var keys *evidence.ContentKeystore
	if _, statErr := os.Stat(evidence.ContentKeystorePath(dir)); statErr == nil {
		keys, _ = evidence.OpenContentKeystore(evidence.ContentKeystorePath(dir))
	}

	endpoints := map[string]int{}
	upstreams := map[string]int{}
	modes := map[string]int{}
	finish := map[string]int{}
	statuses := map[string]int{}
	toolsOffered := map[string]int{}
	toolsCalled := map[string]int{}
	eventTypes := map[string]int{}
	decisions := map[string]int{}
	severities := map[string]int{}
	clients := map[string]struct{}{}
	sessions := map[string]struct{}{}
	models := map[string]*ModelStat{}
	params := map[string]*ParamRange{}

	var latencies, ttfbs []float64

	err = evidence.Walk(dir, func(e evidence.Entry) error {
		ev := e.Event
		s.Records++
		eventTypes[ev.EventType]++

		if s.FirstTime == "" {
			s.FirstTime = e.Record.Timestamp
		}
		s.LastTime = e.Record.Timestamp

		if ev.EventType == evidence.EventHumanIntervention {
			s.Interventions++
			if ev.Decision != "" {
				decisions[ev.Decision]++
			}
		}
		if ev.EventType == evidence.EventIncident {
			s.Incidents++
			if ev.Severity != "" {
				severities[ev.Severity]++
			}
		}
		if ev.EventType != evidence.EventInference {
			return nil
		}
		s.Inference++

		if ev.Endpoint != "" {
			endpoints[ev.Endpoint]++
		}
		if ev.Upstream != "" {
			upstreams[ev.Upstream]++
		}
		if ev.Content != nil {
			modes[ev.Content.Mode]++
			if ev.Content.Encryption != nil {
				if keys.MarkErased(&ev) {
					s.Erased++
				} else {
					s.Encrypted++
				}
			}
		}
		for _, fr := range ev.FinishReasons {
			finish[fr]++
		}
		if ev.Status != 0 {
			statuses[fmt.Sprintf("%d", ev.Status)]++
		}
		if ev.Status >= 400 || ev.Error != "" {
			s.Errors++
		}
		if ev.Stream {
			s.Streamed++
		}
		if ev.ClientHash != "" {
			clients[ev.ClientHash] = struct{}{}
		}
		if ev.SessionID != "" {
			sessions[ev.SessionID] = struct{}{}
		}
		if ev.LatencyMS > 0 {
			latencies = append(latencies, ev.LatencyMS)
		}
		if ev.TTFBMS > 0 {
			ttfbs = append(ttfbs, ev.TTFBMS)
		}

		key := ev.ModelRequested + "\x00" + ev.ModelServed
		m, ok := models[key]
		if !ok {
			m = &ModelStat{Requested: ev.ModelRequested, Served: ev.ModelServed}
			models[key] = m
		}
		m.Requests++
		if ev.Stream {
			m.Streamed++
		}
		if ev.Status >= 400 || ev.Error != "" {
			m.Errors++
		}
		if ev.Usage != nil {
			m.PromptTokens += ev.Usage.PromptTokens
			m.CompletionTokens += ev.Usage.CompletionTokens
			s.PromptTokens += ev.Usage.PromptTokens
			s.CompletionTokens += ev.Usage.CompletionTokens
		}

		for _, tc := range ev.ToolCalls {
			if tc.Name != "" {
				toolsCalled[tc.Name]++
			}
		}
		if ev.Params != nil {
			for _, t := range ev.Params.ToolsOffered {
				toolsOffered[t]++
			}
			observeParam(params, "temperature", ev.Params.Temperature)
			observeParam(params, "top_p", ev.Params.TopP)
			observeParam(params, "presence_penalty", ev.Params.PresencePenalty)
			observeParam(params, "frequency_penalty", ev.Params.FrequencyPenalty)
			if ev.Params.MaxTokens != nil {
				v := float64(*ev.Params.MaxTokens)
				observeParam(params, "max_tokens", &v)
			}
			if ev.Params.N != nil {
				v := float64(*ev.Params.N)
				observeParam(params, "n", &v)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.Endpoints = sortCounts(endpoints)
	s.Upstreams = sortCounts(upstreams)
	s.ContentModes = sortCounts(modes)
	s.FinishReasons = sortCounts(finish)
	s.Statuses = sortCounts(statuses)
	s.ToolsOffered = sortCounts(toolsOffered)
	s.ToolsCalled = sortCounts(toolsCalled)
	s.EventTypes = sortCounts(eventTypes)
	s.ByDecision = sortCounts(decisions)
	s.BySeverity = sortCounts(severities)
	s.DistinctClients = len(clients)
	s.DistinctSessions = len(sessions)

	s.Models = make([]ModelStat, 0, len(models))
	for _, m := range models {
		s.Models = append(s.Models, *m)
	}
	sort.Slice(s.Models, func(i, j int) bool {
		if s.Models[i].Requests != s.Models[j].Requests {
			return s.Models[i].Requests > s.Models[j].Requests
		}
		if s.Models[i].Requested != s.Models[j].Requested {
			return s.Models[i].Requested < s.Models[j].Requested
		}
		return s.Models[i].Served < s.Models[j].Served
	})

	s.Params = make([]ParamRange, 0, len(params))
	for _, p := range params {
		s.Params = append(s.Params, *p)
	}
	sort.Slice(s.Params, func(i, j int) bool { return s.Params[i].Name < s.Params[j].Name })

	s.LatencyP50 = percentile(latencies, 0.50)
	s.LatencyP95 = percentile(latencies, 0.95)
	s.TTFBP50 = percentile(ttfbs, 0.50)

	return s, nil
}

func observeParam(m map[string]*ParamRange, name string, v *float64) {
	if v == nil {
		return
	}
	p, ok := m[name]
	if !ok {
		m[name] = &ParamRange{Name: name, Min: *v, Max: *v, Count: 1}
		return
	}
	p.Count++
	if *v < p.Min {
		p.Min = *v
	}
	if *v > p.Max {
		p.Max = *v
	}
}

// sortCounts orders by descending frequency, then by name, so that report
// output is byte-identical for identical input.
func sortCounts(m map[string]int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func percentile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	idx := int(float64(len(sorted)-1) * q)
	return sorted[idx]
}

func trimFloat(f float64) string {
	s := fmt.Sprintf("%.4f", f)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}
