package proxy

import (
	"fmt"
	"net/http/httputil"
	"net/url"

	"github.com/RamazanKara/flugschreiber/internal/config"
)

// route is one upstream the recording proxy can send a request to. It pairs the
// reverse proxy that reaches that upstream with the criteria that select it: a
// set of model-name globs and a set of permitted endpoint kinds. Each route
// carries its own transport, so model servers behind different certificate
// authorities coexist in one instance.
type route struct {
	name      string
	upstream  *url.URL
	label     string
	apiKey    string
	models    []string
	endpoints map[string]bool
	isDefault bool
	rp        *httputil.ReverseProxy
}

// allowsKind reports whether the route serves the given endpoint kind. An empty
// endpoint set permits every kind.
func (r *route) allowsKind(kind string) bool {
	if len(r.endpoints) == 0 {
		return true
	}
	return r.endpoints[kind]
}

// matches reports whether the route may serve a request for model on the given
// endpoint kind: the kind must be permitted and one of the route's model globs
// must match. A route with no model globs never matches here; it can still be
// chosen as the default fallback.
func (r *route) matches(model, kind string) bool {
	if !r.allowsKind(kind) {
		return false
	}
	for _, g := range r.models {
		if globMatch(g, model) {
			return true
		}
	}
	return false
}

// router selects a route for each recorded request by model name and endpoint
// kind, falling back to the route marked default when nothing else matches.
type router struct {
	routes []*route
	def    *route
}

// selectRoute returns the route that should serve a request for model on the
// given endpoint kind: the first route whose globs and endpoints match, else the
// route marked default, else nil when no default is configured. A nil result is
// the caller's cue to record the attempt and answer 502.
func (rt *router) selectRoute(model, kind string) *route {
	for _, r := range rt.routes {
		if r.matches(model, kind) {
			return r
		}
	}
	return rt.def
}

// globMatch reports whether name matches a glob pattern where '*' matches any
// run of characters, including none, and '?' matches exactly one. Unlike
// path.Match it does not treat '/' specially, so "llama-*" matches a
// vendor-prefixed model id such as "meta/llama-3.1-8b" the way an operator
// listing model globs expects. The matcher is iterative with single-star
// backtracking, so a hostile pattern cannot drive it into deep recursion.
func globMatch(pattern, name string) bool {
	p, n, star, starN := 0, 0, -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == name[n]):
			p++
			n++
		case p < len(pattern) && pattern[p] == '*':
			star = p
			starN = n
			p++
		case star >= 0:
			p = star + 1
			starN++
			n = starN
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// routeSpec is the resolved metadata for one route, before its transport and
// reverse proxy are built.
type routeSpec struct {
	name      string
	upstream  *url.URL
	label     string
	apiKey    string
	caFile    string
	tlsSkip   bool
	models    []string
	endpoints map[string]bool
	isDefault bool
}

// newRouter resolves the configured upstreams into routes, each with its own
// transport and reverse proxy. A single Upstream is expressed as one default
// route, so the single-upstream path and the multi-upstream path share exactly
// one routing and recording code path.
func newRouter(s *Server, cfg config.Config) (*router, error) {
	specs, err := resolveRoutes(cfg)
	if err != nil {
		return nil, err
	}
	rt := &router{}
	for _, spec := range specs {
		transport, err := newTransport(cfg, spec.caFile, spec.tlsSkip)
		if err != nil {
			return nil, err
		}
		r := &route{
			name:      spec.name,
			upstream:  spec.upstream,
			label:     spec.label,
			apiKey:    spec.apiKey,
			models:    spec.models,
			endpoints: spec.endpoints,
			isDefault: spec.isDefault,
		}
		r.rp = s.buildReverseProxy(r, transport)
		rt.routes = append(rt.routes, r)
		if r.isDefault {
			rt.def = r
		}
	}
	return rt, nil
}

// resolveRoutes turns configuration into route specs. When no explicit list is
// given the single Upstream becomes one default route, preserving the mock
// label so demo evidence still reads "mock-upstream".
func resolveRoutes(cfg config.Config) ([]routeSpec, error) {
	if len(cfg.Upstreams) == 0 {
		u, err := url.Parse(cfg.Upstream)
		if err != nil {
			return nil, fmt.Errorf("proxy: parse upstream: %w", err)
		}
		label := upstreamLabel(u)
		if cfg.MockUpstream {
			label = "mock-upstream"
		}
		return []routeSpec{{
			name:      "default",
			upstream:  u,
			label:     label,
			apiKey:    cfg.UpstreamAPIKey,
			caFile:    cfg.UpstreamCAFile,
			tlsSkip:   cfg.UpstreamTLSSkipVerify,
			isDefault: true,
		}}, nil
	}

	specs := make([]routeSpec, 0, len(cfg.Upstreams))
	for _, up := range cfg.Upstreams {
		u, err := url.Parse(up.URL)
		if err != nil {
			return nil, fmt.Errorf("proxy: parse upstream %q: %w", up.Name, err)
		}
		specs = append(specs, routeSpec{
			name:      up.Name,
			upstream:  u,
			label:     upstreamLabel(u),
			apiKey:    up.APIKey,
			caFile:    up.CAFile,
			tlsSkip:   up.TLSSkip,
			models:    up.Models,
			endpoints: endpointSet(up.Endpoints),
			isDefault: up.Default,
		})
	}
	return specs, nil
}

func endpointSet(kinds []string) map[string]bool {
	if len(kinds) == 0 {
		return nil
	}
	m := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		m[k] = true
	}
	return m
}

// upstreamLabel renders where traffic went without leaking any credential
// embedded in the URL. It is the value recorded in the evidence record's
// Upstream field, naming the route that served the request.
func upstreamLabel(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}
