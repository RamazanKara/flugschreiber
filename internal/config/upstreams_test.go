package config

import (
	"strings"
	"testing"
)

func validUpstreams() []UpstreamRoute {
	return []UpstreamRoute{
		{Name: "chat", URL: "http://chat:8000", Models: []string{"llama-*"}, Endpoints: []string{"chat"}, Default: true},
		{Name: "embed", URL: "http://embed:8000", Models: []string{"bge-*"}, Endpoints: []string{"embedding"}},
	}
}

func TestValidateAcceptsAWellFormedUpstreamsList(t *testing.T) {
	c := Default()
	c.Upstreams = validUpstreams()
	if err := c.Validate(); err != nil {
		t.Fatalf("a well-formed upstreams list was rejected: %v", err)
	}
}

// The single upstream and the routes list say the same thing two ways, so
// setting both is ambiguous and refused rather than silently preferring one.
func TestValidateRejectsUpstreamAndUpstreamsTogether(t *testing.T) {
	c := Default()
	c.Upstream = "http://single:8000"
	c.Upstreams = validUpstreams()

	err := c.Validate()
	if err == nil {
		t.Fatal("expected an error when both upstream and upstreams are set")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("error does not explain the conflict: %v", err)
	}
}

func TestValidateRejectsUpstreamsWithNoDefault(t *testing.T) {
	c := Default()
	c.Upstreams = []UpstreamRoute{
		{Name: "chat", URL: "http://chat:8000"},
		{Name: "embed", URL: "http://embed:8000"},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected an error when no route is marked default")
	}
	if !strings.Contains(err.Error(), "exactly one default") {
		t.Errorf("error does not name the rule: %v", err)
	}
}

func TestValidateRejectsUpstreamsWithTwoDefaults(t *testing.T) {
	c := Default()
	c.Upstreams = []UpstreamRoute{
		{Name: "chat", URL: "http://chat:8000", Default: true},
		{Name: "embed", URL: "http://embed:8000", Default: true},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected an error when two routes are marked default")
	}
	if !strings.Contains(err.Error(), "exactly one default") {
		t.Errorf("error does not name the rule: %v", err)
	}
}

func TestValidateRejectsANamelessRoute(t *testing.T) {
	c := Default()
	c.Upstreams = []UpstreamRoute{{URL: "http://chat:8000", Default: true}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for a route with no name")
	}
}

func TestValidateRejectsARouteWithABadURL(t *testing.T) {
	c := Default()
	c.Upstreams = []UpstreamRoute{{Name: "chat", URL: "chat:8000", Default: true}}

	err := c.Validate()
	if err == nil {
		t.Fatal("expected an error for a route URL with no scheme")
	}
	if !strings.Contains(err.Error(), "chat") {
		t.Errorf("error does not name the offending route: %v", err)
	}
}
