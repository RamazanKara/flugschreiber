package cli

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
	"github.com/RamazanKara/flugschreiber/internal/version"
)

func verifySARIF(res *evidence.VerifyResult) (map[string]any, error) {
	dir, err := filepath.Abs(res.Dir)
	if err != nil {
		return nil, err
	}
	base := &url.URL{Scheme: "file", Path: filepath.ToSlash(dir) + "/"}
	if strings.HasPrefix(base.Path, "//") {
		base.Host, base.Path, _ = strings.Cut(strings.TrimPrefix(base.Path, "//"), "/")
		base.Path = "/" + base.Path
	} else if !strings.HasPrefix(base.Path, "/") {
		base.Path = "/" + base.Path
	}
	rules := []any{}
	results := []any{}
	seen := map[string]bool{}
	complete := true
	for _, p := range res.Problems {
		if !seen[p.Kind] {
			rules = append(rules, map[string]any{"id": p.Kind})
			seen[p.Kind] = true
		}
		level := "error"
		if (&evidence.VerifyResult{Problems: []evidence.Problem{p}}).Intact() {
			level = "warning"
			complete = false
		}
		result := map[string]any{
			"ruleId":     p.Kind,
			"level":      level,
			"message":    map[string]any{"text": p.Detail},
			"properties": map[string]any{"sequence": p.Seq, "severity": p.Severity},
		}
		if p.Segment != "" {
			uri := &url.URL{Path: filepath.ToSlash(p.Segment)}
			physical := map[string]any{
				"artifactLocation": map[string]any{"uri": uri.String(), "uriBaseId": "EVIDENCE"},
			}
			if p.Line > 0 {
				physical["region"] = map[string]any{"startLine": p.Line}
			}
			result["locations"] = []any{map[string]any{"physicalLocation": physical}}
		}
		results = append(results, result)
	}
	exitCode := 0
	if !res.Intact() {
		exitCode = 1
	} else if !res.OK() {
		exitCode = 2
	}
	return map[string]any{
		"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "flugschreiber", "version": version.Version, "rules": rules,
			}},
			"originalUriBaseIds": map[string]any{"EVIDENCE": map[string]any{"uri": base.String()}},
			"invocations":        []any{map[string]any{"executionSuccessful": complete, "exitCode": exitCode}},
			"results":            results,
			"properties": map[string]any{
				"records": res.Records, "headHash": res.HeadHash, "attested": res.Attested,
				"pruned": res.Pruned, "notes": res.Notes,
			},
		}},
	}, nil
}
