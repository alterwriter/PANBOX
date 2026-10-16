package main

import "strings"

func toSARIF(b bundle, gate string) map[string]any {
	rules := []any{}
	results := []any{}
	seen := map[string]bool{}
	for _, f := range b.Findings {
		id := strings.ToUpper(f.Module) + "/" + f.RuleID
		if !seen[id] {
			rules = append(rules, map[string]any{"id": id, "shortDescription": map[string]string{"text": f.RuleID}})
			seen[id] = true
		}
		level := "note"
		if f.RawSeverity == "critical" || f.RawSeverity == "high" {
			level = "error"
		} else if f.RawSeverity == "medium" {
			level = "warning"
		}
		result := map[string]any{"ruleId": id, "level": level, "message": map[string]string{"text": f.Message}, "fingerprints": map[string]string{"panbox/v1": f.Fingerprint}, "properties": map[string]any{"raw_severity": f.RawSeverity, "module": f.Module}}
		if f.Location.Path != "" {
			result["locations"] = []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": f.Location.Path}, "region": map[string]int{"startLine": max(1, f.Location.Line)}}}}
		}
		results = append(results, result)
	}
	return map[string]any{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "PANBOX", "version": "0.1.0", "rules": rules}}, "results": results, "properties": map[string]any{"gate": gate, "repository_id": b.RepositoryID, "branch": b.Git.Branch}}}}
}
