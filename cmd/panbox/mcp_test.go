package main

import (
	"encoding/json"
	"testing"
)

func TestMCPReadOnlyToolCatalog(t *testing.T) {
	for _, method := range []string{"initialize", "server/discover", "tools/list"} {
		response := mcpResponse(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: method}, "http://127.0.0.1:8092", "unused")
		if response["error"] != nil || response["result"] == nil {
			t.Fatalf("%s: %#v", method, response)
		}
	}
	response := mcpResponse(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage("2"), Method: "tools/list"}, "http://127.0.0.1:8092", "unused")
	tools := response["result"].(map[string]any)["tools"].([]map[string]any)
	if len(tools) != 4 {
		t.Fatalf("unexpected catalog: %#v", tools)
	}
	for _, tool := range tools {
		if tool["name"] == "panbox_recast" {
			t.Fatal("MCP must be read-only")
		}
	}
}
