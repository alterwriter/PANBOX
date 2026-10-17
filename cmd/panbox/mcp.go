package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func runMCP(args []string) int {
	flags := flag.NewFlagSet("mcp", flag.ContinueOnError)
	server := flags.String("server", os.Getenv("PANBOX_SERVER"), "PANBOX HTTPS or loopback URL")
	if flags.Parse(args) != nil {
		return 2
	}
	base, err := baseServer(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	token := os.Getenv("PANBOX_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "PANBOX_TOKEN read-only access key required")
		return 3
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	output := bufio.NewWriter(os.Stdout)
	defer output.Flush()
	for scanner.Scan() {
		var req mcpRequest
		if json.Unmarshal(scanner.Bytes(), &req) != nil || req.JSONRPC != "2.0" {
			continue
		}
		if len(req.ID) == 0 {
			continue
		} // Notifications have no response.
		response := mcpResponse(req, base, token)
		data, _ := json.Marshal(response)
		_, _ = output.Write(data)
		_ = output.WriteByte('\n')
		_ = output.Flush()
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

func mcpResponse(req mcpRequest, base, token string) map[string]any {
	out := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	modern := req.Method == "server/discover" || strings.Contains(string(req.Params), "2026-07-28")
	result := map[string]any{}
	switch req.Method {
	case "server/discover":
		result = map[string]any{"supportedVersions": []string{"2026-07-28", "2025-11-25"}, "capabilities": map[string]any{"tools": map[string]any{}}, "resultType": "complete"}
	case "initialize":
		result = map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "panbox", "version": "0.1.0"}}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		props := func(keys ...string) map[string]any {
			p := map[string]any{}
			for _, k := range keys {
				p[k] = map[string]string{"type": "string"}
			}
			return map[string]any{"type": "object", "properties": p, "additionalProperties": false}
		}
		result["tools"] = []map[string]any{
			{"name": "panbox_repositories", "description": "List repositories visible to this PANBOX access key.", "inputSchema": props()},
			{"name": "panbox_findings", "description": "List latest complete-scan findings with optional exact repository, branch, module and severity filters.", "inputSchema": props("repository_id", "branch", "module", "severity")},
			{"name": "panbox_scans", "description": "List recent scans, optionally scoped to a repository.", "inputSchema": props("repository_id")},
			{"name": "panbox_scan", "description": "Get a scan by ID.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"scan_id": map[string]string{"type": "string"}}, "required": []string{"scan_id"}, "additionalProperties": false}},
		}
	case "tools/call":
		var params struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if json.Unmarshal(req.Params, &params) != nil {
			out["error"] = map[string]any{"code": -32602, "message": "invalid tool arguments"}
			return out
		}
		path := ""
		q := url.Values{}
		switch params.Name {
		case "panbox_repositories":
			path = "/v1/repos"
		case "panbox_findings":
			path = "/v1/findings"
			for _, key := range []string{"repository_id", "branch", "module", "severity"} {
				if value := params.Arguments[key]; value != "" {
					q.Set(key, value)
				}
			}
		case "panbox_scans":
			path = "/v1/scans"
			if value := params.Arguments["repository_id"]; value != "" {
				q.Set("repository_id", value)
			}
		case "panbox_scan":
			id := params.Arguments["scan_id"]
			if id == "" {
				out["error"] = map[string]any{"code": -32602, "message": "scan_id required"}
				return out
			}
			path = "/v1/scans/" + url.PathEscape(id)
		default:
			out["error"] = map[string]any{"code": -32602, "message": "unknown tool"}
			return out
		}
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		body, err := mcpAPI(base, token, path)
		if err != nil {
			result["isError"] = true
			body = []byte(err.Error())
		}
		result["content"] = []map[string]string{{"type": "text", "text": string(body)}}
	default:
		out["error"] = map[string]any{"code": -32601, "message": "method not found"}
		return out
	}
	if modern {
		result["resultType"] = "complete"
		result["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": map[string]string{"name": "panbox", "version": "0.1.0"}}
	}
	out["result"] = result
	return out
}

func mcpAPI(base, token, path string) ([]byte, error) {
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("PANBOX API HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data))))
	}
	return data, nil
}
