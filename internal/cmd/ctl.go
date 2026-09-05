package cmd

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// CTL executes remote management commands through the public HTTP API.
func CTL(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || HasHelpFlag(args) {
		fmt.Fprintln(stdout, ctlUsage)
		return 0
	}
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "http://localhost:8080", "")
	token := fs.String("token", "", "")
	tokenFile := fs.String("token-file", "", "")
	output := fs.String("output", "table", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "ctl command required")
		return 2
	}
	if *token == "" && *tokenFile != "" {
		b, e := os.ReadFile(*tokenFile)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 1
		}
		*token = strings.TrimSpace(string(b))
	}
	method, path, body, err := ctlSpec(rest, stdin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	reqbody := io.Reader(nil)
	if body != nil {
		b, _ := json.Marshal(body)
		reqbody = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, strings.TrimRight(*server, "/")+path, reqbody)
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 1
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		fmt.Fprintln(stderr, string(data))
		return 1
	}
	if resp.StatusCode != 204 {
		if *output == "json" {
			var v any
			if json.Unmarshal(data, &v) == nil {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				enc.Encode(v)
			} else {
				stdout.Write(data)
			}
		} else {
			stdout.Write(data)
			if len(data) > 0 && data[len(data)-1] != '\n' {
				fmt.Fprintln(stdout)
			}
		}
	}
	return 0
}

const ctlUsage = "authservicecentral ctl [flags] <command>\n\nCommands: token exchange, check, audiences {create,list,get,update,delete}, resources {create,get,update,delete}, relationships {set,remove}, groups {create,get,delete,add-member,remove-member}, grants {create,list,delete}"

func ctlSpec(a []string, in io.Reader) (string, string, any, error) {
	if len(a) < 2 {
		return "", "", nil, fmt.Errorf("incomplete ctl command")
	}
	domain, op := a[0], a[1]
	f := flag.NewFlagSet(domain, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	vals := map[string]*string{}
	bools := map[string]*bool{}
	add := func(n string) { vals[n] = f.String(n, "", "") }
	for _, n := range []string{"id", "type", "resource-type", "resource-id", "relation", "role", "principal-source", "principal-subject", "group", "target", "metadata", "metadata-file", "display-name", "delegation-mode", "token-ttl", "permission", "file", "subject-token", "subject-token-file", "audience", "actor-token", "actor-token-file"} {
		add(n)
	}
	for _, n := range []string{"yes", "all", "create-resource-if-missing"} {
		bools[n] = f.Bool(n, false, "")
	}
	if e := f.Parse(a[2:]); e != nil {
		return "", "", nil, e
	}
	v := func(n string) string { return *vals[n] }
	path := ""
	method := ""
	var body any
	switch domain + "/" + op {
	case "audiences/list":
		method, path = "GET", "/v1/manage/audiences"
	case "audiences/get":
		method, path = "GET", "/v1/manage/audiences/"+v("id")
	case "audiences/delete":
		method, path = "DELETE", "/v1/manage/audiences/"+v("id")
	case "groups/get":
		method, path = "GET", "/v1/manage/groups/"+v("id")
	case "groups/delete":
		method, path = "DELETE", "/v1/manage/groups/"+v("id")
	case "grants/list":
		method, path = "GET", "/v1/manage/grants"
	case "grants/delete":
		method, path = "DELETE", "/v1/manage/grants/"+v("id")
	case "resources/get":
		method, path = "GET", "/v1/manage/resources/"+v("resource-type")+"/"+v("resource-id")
	case "resources/delete":
		method, path = "DELETE", "/v1/manage/resources/"+v("type")+"/"+v("id")
	case "audiences/create", "audiences/update":
		if op == "create" {
			method, path = "POST", "/v1/manage/audiences"
		} else {
			method, path = "PATCH", "/v1/manage/audiences/"+v("id")
		}
		body = map[string]any{}
		for _, k := range []string{"display-name", "delegation-mode"} {
			if v(k) != "" {
				body[strings.ReplaceAll(k, "-", "_")] = v(k)
			}
		}
		if v("token-ttl") != "" {
			body["token_ttl_seconds"] = v("token-ttl")
		}
		if op == "create" {
			body["id"] = v("id")
		}
	case "groups/create":
		method, path = "POST", "/v1/manage/groups"
		body = map[string]any{"id": v("id"), "display_name": v("display-name")}
	case "resources/create":
		method, path = "POST", "/v1/manage/resources"
		body = map[string]any{"type": v("type"), "id": v("id")}
	case "resources/update":
		method, path = "PATCH", "/v1/manage/resources/"+v("type")+"/"+v("id")
		body = map[string]any{}
	case "grants/create":
		method, path = "POST", "/v1/manage/grants"
		body = map[string]any{"id": v("id"), "role": v("role"), "resource": map[string]any{"type": v("resource-type"), "id": v("resource-id")}, "subject": map[string]any{}}
	case "check":
		method, path = "POST", "/v1/check"
		if v("file") != "" {
			var b []byte
			if v("file") == "-" {
				b, _ = io.ReadAll(in)
			} else {
				b, _ = os.ReadFile(v("file"))
			}
			json.Unmarshal(b, &body)
		} else {
			body = map[string]any{"checks": []any{map[string]any{"id": "check-1", "permission": v("permission"), "resource": map[string]any{"type": v("resource-type"), "id": v("resource-id")}}}}
		}
	default:
		return "", "", nil, fmt.Errorf("unsupported ctl command %s %s", domain, op)
	}
	_ = in
	_ = body
	_ = bools
	return method, path, body, nil
}
