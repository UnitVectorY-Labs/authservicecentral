package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/api"
)

const (
	ctlDefaultServer   = "http://localhost:8080"
	jwtTokenType       = "urn:ietf:params:oauth:token-type:jwt"
	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
)

type ctlOptions struct {
	server, token, tokenFile, output, requestID string
	timeout                                     time.Duration
	stdin                                       io.Reader
	stdout, stderr                              io.Writer
	stdinUsed                                   bool
}

type ctlRequest struct {
	method, path, contentType string
	body                      []byte
	result                    string
}
type trackedStrings struct {
	values map[string]string
	set    map[string]bool
}
type stringList []string

func newTrackedStrings() *trackedStrings {
	return &trackedStrings{map[string]string{}, map[string]bool{}}
}
func (t *trackedStrings) add(fs *flag.FlagSet, name string) {
	fs.Func(name, "", func(v string) error { t.values[name], t.set[name] = v, true; return nil })
}
func (t *trackedStrings) get(name string) string { return t.values[name] }
func (s *stringList) String() string             { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error         { *s = append(*s, v); return nil }

// CTL executes a remote command exclusively through the public HTTP API.
func CTL(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, commandArgs, help, err := parseCTLCommon(args, stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if help {
		fmt.Fprintln(stdout, ctlUsage())
		return 0
	}
	r, err := buildCTLRequest(o, commandArgs)
	var helpRequest *ctlHelpRequest
	if errors.As(err, &helpRequest) {
		fmt.Fprintln(stdout, ctlCommandUsage(helpRequest.command))
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if err := executeCTL(o, r); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func parseCTLCommon(args []string, stdin io.Reader, stdout, stderr io.Writer) (*ctlOptions, []string, bool, error) {
	if len(args) == 0 {
		return nil, nil, true, nil
	}
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	timeout := 30 * time.Second
	if raw := os.Getenv("SERVICEAUTH_CTL_TIMEOUT"); raw != "" {
		var err error
		timeout, err = time.ParseDuration(raw)
		if err != nil {
			return nil, nil, false, fmt.Errorf("SERVICEAUTH_CTL_TIMEOUT must be a valid duration: %w", err)
		}
	}
	o := &ctlOptions{server: envOr("SERVICEAUTH_CTL_SERVER", ctlDefaultServer), token: os.Getenv("SERVICEAUTH_CTL_TOKEN"), output: "table", timeout: timeout, stdin: stdin, stdout: stdout, stderr: stderr}
	fs.StringVar(&o.server, "server", o.server, "")
	fs.StringVar(&o.token, "token", o.token, "")
	fs.StringVar(&o.tokenFile, "token-file", "", "")
	fs.DurationVar(&o.timeout, "timeout", o.timeout, "")
	fs.StringVar(&o.output, "output", "table", "")
	fs.StringVar(&o.requestID, "request-id", "", "")
	var h, help bool
	fs.BoolVar(&h, "h", false, "")
	fs.BoolVar(&help, "help", false, "")
	if err := fs.Parse(args); err != nil {
		return nil, nil, false, err
	}
	if h || help {
		return o, nil, true, nil
	}
	commandArgs := fs.Args()
	if len(commandArgs) == 0 {
		return nil, nil, false, errors.New("a ctl command is required")
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, name := range []string{"server", "token", "token-file", "output", "request-id"} {
		if set[name] && fs.Lookup(name).Value.String() == "" {
			return nil, nil, false, fmt.Errorf("--%s must not be empty", name)
		}
	}
	if set["token"] && set["token-file"] {
		return nil, nil, false, errors.New("--token and --token-file are mutually exclusive")
	}
	if o.timeout <= 0 {
		return nil, nil, false, errors.New("--timeout must be positive")
	}
	if o.output != "table" && o.output != "json" {
		return nil, nil, false, errors.New("--output must be table or json")
	}
	u, err := url.Parse(o.server)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, nil, false, errors.New("--server must be an absolute http or https URL without user information, query, or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	o.server = u.String()
	if o.requestID != "" && !validRequestID(o.requestID) {
		return nil, nil, false, errors.New("--request-id must be 1-128 ASCII letters, digits, '-', '_', or '.'")
	}
	if o.tokenFile != "" {
		value, err := o.readValue(o.tokenFile, "bearer token")
		if err != nil {
			return nil, nil, false, err
		}
		o.token = trimLine(value)
		if o.token == "" {
			return nil, nil, false, errors.New("bearer token file is empty")
		}
	}
	return o, commandArgs, false, nil
}

func buildCTLRequest(o *ctlOptions, args []string) (ctlRequest, error) {
	if args[0] == "check" {
		return buildCheck(o, args[1:])
	}
	if len(args) < 2 {
		return ctlRequest{}, fmt.Errorf("%s requires a subcommand", args[0])
	}
	if args[1] == "-h" || args[1] == "--help" {
		return ctlRequest{}, &ctlHelpRequest{command: args[0]}
	}
	command, operation, rest := args[0], args[1], args[2:]
	if command == "token" && operation == "exchange" {
		return buildTokenExchange(o, rest)
	}
	switch command {
	case "audiences":
		return buildAudience(o, operation, rest)
	case "resources":
		return buildResource(o, operation, rest)
	case "relationships":
		return buildRelationship(operation, rest)
	case "groups":
		return buildGroup(o, operation, rest)
	case "grants":
		return buildGrant(o, operation, rest)
	default:
		return ctlRequest{}, fmt.Errorf("unknown ctl command %q", command)
	}
}

type ctlHelpRequest struct{ command string }

func (e *ctlHelpRequest) Error() string { return "help requested for " + e.command }

func parseCommand(name string, args, stringsFlags, boolFlags []string, lists map[string]*stringList) (*trackedStrings, map[string]bool, error) {
	for _, arg := range args {
		for _, flagName := range boolFlags {
			if strings.HasPrefix(arg, "--"+flagName+"=") {
				return nil, nil, fmt.Errorf("--%s is enabled by its presence and does not take a value", flagName)
			}
		}
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	v := newTrackedStrings()
	for _, n := range stringsFlags {
		v.add(fs, n)
	}
	b := map[string]bool{}
	boolPointers := map[string]*bool{}
	for _, n := range boolFlags {
		boolPointers[n] = fs.Bool(n, false, "")
	}
	for n, list := range lists {
		fs.Var(list, n, "")
	}
	var h, help bool
	fs.BoolVar(&h, "h", false, "")
	fs.BoolVar(&help, "help", false, "")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if h || help {
		return nil, nil, &ctlHelpRequest{command: name}
	}
	if len(fs.Args()) > 0 {
		return nil, nil, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	for name, pointer := range boolPointers {
		b[name] = *pointer
	}
	return v, b, nil
}

func executeCTL(o *ctlOptions, r ctlRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	var body io.Reader
	if r.body != nil {
		body = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, o.server+r.path, body)
	if err != nil {
		return err
	}
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}
	if o.token != "" && r.path != "/oauth2/token" {
		req.Header.Set("Authorization", "Bearer "+o.token)
	}
	if o.requestID != "" {
		req.Header.Set("X-Request-ID", o.requestID)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return formatAPIError(resp, raw)
	}
	if resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if o.output == "json" {
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return fmt.Errorf("server returned invalid JSON: %w", err)
		}
		compact.WriteByte('\n')
		_, err = o.stdout.Write(compact.Bytes())
		return err
	}
	return writeCTLTable(o.stdout, r.result, raw)
}

func jsonRequest(method, p string, body any, result string) ctlRequest {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	content := ""
	if raw != nil {
		content = "application/json"
	}
	return ctlRequest{method, p, content, raw, result}
}

func writeCTLTable(out io.Writer, kind string, raw []byte) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	defer w.Flush()
	switch kind {
	case "audience":
		var x api.Audience
		if err := json.Unmarshal(raw, &x); err != nil {
			return err
		}
		writeAudienceRows(w, []api.Audience{x})
	case "audiences":
		var x struct {
			Audiences []api.Audience `json:"audiences"`
		}
		if err := json.Unmarshal(raw, &x); err != nil {
			return err
		}
		writeAudienceRows(w, x.Audiences)
	case "group":
		var x api.Group
		if err := json.Unmarshal(raw, &x); err != nil {
			return err
		}
		fmt.Fprintln(w, "ID\tDISPLAY_NAME")
		fmt.Fprintf(w, "%s\t%s\n", x.ID, x.DisplayName)
	case "grant":
		var x api.Grant
		if err := json.Unmarshal(raw, &x); err != nil {
			return err
		}
		writeGrantRows(w, []api.Grant{x})
	case "grants":
		var x struct {
			Grants []api.Grant `json:"grants"`
		}
		if err := json.Unmarshal(raw, &x); err != nil {
			return err
		}
		writeGrantRows(w, x.Grants)
	case "checks":
		var x api.CheckResponse
		if err := json.Unmarshal(raw, &x); err != nil {
			return err
		}
		fmt.Fprintln(w, "ID\tALLOWED")
		for _, r := range x.Results {
			fmt.Fprintf(w, "%s\t%t\n", r.ID, r.Allowed)
		}
	case "token":
		var x api.TokenExchangeResponse
		if err := json.Unmarshal(raw, &x); err != nil {
			return err
		}
		fmt.Fprintln(w, "ACCESS_TOKEN\tTOKEN_TYPE\tEXPIRES_IN")
		fmt.Fprintf(w, "%s\t%s\t%d\n", x.AccessToken, x.TokenType, x.ExpiresIn)
	case "resource":
		var x api.Resource
		if err := json.Unmarshal(raw, &x); err != nil {
			return err
		}
		metadata, _ := json.Marshal(x.Metadata)
		fmt.Fprintln(w, "TYPE\tID\tMETADATA")
		fmt.Fprintf(w, "%s\t%s\t%s\n", x.Type, x.ID, string(metadata))
		if len(x.Relationships) > 0 {
			fmt.Fprintln(w, "\nRELATIONSHIP\tTARGET")
			relations := make([]string, 0, len(x.Relationships))
			for relation := range x.Relationships {
				relations = append(relations, relation)
			}
			sort.Strings(relations)
			for _, relation := range relations {
				targets := x.Relationships[relation]
				for _, target := range targets {
					fmt.Fprintf(w, "%s\t%s:%s\n", relation, target.Type, target.ID)
				}
			}
		}
	default:
		return fmt.Errorf("unknown response type %q", kind)
	}
	return nil
}
func writeAudienceRows(w io.Writer, x []api.Audience) {
	fmt.Fprintln(w, "ID\tDISPLAY_NAME\tTOKEN_TTL_SECONDS\tDELEGATION_MODE")
	for _, v := range x {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", v.ID, v.DisplayName, v.TokenTTLSeconds, v.Delegation.Mode)
	}
}
func writeGrantRows(w io.Writer, x []api.Grant) {
	fmt.Fprintln(w, "ID\tSUBJECT\tROLE\tRESOURCE")
	for _, v := range x {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s:%s\n", v.ID, subjectString(v.Subject), v.Role, v.Resource.Type, v.Resource.ID)
	}
}
func subjectString(s api.Subject) string {
	if s.Type == "group" {
		return "group:" + s.Group
	}
	return "principal:" + s.Source + ":" + s.Subject
}

func buildAudience(o *ctlOptions, op string, args []string) (ctlRequest, error) {
	flags := []string{"id"}
	if op == "create" || op == "update" {
		flags = append(flags, "display-name", "token-ttl", "delegation-mode")
	}
	bools := []string{}
	if op == "delete" {
		bools = []string{"yes"}
	}
	v, b, err := parseCommand("audiences "+op, args, flags, bools, nil)
	if err != nil {
		return ctlRequest{}, err
	}
	switch op {
	case "list":
		if v.set["id"] {
			return ctlRequest{}, errors.New("audiences list does not accept --id")
		}
		return jsonRequest(http.MethodGet, "/v1/manage/audiences", nil, "audiences"), nil
	case "get":
		if err := require(v, "id"); err != nil {
			return ctlRequest{}, err
		}
		return jsonRequest(http.MethodGet, path("v1", "manage", "audiences", v.get("id")), nil, "audience"), nil
	case "delete":
		if err := require(v, "id"); err != nil {
			return ctlRequest{}, err
		}
		if !b["yes"] {
			if err := o.confirmDelete("audience " + v.get("id")); err != nil {
				return ctlRequest{}, err
			}
		}
		return jsonRequest(http.MethodDelete, path("v1", "manage", "audiences", v.get("id")), nil, "none"), nil
	case "create", "update":
		if err := require(v, "id"); err != nil {
			return ctlRequest{}, err
		}
		if op == "create" && !v.set["token-ttl"] {
			return ctlRequest{}, errors.New("--token-ttl is required")
		}
		if op == "update" && !v.set["display-name"] && !v.set["token-ttl"] && !v.set["delegation-mode"] {
			return ctlRequest{}, errors.New("at least one update flag is required")
		}
		body := map[string]any{}
		if op == "create" {
			body["id"] = v.get("id")
		}
		if v.set["display-name"] {
			body["display_name"] = v.get("display-name")
		}
		if v.set["token-ttl"] {
			seconds, err := ttlSeconds(v.get("token-ttl"))
			if err != nil {
				return ctlRequest{}, err
			}
			body["token_ttl_seconds"] = seconds
		}
		if v.set["delegation-mode"] {
			mode := v.get("delegation-mode")
			if !validDelegationMode(mode) {
				return ctlRequest{}, errors.New("--delegation-mode must be disabled, subject, intersection, actor, or union")
			}
			body["delegation"] = map[string]any{"enabled": mode != "disabled", "mode": mode}
		} else if op == "create" {
			body["delegation"] = map[string]any{"enabled": false, "mode": "disabled"}
		}
		method, p := http.MethodPost, "/v1/manage/audiences"
		if op == "update" {
			method, p = http.MethodPatch, path("v1", "manage", "audiences", v.get("id"))
		}
		return jsonRequest(method, p, body, "audience"), nil
	default:
		return ctlRequest{}, fmt.Errorf("unknown audiences subcommand %q", op)
	}
}

func buildResource(o *ctlOptions, op string, args []string) (ctlRequest, error) {
	flags := []string{"type", "id"}
	if op == "create" || op == "update" {
		flags = append(flags, "metadata", "metadata-file")
	}
	rels := stringList{}
	var lists map[string]*stringList
	if op == "create" {
		lists = map[string]*stringList{"relationship": &rels}
	}
	bools := []string{}
	if op == "delete" {
		bools = []string{"yes"}
	}
	v, b, err := parseCommand("resources "+op, args, flags, bools, lists)
	if err != nil {
		return ctlRequest{}, err
	}
	if op != "create" && op != "get" && op != "update" && op != "delete" {
		return ctlRequest{}, fmt.Errorf("unknown resources subcommand %q", op)
	}
	if err := require(v, "type", "id"); err != nil {
		return ctlRequest{}, err
	}
	p := path("v1", "manage", "resources", v.get("type"), v.get("id"))
	switch op {
	case "get":
		return jsonRequest(http.MethodGet, p, nil, "resource"), nil
	case "delete":
		if !b["yes"] {
			if err := o.confirmDelete("resource " + v.get("type") + ":" + v.get("id")); err != nil {
				return ctlRequest{}, err
			}
		}
		return jsonRequest(http.MethodDelete, p, nil, "none"), nil
	}
	if v.set["metadata"] && v.set["metadata-file"] {
		return ctlRequest{}, errors.New("--metadata and --metadata-file are mutually exclusive")
	}
	if op == "update" && !v.set["metadata"] && !v.set["metadata-file"] {
		return ctlRequest{}, errors.New("one of --metadata or --metadata-file is required")
	}
	body := map[string]any{}
	if op == "create" {
		body["type"], body["id"] = v.get("type"), v.get("id")
	}
	if v.set["metadata"] || v.set["metadata-file"] {
		raw := v.get("metadata")
		if v.set["metadata-file"] {
			raw, err = o.readValue(v.get("metadata-file"), "metadata")
			if err != nil {
				return ctlRequest{}, err
			}
		}
		metadata, err := jsonObject(raw, "metadata")
		if err != nil {
			return ctlRequest{}, err
		}
		body["metadata"] = metadata
	}
	if len(rels) > 0 {
		relationships, err := parseInitialRelationships(rels)
		if err != nil {
			return ctlRequest{}, err
		}
		body["relationships"] = relationships
	}
	method := http.MethodPatch
	if op == "create" {
		method, p = http.MethodPost, "/v1/manage/resources"
	}
	return jsonRequest(method, p, body, "resource"), nil
}

func buildRelationship(op string, args []string) (ctlRequest, error) {
	targets := stringList{}
	v, b, err := parseCommand("relationships "+op, args, []string{"resource-type", "resource-id", "relation"}, []string{"all"}, map[string]*stringList{"target": &targets})
	if err != nil {
		return ctlRequest{}, err
	}
	if op != "set" && op != "remove" {
		return ctlRequest{}, fmt.Errorf("unknown relationships subcommand %q", op)
	}
	if err := require(v, "resource-type", "resource-id", "relation"); err != nil {
		return ctlRequest{}, err
	}
	if op == "set" && len(targets) == 0 {
		return ctlRequest{}, errors.New("at least one --target is required")
	}
	if op == "set" && b["all"] {
		return ctlRequest{}, errors.New("relationships set does not accept --all")
	}
	if op == "remove" && ((len(targets) > 0) == b["all"]) {
		return ctlRequest{}, errors.New("use either one or more --target flags or --all")
	}
	refs := make([]api.ResourceRef, 0, len(targets))
	for _, target := range targets {
		ref, err := parseTarget(target)
		if err != nil {
			return ctlRequest{}, err
		}
		refs = append(refs, ref)
	}
	p := path("v1", "manage", "resources", v.get("resource-type"), v.get("resource-id"), "relationships", v.get("relation"))
	if op == "set" {
		return jsonRequest(http.MethodPut, p, relationshipBody(refs), "none"), nil
	}
	if b["all"] {
		return ctlRequest{method: http.MethodDelete, path: p, result: "none"}, nil
	}
	return jsonRequest(http.MethodDelete, p, relationshipBody(refs), "none"), nil
}

func buildGroup(o *ctlOptions, op string, args []string) (ctlRequest, error) {
	flags := []string{"id"}
	if op == "create" {
		flags = append(flags, "display-name")
	}
	if op == "add-member" || op == "remove-member" {
		flags = append(flags, "principal-source", "principal-subject", "group")
	}
	bools := []string{}
	if op == "delete" {
		bools = []string{"yes"}
	}
	v, b, err := parseCommand("groups "+op, args, flags, bools, nil)
	if err != nil {
		return ctlRequest{}, err
	}
	if err := require(v, "id"); err != nil {
		return ctlRequest{}, err
	}
	p := path("v1", "manage", "groups", v.get("id"))
	switch op {
	case "create":
		body := map[string]any{"id": v.get("id")}
		if v.set["display-name"] {
			body["display_name"] = v.get("display-name")
		}
		return jsonRequest(http.MethodPost, "/v1/manage/groups", body, "group"), nil
	case "get":
		return jsonRequest(http.MethodGet, p, nil, "group"), nil
	case "delete":
		if !b["yes"] {
			if err := o.confirmDelete("group " + v.get("id")); err != nil {
				return ctlRequest{}, err
			}
		}
		return jsonRequest(http.MethodDelete, p, nil, "none"), nil
	case "add-member", "remove-member":
		subject, err := parseSubject(v)
		if err != nil {
			return ctlRequest{}, err
		}
		method := http.MethodPost
		if op == "remove-member" {
			method = http.MethodDelete
		}
		return jsonRequest(method, p+"/members", api.MembershipRequest{Member: subject}, "none"), nil
	default:
		return ctlRequest{}, fmt.Errorf("unknown groups subcommand %q", op)
	}
}

func buildGrant(o *ctlOptions, op string, args []string) (ctlRequest, error) {
	flags := []string{"id"}
	if op == "create" {
		flags = append(flags, "principal-source", "principal-subject", "group", "role", "resource-type", "resource-id")
	}
	bools := []string{}
	if op == "create" {
		bools = []string{"create-resource-if-missing"}
	} else if op == "delete" {
		bools = []string{"yes"}
	}
	v, b, err := parseCommand("grants "+op, args, flags, bools, nil)
	if err != nil {
		return ctlRequest{}, err
	}
	switch op {
	case "list":
		if v.set["id"] {
			return ctlRequest{}, errors.New("grants list does not accept --id")
		}
		return jsonRequest(http.MethodGet, "/v1/manage/grants", nil, "grants"), nil
	case "delete":
		if err := require(v, "id"); err != nil {
			return ctlRequest{}, err
		}
		if !b["yes"] {
			if err := o.confirmDelete("grant " + v.get("id")); err != nil {
				return ctlRequest{}, err
			}
		}
		return jsonRequest(http.MethodDelete, path("v1", "manage", "grants", v.get("id")), nil, "none"), nil
	case "create":
		if err := require(v, "role", "resource-type", "resource-id"); err != nil {
			return ctlRequest{}, err
		}
		if v.set["id"] && v.get("id") == "" {
			return ctlRequest{}, errors.New("--id must not be empty when supplied")
		}
		subject, err := parseSubject(v)
		if err != nil {
			return ctlRequest{}, err
		}
		grant := api.Grant{ID: v.get("id"), Subject: subject, Role: v.get("role"), Resource: api.ResourceRef{Type: v.get("resource-type"), ID: v.get("resource-id")}, CreateResourceIfMissing: b["create-resource-if-missing"]}
		return jsonRequest(http.MethodPost, "/v1/manage/grants", grant, "grant"), nil
	default:
		return ctlRequest{}, fmt.Errorf("unknown grants subcommand %q", op)
	}
}

func buildCheck(o *ctlOptions, args []string) (ctlRequest, error) {
	v, _, err := parseCommand("check", args, []string{"permission", "resource-type", "resource-id", "id", "file"}, nil, nil)
	if err != nil {
		return ctlRequest{}, err
	}
	var request api.CheckRequest
	if v.set["file"] {
		if v.set["permission"] || v.set["resource-type"] || v.set["resource-id"] || v.set["id"] {
			return ctlRequest{}, errors.New("--file is mutually exclusive with single-check flags")
		}
		raw, err := o.readValue(v.get("file"), "check request")
		if err != nil {
			return ctlRequest{}, err
		}
		if err := decodeExactJSON(raw, &request); err != nil {
			return ctlRequest{}, fmt.Errorf("invalid check request JSON: %w", err)
		}
	} else {
		if err := require(v, "permission", "resource-type", "resource-id"); err != nil {
			return ctlRequest{}, err
		}
		id := "check-1"
		if v.set["id"] {
			if v.get("id") == "" {
				return ctlRequest{}, errors.New("--id must not be empty")
			}
			id = v.get("id")
		}
		request.Checks = []api.Check{{ID: id, Permission: v.get("permission"), Resource: api.ResourceRef{Type: v.get("resource-type"), ID: v.get("resource-id")}}}
	}
	if len(request.Checks) == 0 {
		return ctlRequest{}, errors.New("checks must contain at least one item")
	}
	for i, check := range request.Checks {
		if check.ID == "" || check.Permission == "" || check.Resource.Type == "" || check.Resource.ID == "" {
			return ctlRequest{}, fmt.Errorf("check %d requires non-empty id, permission, resource type, and resource id", i+1)
		}
	}
	return jsonRequest(http.MethodPost, "/v1/check", request, "checks"), nil
}

func buildTokenExchange(o *ctlOptions, args []string) (ctlRequest, error) {
	v, _, err := parseCommand("token exchange", args, []string{"subject-token", "subject-token-file", "audience", "actor-token", "actor-token-file"}, nil, nil)
	if err != nil {
		return ctlRequest{}, err
	}
	if err := require(v, "audience"); err != nil {
		return ctlRequest{}, err
	}
	subject, err := oneValue(o, v, "subject-token", "subject-token-file", true)
	if err != nil {
		return ctlRequest{}, err
	}
	actor, err := oneValue(o, v, "actor-token", "actor-token-file", false)
	if err != nil {
		return ctlRequest{}, err
	}
	form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {subject}, "subject_token_type": {jwtTokenType}, "audience": {v.get("audience")}}
	if actor != "" {
		form.Set("actor_token", actor)
		form.Set("actor_token_type", jwtTokenType)
	}
	return ctlRequest{http.MethodPost, "/oauth2/token", "application/x-www-form-urlencoded", []byte(form.Encode()), "token"}, nil
}

func (o *ctlOptions) readValue(source, label string) (string, error) {
	if source == "" {
		return "", fmt.Errorf("%s path must not be empty", label)
	}
	if source == "-" {
		if o.stdinUsed {
			return "", errors.New("at most one input option may read standard input")
		}
		o.stdinUsed = true
		raw, err := io.ReadAll(o.stdin)
		if err != nil {
			return "", fmt.Errorf("read %s from standard input: %w", label, err)
		}
		return string(raw), nil
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	return string(raw), nil
}

func (o *ctlOptions) confirmDelete(label string) error {
	file, ok := o.stdin.(*os.File)
	if !ok {
		return errors.New("--yes is required when standard input is not interactive")
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("--yes is required when standard input is not interactive")
	}
	fmt.Fprintf(o.stderr, "Delete %s? [y/N] ", label)
	answer, err := bufio.NewReader(o.stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read confirmation: %w", err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return errors.New("deletion cancelled")
	}
	return nil
}
func require(v *trackedStrings, names ...string) error {
	for _, name := range names {
		if !v.set[name] || v.get(name) == "" {
			return fmt.Errorf("--%s is required and must not be empty", name)
		}
	}
	return nil
}
func parseSubject(v *trackedStrings) (api.Subject, error) {
	principal := v.set["principal-source"] || v.set["principal-subject"]
	group := v.set["group"]
	if principal == group {
		return api.Subject{}, errors.New("use exactly one complete principal or group subject")
	}
	if group {
		if v.get("group") == "" {
			return api.Subject{}, errors.New("--group must not be empty")
		}
		return api.Subject{Type: "group", Group: v.get("group")}, nil
	}
	if err := require(v, "principal-source", "principal-subject"); err != nil {
		return api.Subject{}, err
	}
	return api.Subject{Type: "principal", Source: v.get("principal-source"), Subject: v.get("principal-subject")}, nil
}
func parseTarget(value string) (api.ResourceRef, error) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return api.ResourceRef{}, fmt.Errorf("target %q must use non-empty TYPE:ID syntax", value)
	}
	return api.ResourceRef{Type: parts[0], ID: parts[1]}, nil
}
func parseInitialRelationships(values []string) (map[string][]api.ResourceRef, error) {
	result := map[string][]api.ResourceRef{}
	for _, value := range values {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("relationship %q must use RELATION=TYPE:ID syntax", value)
		}
		target, err := parseTarget(parts[1])
		if err != nil {
			return nil, err
		}
		result[parts[0]] = append(result[parts[0]], target)
	}
	return result, nil
}
func relationshipBody(refs []api.ResourceRef) any {
	if len(refs) == 1 {
		return map[string]any{"target": refs[0]}
	}
	return map[string]any{"targets": refs}
}
func oneValue(o *ctlOptions, v *trackedStrings, inline, file string, required bool) (string, error) {
	if v.set[inline] && v.set[file] {
		return "", fmt.Errorf("--%s and --%s are mutually exclusive", inline, file)
	}
	if !v.set[inline] && !v.set[file] {
		if required {
			return "", fmt.Errorf("one of --%s or --%s is required", inline, file)
		}
		return "", nil
	}
	value := v.get(inline)
	var err error
	if v.set[file] {
		value, err = o.readValue(v.get(file), strings.ReplaceAll(inline, "-", " "))
		if err != nil {
			return "", err
		}
		value = trimLine(value)
	}
	if value == "" {
		return "", fmt.Errorf("--%s value must not be empty", inline)
	}
	return value, nil
}
func jsonObject(raw, label string) (map[string]any, error) {
	var value map[string]any
	if err := decodeExactJSON(raw, &value); err != nil {
		return nil, fmt.Errorf("invalid %s JSON object: %w", label, err)
	}
	if value == nil {
		return nil, fmt.Errorf("%s must be a JSON object", label)
	}
	return value, nil
}
func decodeExactJSON(raw string, dst any) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
func ttlSeconds(value string) (int64, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration%time.Second != 0 {
		return 0, errors.New("--token-ttl must be a positive duration resolving to whole seconds")
	}
	return int64(duration / time.Second), nil
}
func validDelegationMode(value string) bool {
	switch value {
	case "disabled", "subject", "intersection", "actor", "union":
		return true
	}
	return false
}
func validRequestID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
func path(segments ...string) string {
	escaped := make([]string, len(segments))
	for i, s := range segments {
		escaped[i] = url.PathEscape(s)
	}
	return "/" + strings.Join(escaped, "/")
}
func trimLine(value string) string {
	if strings.HasSuffix(value, "\r\n") {
		return strings.TrimSuffix(value, "\r\n")
	}
	return strings.TrimSuffix(value, "\n")
}
func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func formatAPIError(response *http.Response, raw []byte) error {
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) == nil && envelope.Error.Message != "" {
		id := envelope.Error.RequestID
		if id == "" {
			id = response.Header.Get("X-Request-ID")
		}
		details := envelope.Error.Message
		if envelope.Error.Code != "" {
			details = envelope.Error.Code + ": " + details
		}
		if id != "" {
			details += " (request_id=" + id + ")"
		}
		return fmt.Errorf("HTTP %s: %s", response.Status, details)
	}
	message := strings.TrimSpace(string(raw))
	if message == "" {
		message = http.StatusText(response.StatusCode)
	}
	return fmt.Errorf("HTTP %s: %s", response.Status, message)
}
func ctlUsage() string {
	return `authservicecentral ctl — remote HTTP API client

Usage:
  authservicecentral ctl [common flags] <command> [subcommand] [command flags]

Commands:
  token exchange
  check
  audiences create|list|get|update|delete
  resources create|get|update|delete
  relationships set|remove
  groups create|get|delete|add-member|remove-member
  grants create|list|delete

Common flags:
  --server URL  --token TOKEN  --token-file PATH  --timeout DURATION
  --output table|json  --request-id ID  -h|--help`
}

func ctlCommandUsage(command string) string {
	usage := map[string]string{
		"token exchange":   "(--subject-token JWT | --subject-token-file PATH) --audience ID [--actor-token JWT | --actor-token-file PATH]",
		"check":            "(--permission PERMISSION --resource-type TYPE --resource-id ID [--id ID] | --file PATH)",
		"audiences create": "--id ID --token-ttl DURATION [--display-name NAME] [--delegation-mode MODE]",
		"audiences list":   "", "audiences get": "--id ID", "audiences update": "--id ID [--display-name NAME] [--token-ttl DURATION] [--delegation-mode MODE]", "audiences delete": "--id ID [--yes]",
		"resources create": "--type TYPE --id ID [--metadata JSON | --metadata-file PATH] [--relationship RELATION=TYPE:ID ...]",
		"resources get":    "--type TYPE --id ID", "resources update": "--type TYPE --id ID (--metadata JSON | --metadata-file PATH)", "resources delete": "--type TYPE --id ID [--yes]",
		"relationships set":    "--resource-type TYPE --resource-id ID --relation RELATION --target TYPE:ID [--target TYPE:ID ...]",
		"relationships remove": "--resource-type TYPE --resource-id ID --relation RELATION (--target TYPE:ID [...] | --all)",
		"groups create":        "--id ID [--display-name NAME]", "groups get": "--id ID", "groups delete": "--id ID [--yes]",
		"groups add-member": "--id ID (--principal-source SOURCE --principal-subject SUBJECT | --group GROUP_ID)", "groups remove-member": "--id ID (--principal-source SOURCE --principal-subject SUBJECT | --group GROUP_ID)",
		"grants create": "(--principal-source SOURCE --principal-subject SUBJECT | --group GROUP_ID) --role ROLE --resource-type TYPE --resource-id ID [--id ID] [--create-resource-if-missing]",
		"grants list":   "", "grants delete": "--id ID [--yes]",
	}
	flags, ok := usage[command]
	if !ok {
		return ctlUsage()
	}
	line := "authservicecentral ctl [common flags] " + command
	if flags != "" {
		line += " " + flags
	}
	return "Usage:\n  " + line + "\n\nSee docs/ctl for command details and examples."
}
