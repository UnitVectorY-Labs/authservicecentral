---
layout: default
title: Command-line client
nav_order: 3
has_children: true
permalink: /ctl
---

# `authservicecentral ctl`

`authservicecentral ctl` controls a running authservicecentral deployment through its public HTTP API. It is bundled into the service executable for convenient installation and synchronized releases, but behaves as a remote client: it never reads deployment YAML, connects directly to PostgreSQL, calls internal service methods, or accesses embedded OpenFGA.

The local lifecycle commands (`run`, `migrate`, `bootstrap`, `validate`, `model`, `doctor`, and `config-docs`) remain top-level commands. Every remote client operation is nested below `ctl`.

## Invocation

```text
authservicecentral ctl [common flags] <command> [subcommand] [command flags]
```

Common flags must appear after `ctl` and before the command name. Command-specific flags follow the complete command path. Values are passed as flags rather than positional arguments so invocations remain explicit and scripts are readable.

Examples:

```bash
authservicecentral ctl --server https://auth.example.com audiences list
authservicecentral ctl --output json resources get --type document --id report-123
authservicecentral ctl --token-file ./management.jwt groups create \
  --id engineering --display-name Engineering
```

## Command tree

| Command | API operation | Documentation |
|---|---|---|
| `ctl token exchange` | Exchange a trusted JWT for a platform token. | [token exchange](ctl/token-exchange.md) |
| `ctl check` | Evaluate one check or an exact JSON batch. | [check](ctl/check.md) |
| `ctl audiences create` | Create or replace an audience. | [audiences create](ctl/audiences-create.md) |
| `ctl audiences list` | List audiences. | [audiences list](ctl/audiences-list.md) |
| `ctl audiences get` | Get one audience. | [audiences get](ctl/audiences-get.md) |
| `ctl audiences update` | Partially update an audience. | [audiences update](ctl/audiences-update.md) |
| `ctl audiences delete` | Delete an audience. | [audiences delete](ctl/audiences-delete.md) |
| `ctl resources create` | Create a resource and optional relationships. | [resources create](ctl/resources-create.md) |
| `ctl resources get` | Get one resource. | [resources get](ctl/resources-get.md) |
| `ctl resources update` | Replace resource metadata. | [resources update](ctl/resources-update.md) |
| `ctl resources delete` | Delete a resource and its authorization state. | [resources delete](ctl/resources-delete.md) |
| `ctl relationships set` | Replace the targets of a relationship. | [relationships set](ctl/relationships-set.md) |
| `ctl relationships remove` | Remove selected or all relationship targets. | [relationships remove](ctl/relationships-remove.md) |
| `ctl groups create` | Create a group. | [groups create](ctl/groups-create.md) |
| `ctl groups get` | Get one group. | [groups get](ctl/groups-get.md) |
| `ctl groups delete` | Delete a group. | [groups delete](ctl/groups-delete.md) |
| `ctl groups add-member` | Add a principal or nested group member. | [groups add-member](ctl/groups-add-member.md) |
| `ctl groups remove-member` | Remove an exact group member. | [groups remove-member](ctl/groups-remove-member.md) |
| `ctl grants create` | Create a resource-scoped role grant. | [grants create](ctl/grants-create.md) |
| `ctl grants list` | List grants. | [grants list](ctl/grants-list.md) |
| `ctl grants delete` | Delete a grant. | [grants delete](ctl/grants-delete.md) |

The `ctl` surface intentionally excludes discovery documents, JWKS, liveness, readiness, metrics, Swagger UI, and the OpenAPI document. Those remain HTTP and operational integration surfaces described in [API.md](API.md).

## Common flags and environment variables

Precedence is command-line flag, environment variable, then default. An explicitly supplied but empty flag is invalid; it does not fall through to the environment. Command-specific API attributes do not have environment-variable equivalents.

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--server URL` | `SERVICEAUTH_CTL_SERVER` | `http://localhost:8080` | Deployment base URL. It must be an absolute `http` or `https` URL without user information, query, or fragment. A trailing slash is ignored. |
| `--token TOKEN` | `SERVICEAUTH_CTL_TOKEN` | none | Bearer token used by `check` and management commands. Prefer the environment or `--token-file` so the token is not exposed in process listings or shell history. |
| `--token-file PATH` | none | none | Read the bearer token from a file. `-` reads it from standard input. Mutually exclusive with `--token`; when set, it takes precedence over `SERVICEAUTH_CTL_TOKEN`. One trailing line ending is removed. |
| `--timeout DURATION` | `SERVICEAUTH_CTL_TIMEOUT` | `30s` | Maximum duration for the complete HTTP request. Uses Go duration syntax and must be positive. |
| `--output FORMAT` | none | `table` | Success output format: `table` or `json`. |
| `--request-id ID` | none | generated by the service | Send `X-Request-ID`. IDs must be 1–128 ASCII letters, digits, `-`, `_`, or `.`. |
| `-h`, `--help` | none | false | Print help for the selected command without making a request. |

`ctl check` requires a bearer token, which must be an application-audience platform token. Audience, resource, relationship, group, and grant commands send the resolved bearer token when one is available; production deployments require a management-audience platform token with the route permission. Omitting it is useful only against an isolated development server started with `--insecure-management`. `ctl token exchange` does not use the common bearer token.

The client uses the operating system trust store for HTTPS. The contract deliberately has no option to skip certificate verification.

## Command-value conventions

Durations use Go duration syntax such as `30s`, `15m`, or `1h`. Audience token TTLs must resolve to a positive whole number of seconds because the API stores seconds.

JSON-valued flags accept one complete JSON value. A corresponding `*-file` flag accepts a path or `-` for standard input and is mutually exclusive with the inline flag. Input is validated locally as JSON before a request is sent, while schema and authorization validation remain authoritative at the server.

At most one input option in an invocation may use `-`; the client does not attempt to divide standard input among a bearer token and command data. Boolean flags such as `--yes`, `--all`, and `--create-resource-if-missing` are enabled by their presence and do not take a value.

Resource targets use `TYPE:ID`, for example `folder:finance`. The first colon separates the configured resource type from its ID; the ID may contain additional colons. Both parts must be non-empty.

Commands that accept a subject use exactly one of these forms:

```text
--principal-source SOURCE --principal-subject SUBJECT
--group GROUP_ID
```

The two principal flags are required together and cannot be combined with `--group`.

## Output

Human-readable table output is the default. Tables have stable uppercase column headings, but their spacing is presentation and must not be parsed by scripts. `--output json` writes the successful API response body as JSON without renaming or omitting fields. Commands backed by a successful `204 No Content` response write nothing to standard output in either format.

Diagnostics, validation failures, and API error messages go to standard error. Tokens are never written to diagnostics. API errors include the HTTP status, error code, message, and request ID when present. The client does not retry mutations automatically; callers can use the API's documented idempotency behavior when retrying after an uncertain result.

## Exit status

| Status | Meaning |
|---:|---|
| `0` | The request succeeded. A valid authorization result of `allowed: false` is still success. |
| `1` | The request failed because of networking, timeout, authentication, authorization, server, or other API failure. |
| `2` | Invocation, flag, environment, local file, or local JSON validation failed before a request was made. |

## Destructive commands

Audience, resource, group, and grant deletion prompts for confirmation when standard input is an interactive terminal. Pass the command-specific `--yes` flag to skip the prompt. A non-interactive invocation without `--yes` fails locally with exit status `2`. Relationship removal is explicit through one or more `--target` flags or `--all` and does not prompt.

## API synchronization

[openapi.yaml](../openapi.yaml) and [API.md](API.md) remain authoritative for HTTP methods, paths, payloads, and response schemas. `CTL.md` and every page below `docs/ctl/` are authoritative for command names, flag mapping, output, and exit behavior. An API change affecting a supported operation must update all of these surfaces in the same change.
