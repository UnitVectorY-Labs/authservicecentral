---
layout: default
title: token exchange
parent: Command-line client
nav_order: 1
permalink: /ctl/token-exchange
---

# `authservicecentral ctl token exchange`

Exchange a JWT from a configured trusted token source for a short-lived, audience-scoped platform token through `POST /oauth2/token`.

See [the `ctl` overview](../CTL.md) for common flags and conventions.

## Usage

```text
authservicecentral ctl [common flags] token exchange \
  (--subject-token JWT | --subject-token-file PATH) \
  --audience ID \
  [--actor-token JWT | --actor-token-file PATH]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--subject-token JWT` | conditional | none | Trusted external JWT to exchange. Mutually exclusive with `--subject-token-file`. |
| `--subject-token-file PATH` | conditional | none | Read the trusted external JWT from a file, or from standard input with `-`. Mutually exclusive with `--subject-token`. One subject-token source is required. |
| `--audience ID` | yes | none | Existing runtime audience for the issued platform token. |
| `--actor-token JWT` | no | none | Trusted external JWT for delegated exchange. Mutually exclusive with `--actor-token-file`. |
| `--actor-token-file PATH` | no | none | Read the delegated actor JWT from a file, or from standard input with `-`. Mutually exclusive with `--actor-token`. |

The OAuth grant type and subject/actor token types are fixed to their RFC 8693 JWT values and are not configurable flags. Actor-token options request delegated exchange and are valid only when the target audience enables delegation. The subject and actor token files cannot both be `-`.

The common `--token` and `--token-file` flags are not used by this command. Inline JWT flags are supported for direct use, but files are preferable because command arguments can be visible in process listings and shell history.

## Examples

```bash
authservicecentral ctl token exchange \
  --subject-token-file ./external.jwt \
  --audience documents-api
```

```bash
authservicecentral ctl --output json token exchange \
  --subject-token-file ./subject.jwt \
  --actor-token-file ./actor.jwt \
  --audience documents-api
```

The default table contains `ACCESS_TOKEN`, `TOKEN_TYPE`, and `EXPIRES_IN` columns. JSON output preserves `access_token`, `issued_token_type`, `token_type`, and `expires_in`. Handle either output as secret material.
