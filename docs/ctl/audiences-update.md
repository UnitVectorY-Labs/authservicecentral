---
layout: default
title: audiences update
parent: Command-line client
nav_order: 6
permalink: /ctl/audiences-update
---

# `authservicecentral ctl audiences update`

Partially update a runtime audience through `PATCH /v1/manage/audiences/{id}`. The management token requires the configured `audiences.write` permission, conventionally `management.audiences.write`.

See [the `ctl` overview](../CTL.md) for common flags.

## Usage

```text
authservicecentral ctl [common flags] audiences update --id ID \
  [--display-name NAME] [--token-ttl DURATION] [--delegation-mode MODE]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Audience identifier. |
| `--display-name NAME` | no | unchanged | Replace the display name. An explicitly supplied empty value clears it. |
| `--token-ttl DURATION` | no | unchanged | Replace the token lifetime with a positive duration resolving to whole seconds. |
| `--delegation-mode MODE` | no | unchanged | Replace delegation mode with `disabled`, `subject`, `intersection`, `actor`, or `union`. |

At least one update flag is required. Omitted fields are not sent and retain their current values.

## Example

```bash
authservicecentral ctl --token-file ./management.jwt audiences update \
  --id documents-api --token-ttl 10m --delegation-mode disabled
```

The default table contains the complete updated audience.
