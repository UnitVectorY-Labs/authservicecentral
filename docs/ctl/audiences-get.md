---
layout: default
title: audiences get
parent: Command-line client
nav_order: 5
permalink: /ctl/audiences-get
---

# `authservicecentral ctl audiences get`

Get one runtime audience through `GET /v1/manage/audiences/{id}`. The management token requires the configured `audiences.read` permission, conventionally `management.audiences.read`.

See [the `ctl` overview](../CTL.md) for common flags.

## Usage

```text
authservicecentral ctl [common flags] audiences get --id ID
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Audience identifier. |

## Example

```bash
authservicecentral ctl --token "$MANAGEMENT_TOKEN" audiences get --id documents-api
```

The default table contains `ID`, `DISPLAY_NAME`, `TOKEN_TTL_SECONDS`, and `DELEGATION_MODE`.
