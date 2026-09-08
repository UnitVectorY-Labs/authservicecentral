---
layout: default
title: groups get
parent: Command-line client
nav_order: 15
permalink: /ctl/groups-get
---

# `authservicecentral ctl groups get`

Get one runtime group through `GET /v1/manage/groups/{id}`. The management token requires the configured `groups.read` permission, conventionally `management.groups.read`.

See [the `ctl` overview](../CTL.md) for common flags.

## Usage

```text
authservicecentral ctl [common flags] groups get --id ID
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Runtime group identifier. |

## Example

```bash
authservicecentral ctl --token "$MANAGEMENT_TOKEN" groups get --id engineering
```

The default table contains `ID` and `DISPLAY_NAME`. The current API response does not include group membership; memberships are changed with `groups add-member` and `groups remove-member`.
