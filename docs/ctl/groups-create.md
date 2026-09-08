---
layout: default
title: groups create
parent: Command-line client
nav_order: 14
permalink: /ctl/groups-create
---

# `authservicecentral ctl groups create`

Create a runtime group through `POST /v1/manage/groups`. The management token requires the configured `groups.write` permission, conventionally `management.groups.write`.

See [the `ctl` overview](../CTL.md) for common flags.

## Usage

```text
authservicecentral ctl [common flags] groups create \
  --id ID [--display-name NAME]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Stable runtime group identifier. |
| `--display-name NAME` | no | empty | Human-readable group name. |

## Example

```bash
authservicecentral ctl --token-file ./management.jwt groups create \
  --id engineering --display-name Engineering
```

The default table contains `ID` and `DISPLAY_NAME`.
