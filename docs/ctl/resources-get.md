---
layout: default
title: resources get
parent: Command-line client
nav_order: 9
permalink: /ctl/resources-get
---

# `authservicecentral ctl resources get`

Get a configured resource, its metadata, and relationships through `GET /v1/manage/resources/{type}/{id}`. The management token requires the configured `resources.read` permission, conventionally `management.resources.read`.

See [the `ctl` overview](../CTL.md) for common flags.

## Usage

```text
authservicecentral ctl [common flags] resources get --type TYPE --id ID
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--type TYPE` | yes | none | YAML-defined resource type. |
| `--id ID` | yes | none | Runtime resource identifier. |

## Example

```bash
authservicecentral ctl --token "$MANAGEMENT_TOKEN" resources get \
  --type document --id report-123
```

The default table prints the resource and metadata followed by a relationship table when relationships are present.
