---
layout: default
title: resources delete
parent: Command-line client
nav_order: 11
permalink: /ctl/resources-delete
---

# `authservicecentral ctl resources delete`

Idempotently delete a resource, its catalog state, associated grants, and relationships through `DELETE /v1/manage/resources/{type}/{id}`. The management token requires the configured `resources.write` permission, conventionally `management.resources.write`.

See [the `ctl` overview](../CTL.md) for common flags and destructive-command behavior.

## Usage

```text
authservicecentral ctl [common flags] resources delete \
  --type TYPE --id ID [--yes]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--type TYPE` | yes | none | YAML-defined resource type. Audiences and groups use their dedicated deletion commands. |
| `--id ID` | yes | none | Runtime resource identifier. |
| `--yes` | no | false | Skip interactive confirmation. Required for non-interactive use. |

## Example

```bash
authservicecentral ctl --token-file ./management.jwt resources delete \
  --type document --id report-123 --yes
```

A successful deletion, including an already-absent resource, writes no standard output.
