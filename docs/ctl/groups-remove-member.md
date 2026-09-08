---
layout: default
title: groups remove-member
parent: Command-line client
nav_order: 18
permalink: /ctl/groups-remove-member
---

# `authservicecentral ctl groups remove-member`

Remove an exact principal or nested group membership through `DELETE /v1/manage/groups/{id}/members`. The management token requires the configured `groups.write` permission, conventionally `management.groups.write`.

See [the `ctl` overview](../CTL.md) for common flags and subject-selection rules.

## Usage

```text
authservicecentral ctl [common flags] groups remove-member --id ID \
  (--principal-source SOURCE --principal-subject SUBJECT | --group GROUP_ID)
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Parent group containing the member. |
| `--principal-source SOURCE` | conditional | none | Configured token-source identity prefix for a principal member. Requires `--principal-subject`. |
| `--principal-subject SUBJECT` | conditional | none | External subject identifier for a principal member. Requires `--principal-source`. |
| `--group GROUP_ID` | conditional | none | Nested group member to remove. Mutually exclusive with principal flags. |

Exactly one complete member form is required. Unlike group deletion, removing an absent membership returns an API error.

## Example

```bash
authservicecentral ctl --token-file ./management.jwt groups remove-member \
  --id engineering \
  --principal-source corporate \
  --principal-subject alice
```

A successful removal writes no standard output.
