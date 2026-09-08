---
layout: default
title: groups add-member
parent: Command-line client
nav_order: 17
permalink: /ctl/groups-add-member
---

# `authservicecentral ctl groups add-member`

Add a principal or nested group to a runtime group through `POST /v1/manage/groups/{id}/members`. The management token requires the configured `groups.write` permission, conventionally `management.groups.write`.

See [the `ctl` overview](../CTL.md) for common flags and subject-selection rules.

## Usage

```text
authservicecentral ctl [common flags] groups add-member --id ID \
  (--principal-source SOURCE --principal-subject SUBJECT | --group GROUP_ID)
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Parent group receiving the member. |
| `--principal-source SOURCE` | conditional | none | Configured token-source identity prefix for a principal member. Requires `--principal-subject`. |
| `--principal-subject SUBJECT` | conditional | none | External subject identifier for a principal member. Requires `--principal-source`. |
| `--group GROUP_ID` | conditional | none | Existing group to add as a nested member. Mutually exclusive with principal flags. |

Exactly one complete member form is required. Both the parent and member group must exist before adding a nested group, and the server rejects membership cycles.

## Examples

```bash
authservicecentral ctl --token-file ./management.jwt groups add-member \
  --id engineering \
  --principal-source corporate \
  --principal-subject alice
```

```bash
authservicecentral ctl --token-file ./management.jwt groups add-member \
  --id engineering --group platform-team
```

A successful addition writes no standard output.
