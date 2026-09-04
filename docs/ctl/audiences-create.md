# `authservicecentral ctl audiences create`

Create or replace a runtime audience through `POST /v1/manage/audiences`. The management token requires the configured `audiences.write` permission, conventionally `management.audiences.write`.

This is an upsert operation: an existing audience with the same ID is replaced. See [the `ctl` overview](../CTL.md) for common flags.

## Usage

```text
authservicecentral ctl [common flags] audiences create \
  --id ID --token-ttl DURATION \
  [--display-name NAME] [--delegation-mode MODE]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Stable audience identifier requested by token-exchange callers. |
| `--token-ttl DURATION` | yes | none | Positive token lifetime resolving to a whole number of seconds. |
| `--display-name NAME` | no | empty | Human-readable operator display name. |
| `--delegation-mode MODE` | no | `disabled` | One of `disabled`, `subject`, `intersection`, `actor`, or `union`. The API `enabled` value is derived as false only for `disabled`. |

## Example

```bash
authservicecentral ctl --token-file ./management.jwt audiences create \
  --id documents-api \
  --display-name "Documents API" \
  --token-ttl 15m \
  --delegation-mode intersection
```

The default table contains `ID`, `DISPLAY_NAME`, `TOKEN_TTL_SECONDS`, and `DELEGATION_MODE`.
