# `authservicecentral ctl audiences delete`

Idempotently delete an audience and its associated authorization state through `DELETE /v1/manage/audiences/{id}`. The management token requires the configured `audiences.write` permission, conventionally `management.audiences.write`.

See [the `ctl` overview](../CTL.md) for common flags and destructive-command behavior.

## Usage

```text
authservicecentral ctl [common flags] audiences delete --id ID [--yes]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Audience identifier. |
| `--yes` | no | false | Skip interactive confirmation. Required for non-interactive use. |

## Example

```bash
authservicecentral ctl --token-file ./management.jwt audiences delete \
  --id documents-api --yes
```

A successful deletion, including an already-absent audience, writes no standard output.
