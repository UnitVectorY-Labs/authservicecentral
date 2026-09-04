# `authservicecentral ctl grants delete`

Idempotently delete a resource-scoped role grant through `DELETE /v1/manage/grants/{id}`. The management token requires the configured `grants.write` permission, conventionally `management.grants.write`.

See [the `ctl` overview](../CTL.md) for common flags and destructive-command behavior.

## Usage

```text
authservicecentral ctl [common flags] grants delete --id ID [--yes]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Grant identifier. |
| `--yes` | no | false | Skip interactive confirmation. Required for non-interactive use. |

## Example

```bash
authservicecentral ctl --token-file ./management.jwt grants delete \
  --id grant-123 --yes
```

A successful deletion, including an already-absent grant, writes no standard output.
