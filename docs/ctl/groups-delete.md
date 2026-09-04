# `authservicecentral ctl groups delete`

Idempotently delete a group and its associated authorization state through `DELETE /v1/manage/groups/{id}`. The management token requires the configured `groups.write` permission, conventionally `management.groups.write`.

See [the `ctl` overview](../CTL.md) for common flags and destructive-command behavior.

## Usage

```text
authservicecentral ctl [common flags] groups delete --id ID [--yes]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--id ID` | yes | none | Runtime group identifier. |
| `--yes` | no | false | Skip interactive confirmation. Required for non-interactive use. |

## Example

```bash
authservicecentral ctl --token-file ./management.jwt groups delete \
  --id engineering --yes
```

A successful deletion, including an already-absent group, writes no standard output.
