# `authservicecentral ctl relationships remove`

Remove selected targets or all targets of one relationship through `DELETE /v1/manage/resources/{type}/{id}/relationships/{relation}`. The management token requires the configured `resources.write` permission, conventionally `management.resources.write`.

See [the `ctl` overview](../CTL.md) for common flags and `TYPE:ID` syntax.

## Usage

```text
authservicecentral ctl [common flags] relationships remove \
  --resource-type TYPE --resource-id ID --relation RELATION \
  (--target TYPE:ID [--target TYPE:ID ...] | --all)
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--resource-type TYPE` | yes | none | Type of the source resource. |
| `--resource-id ID` | yes | none | ID of the source resource. |
| `--relation RELATION` | yes | none | YAML-defined relationship name on the source resource type. |
| `--target TYPE:ID` | conditional | none | Exact target to remove. Repeat to remove several targets. Mutually exclusive with `--all`. |
| `--all` | conditional | false | Explicitly remove every target for the named relationship. Mutually exclusive with `--target`. |

One or more `--target` flags or `--all` is required. The server rejects removal that would violate a required relationship.

## Example

```bash
authservicecentral ctl --token-file ./management.jwt relationships remove \
  --resource-type document --resource-id report-123 \
  --relation reviewer --target group:contractors
```

A successful removal writes no standard output.
