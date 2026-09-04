# `authservicecentral ctl relationships set`

Replace all targets of one resource relationship through `PUT /v1/manage/resources/{type}/{id}/relationships/{relation}`. The management token requires the configured `resources.write` permission, conventionally `management.resources.write`.

See [the `ctl` overview](../CTL.md) for common flags and `TYPE:ID` syntax.

## Usage

```text
authservicecentral ctl [common flags] relationships set \
  --resource-type TYPE --resource-id ID --relation RELATION \
  --target TYPE:ID [--target TYPE:ID ...]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--resource-type TYPE` | yes | none | Type of the source resource. |
| `--resource-id ID` | yes | none | ID of the source resource. |
| `--relation RELATION` | yes | none | YAML-defined relationship name on the source resource type. |
| `--target TYPE:ID` | yes | none | Complete desired target set. Repeat for a many-cardinality relationship. |

This is replacement, not additive, behavior. Existing targets not named by `--target` are removed. Cardinality, allowed target types, target existence, and required-relationship rules are enforced by the server.

## Example

```bash
authservicecentral ctl --token-file ./management.jwt relationships set \
  --resource-type document --resource-id report-123 \
  --relation parent --target folder:finance
```

A successful update writes no standard output.
