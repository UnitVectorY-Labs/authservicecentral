# `authservicecentral ctl resources create`

Create a configured resource, optional metadata, and optional initial relationships through `POST /v1/manage/resources`. The management token requires the configured `resources.write` permission, conventionally `management.resources.write`.

See [the `ctl` overview](../CTL.md) for common flags and resource-target syntax.

## Usage

```text
authservicecentral ctl [common flags] resources create \
  --type TYPE --id ID \
  [--metadata JSON | --metadata-file PATH] \
  [--relationship RELATION=TYPE:ID ...]
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--type TYPE` | yes | none | Resource type declared in deployment YAML. Intrinsic `audience` and `group` resources use their dedicated commands. |
| `--id ID` | yes | none | Caller-defined runtime resource identifier. |
| `--metadata JSON` | no | omitted | Complete JSON object stored as non-authoritative metadata. Mutually exclusive with `--metadata-file`. |
| `--metadata-file PATH` | no | omitted | Read the complete metadata JSON object from a file, or standard input with `-`. Mutually exclusive with `--metadata`. |
| `--relationship RELATION=TYPE:ID` | no | none | Initial relationship target. Repeat for multiple relationships or targets. |

Every relationship is validated against the active YAML schema. Repeat the same relationship name for a many-cardinality relationship. A one-cardinality relationship accepts exactly one target. All YAML-required relationships must be supplied.

## Example

```bash
authservicecentral ctl --token-file ./management.jwt resources create \
  --type document \
  --id report-123 \
  --metadata '{"title":"Quarterly plan"}' \
  --relationship parent=folder:finance
```

The default table prints the created resource followed by a relationship table when relationships are present.
