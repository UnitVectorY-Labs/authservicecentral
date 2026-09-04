# `authservicecentral ctl resources update`

Replace all metadata for a configured resource through `PATCH /v1/manage/resources/{type}/{id}`. This command does not modify relationships. The management token requires the configured `resources.write` permission, conventionally `management.resources.write`.

See [the `ctl` overview](../CTL.md) for common flags and JSON input conventions.

## Usage

```text
authservicecentral ctl [common flags] resources update \
  --type TYPE --id ID (--metadata JSON | --metadata-file PATH)
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--type TYPE` | yes | none | YAML-defined resource type. |
| `--id ID` | yes | none | Runtime resource identifier. |
| `--metadata JSON` | conditional | none | Complete replacement metadata JSON object. Mutually exclusive with `--metadata-file`. Use `{}` to clear metadata. |
| `--metadata-file PATH` | conditional | none | Read the complete replacement metadata object from a file, or standard input with `-`. Mutually exclusive with `--metadata`. One metadata source is required. |

## Example

```bash
authservicecentral ctl --token-file ./management.jwt resources update \
  --type document --id report-123 \
  --metadata '{"title":"Final quarterly plan"}'
```

The default table prints the complete updated resource.
