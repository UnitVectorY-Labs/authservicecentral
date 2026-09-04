# `authservicecentral ctl grants list`

List resource-scoped role grants through `GET /v1/manage/grants`. The management token requires the configured `grants.read` permission, conventionally `management.grants.read`.

See [the `ctl` overview](../CTL.md) for common flags.

## Usage

```text
authservicecentral ctl [common flags] grants list
```

This command has no command-specific flags. The server currently returns up to its fixed management-list limit; the API does not expose filters or pagination parameters.

## Example

```bash
authservicecentral ctl --token-file ./management.jwt grants list
```

The default table contains `ID`, `SUBJECT`, `ROLE`, and `RESOURCE`, with one row per grant. JSON output preserves the top-level `grants` object.
