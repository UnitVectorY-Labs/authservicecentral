# `authservicecentral ctl audiences list`

List runtime audiences through `GET /v1/manage/audiences`. The management token requires the configured `audiences.read` permission, conventionally `management.audiences.read`.

See [the `ctl` overview](../CTL.md) for common flags.

## Usage

```text
authservicecentral ctl [common flags] audiences list
```

This command has no command-specific flags. The server currently returns up to its fixed management-list limit; the API does not expose pagination parameters.

## Example

```bash
authservicecentral ctl --token-file ./management.jwt audiences list
```

The default table contains `ID`, `DISPLAY_NAME`, `TOKEN_TTL_SECONDS`, and `DELEGATION_MODE`, with one row per audience. JSON output preserves the top-level `audiences` object.
