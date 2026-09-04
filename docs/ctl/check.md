# `authservicecentral ctl check`

Evaluate resource permissions through `POST /v1/check`. The platform token supplies the subject, audience, and optional actor; identity cannot be supplied as command flags.

See [the `ctl` overview](../CTL.md) for common bearer-token, output, and exit conventions.

## Usage

```text
authservicecentral ctl [common flags] check \
  --permission PERMISSION --resource-type TYPE --resource-id ID [--id ID]

authservicecentral ctl [common flags] check --file PATH
```

## Flags

| Flag | Required | Default | Description |
|---|---:|---|---|
| `--permission PERMISSION` | conditional | none | YAML-defined permission for a single check. |
| `--resource-type TYPE` | conditional | none | YAML-defined resource type for a single check. |
| `--resource-id ID` | conditional | none | Runtime resource ID for a single check. |
| `--id ID` | no | `check-1` | Caller-controlled result ID for a single check. |
| `--file PATH` | conditional | none | Read an exact API `CheckRequest` JSON object from a file, or from standard input with `-`, for one or more checks. |

Use either `--file` or the three single-check flags. They are mutually exclusive. The file form must contain an object with a non-empty `checks` array in the schema documented by [API.md](../API.md); the service's configured maximum batch size remains authoritative.

## Examples

```bash
authservicecentral ctl --token-file ./application.jwt check \
  --permission document.read \
  --resource-type document \
  --resource-id report-123
```

```bash
authservicecentral ctl --token "$APPLICATION_TOKEN" --output json check --file ./checks.json
```

The default table contains `ID` and `ALLOWED` columns in request order. A legitimate denial prints `false` and exits with status `0`; only an invalid or failed request is an error.
