# Usage

`authservicecentral` is a single executable. It validates a deployment YAML file, manages the PostgreSQL/OpenFGA lifecycle, exchanges trusted JWTs, and serves the HTTP API.

For the HTTP contract, see [API.md](API.md) and the repository’s machine-readable [openapi.yaml](../openapi.yaml). For the YAML document itself, see [CONFIG.md](CONFIG.md). Architectural context is in [ARCHITECTURE.md](ARCHITECTURE.md).

## Invocation

```text
authservicecentral <command> [flags]
```

The executable accepts these commands:

| Command | Purpose | Changes external state? |
|---|---|---:|
| `run` | Start the HTTP API and background reconciliation loop. | Yes, through runtime API requests. |
| `api` | Alias for `run`. | Yes, through runtime API requests. |
| `migrate` | Apply embedded migrations, compile the YAML model, and activate its fingerprint/model. | Yes. |
| `bootstrap` | Create the initial management audience grant for a trusted principal. | Yes. |
| `config-docs` | Render the validated YAML as safe, browsable static HTML pages. | Yes, by writing files. |
| `validate` | Parse, validate, fingerprint, and compile YAML without changing runtime state. | No. |
| `model` | Print the deterministic compiled OpenFGA 1.1 JSON model. | No. |
| `doctor` | Check database, active model, signing backend, and configured remote trust. | No, but it performs network probes. |
| `version` | Print the build version. | No. |

Use the command-specific flag reference below when composing a deployment command. The executable name can be replaced with `go run .` from a source checkout.

## Recommended first deployment

The order is intentional. `run` does not migrate the database or silently activate a model.

```bash
authservicecentral validate --config serviceauth.yaml
authservicecentral migrate --config serviceauth.yaml --database-url "$SERVICEAUTH_DATABASE_URL"
authservicecentral bootstrap --config serviceauth.yaml --database-url "$SERVICEAUTH_DATABASE_URL" \
  --source corporate --subject alice --role serviceauth_admin
authservicecentral doctor --config serviceauth.yaml --database-url "$SERVICEAUTH_DATABASE_URL" \
  --signing-key-file ./platform-key.pem
authservicecentral run --config serviceauth.yaml --database-url "$SERVICEAUTH_DATABASE_URL" \
  --signing-key-file ./platform-key.pem
```

For GCP KMS signing, use `--signing-provider=gcp-kms` and `--gcp-kms-key` instead of `--signing-key-file`, with Application Default Credentials available to the process.

## Command reference

### `run`

Starts the HTTP server and the periodic authorization outbox reconciler. It loads and strictly validates the YAML, verifies that its fingerprint is active in PostgreSQL/OpenFGA, initializes trust and signing, drains a bounded amount of pending reconciliation work, and then listens on `--listen-address`.

The local signing provider requires `--signing-key-file`; the GCP KMS provider requires `--gcp-kms-key`. `run` never applies migrations. Stop the process with the platform’s normal interrupt or termination signal for graceful shutdown.

The public discovery documents are available at `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`. Both return the configured issuer, token exchange endpoint, JWKS URI, and supported grant metadata. The OpenID path supports clients that use standard issuer discovery for key retrieval; this service does not provide interactive OpenID Connect authorization or ID tokens.

When `--swagger-ui` is enabled, `GET /` serves the static Swagger UI shell and `GET /openapi.yaml` serves the embedded OpenAPI document. The served document’s `servers` entry is substituted with the configured platform issuer (`--issuer` / `SERVICEAUTH_ISSUER`) so the API reference points at the deployment’s canonical host instead of the local default. This surface is enabled by default and can be disabled with `SERVICEAUTH_SWAGGER_UI=false` or `--swagger-ui=false`.

### `api`

An alias for `run`, retained for compatibility with deployments that use `api` as the service command. It accepts the same flags and environment variables and has the same startup and shutdown behavior.

### `migrate`

Validates the YAML and token-source configuration, applies the embedded application migrations, applies the supported OpenFGA datastore migrations, compiles the authorization model, and creates or reuses the immutable model identified by the YAML fingerprint. It then records and activates the configuration version.

This is the only command that migrates or activates the authorization model. It does not require signing material because it does not issue platform tokens.

### `bootstrap`

Creates the first management path after `migrate` has activated the matching model. It:

1. verifies that `--source` matches a configured token-source identity prefix;
2. verifies that `--role` exists and contains a management permission applicable to `audience`;
3. verifies the active YAML fingerprint/model;
4. upserts the management audience; and
5. creates and reconciles a deterministic resource-scoped grant for `--source:--subject`.

Repeating the same invocation is idempotent. The principal still obtains a normal platform JWT through token exchange; bootstrap does not create an HTTP bypass.

### `config-docs`

Renders the validated deployment YAML as a static HTML site. The command uses the same strict parser and validation rules as the runtime, computes the configuration fingerprint, and writes seven pages to `config-docs/` by default:

```text
index.html
configuration.html
token-sources.html
permissions.html
roles.html
resources.html
management-permissions.html
```

Generate the site into a chosen directory with either spelling of the output flag:

```bash
authservicecentral config-docs --config serviceauth.yaml --output-dir ./config-reference
```

`--output` is an alias for `--output-dir`. The generated pages are standalone static files and use basic Go templates with HTMX navigation; they do not require a JavaScript framework or a running authservicecentral process. The full configuration page redacts private JWK parameters, private PEM blocks, and secret-like values before rendering. Publish the output as static documentation only after reviewing the redaction policy for the deployment’s own extensions.

### `validate`

Parses the one-document YAML file with strict fields, validates all references and matchers, computes its canonical fingerprint, compiles the OpenFGA model, and validates token-source configuration. It does not connect to PostgreSQL or mutate the deployment.

### `model`

Prints the deterministic compiled OpenFGA 1.1 JSON model for inspection, review, or diffing. It does not connect to PostgreSQL or mutate the deployment.

### `doctor`

Checks PostgreSQL connectivity, the active model fingerprint, the configured signing backend and public JWK, token-source validation, and remote issuer/JWKS trust where configured. It requires the same signing material as `run` and may make outbound HTTPS requests.

### `version`

Prints the build version and does not read the YAML or contact external services.

## Process flags and environment variables

Every operational process setting has a flag and a `SERVICEAUTH_*` environment variable. A supplied flag overrides its environment variable; an environment variable overrides the default. The YAML authorization schema is separate and is documented in [CONFIG.md](CONFIG.md). The `config-docs` output directory is a command-only setting with no environment-variable equivalent.

Malformed typed environment values use the default. Invalid flag values fail command parsing. Durations use Go syntax such as `500ms`, `15s`, or `2m`.

| Setting | Flag | Environment variable | Default | Applies to |
|---|---|---|---|---|
| YAML path | `--config` | `SERVICEAUTH_CONFIG` | `serviceauth.yaml` | all commands except `version` |
| PostgreSQL URL | `--database-url` | `SERVICEAUTH_DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/authservicecentral?sslmode=disable` | `run`, `migrate`, `bootstrap`, `doctor` |
| Platform issuer | `--issuer` | `SERVICEAUTH_ISSUER` | `http://localhost:8080` | `run`/`api`, `doctor` |
| Listen address | `--listen-address` | `SERVICEAUTH_LISTEN_ADDRESS` | `:8080` | `run`/`api` |
| Local signing key | `--signing-key-file` | `SERVICEAUTH_SIGNING_KEY_FILE` | empty; required for local `run`/`doctor` | `run`/`api`, `doctor` |
| Signing provider | `--signing-provider` | `SERVICEAUTH_SIGNING_PROVIDER` | `local` | `run`/`api`, `doctor` |
| GCP KMS key version | `--gcp-kms-key` | `SERVICEAUTH_GCP_KMS_KEY` | empty; required for GCP KMS `run`/`doctor` | `run`/`api`, `doctor` |
| Inactive local signing keys | `--inactive-signing-key-files` | `SERVICEAUTH_INACTIVE_SIGNING_KEY_FILES` | empty comma-separated list | `run`/`api`, `doctor` |
| Configuration-docs output directory | `--output-dir` or `--output` | — | `config-docs` | `config-docs` |
| Unauthenticated management | `--insecure-management` | `SERVICEAUTH_INSECURE_MANAGEMENT` | `false` | `run`/`api` |
| Swagger UI | `--swagger-ui` | `SERVICEAUTH_SWAGGER_UI` | `true` | `run`/`api` |
| Maximum check batch | `--max-batch-size` | `SERVICEAUTH_MAX_BATCH_SIZE` | `100` (1–1000) | `run`/`api` |
| HTTP timeout | `--http-timeout` | `SERVICEAUTH_HTTP_TIMEOUT` | `15s` | `run`/`api` |
| Shutdown timeout | `--shutdown-timeout` | `SERVICEAUTH_SHUTDOWN_TIMEOUT` | `15s` | `run`/`api` |
| Reconciliation interval | `--reconcile-interval` | `SERVICEAUTH_RECONCILE_INTERVAL` | `2s` | `run`/`api` |
| Reconciliation batch | `--reconcile-batch` | `SERVICEAUTH_RECONCILE_BATCH` | `100` (1–1000) | `run`/`api` |
| Metrics | `--metrics` | `SERVICEAUTH_METRICS` | `true` | `run`/`api` |
| Rate limit per second | `--rate-limit-per-second` | `SERVICEAUTH_RATE_LIMIT_PER_SECOND` | `0` (disabled) | `run`/`api` |
| Rate-limit burst | `--rate-limit-burst` | `SERVICEAUTH_RATE_LIMIT_BURST` | `0` (disabled) | `run`/`api` |
| Bootstrap source prefix | `--source` | `SERVICEAUTH_BOOTSTRAP_SOURCE` | empty; required by `bootstrap` | `bootstrap` |
| Bootstrap subject | `--subject` | `SERVICEAUTH_BOOTSTRAP_SUBJECT` | empty; required by `bootstrap` | `bootstrap` |
| Bootstrap role | `--role` | `SERVICEAUTH_BOOTSTRAP_ROLE` | empty; required by `bootstrap` | `bootstrap` |
| Management audience ID | `--management-audience` | `SERVICEAUTH_MANAGEMENT_AUDIENCE` | `serviceauth-management` | `bootstrap` |
| Management display name | `--management-display-name` | `SERVICEAUTH_MANAGEMENT_DISPLAY_NAME` | `ServiceAuth Management` | `bootstrap` |
| Management token TTL | `--management-ttl` | `SERVICEAUTH_MANAGEMENT_TTL` | `900` seconds | `bootstrap` |

The rate-limit settings must both be zero or both be positive. `--insecure-management` disables only management authentication and is for isolated development; it does not make token exchange or `/v1/check` unauthenticated.

## HTTP and documentation surfaces

The service’s repository and runtime reference surfaces are deliberately separate:

- [API.md](API.md) explains request/response behavior and integration patterns.
- [openapi.yaml](../openapi.yaml) is the machine-readable API contract served at `/openapi.yaml` when the Swagger surface is enabled.
- [CONFIG.md](CONFIG.md) explains the deployment YAML and does not catalog process flags.
- `config-docs` renders a redacted, browsable snapshot of one YAML file for publication as static files; it is not a runtime configuration endpoint.
- `GET /` serves Swagger UI when enabled; it does not expose YAML configuration or private key material.

The API is a standalone executable surface. Requests can be exercised with any HTTP client, including curl, Postman, a browser, or an application test harness.
