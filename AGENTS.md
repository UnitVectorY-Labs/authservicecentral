# Working guidelines

authservicecentral is a self-contained Go authorization and OAuth 2.0 token-exchange service. It unifies human and workload identities, issues audience-scoped platform JWTs, and evaluates fine-grained resource permissions with an embedded OpenFGA model backed by PostgreSQL.

## Core decisions

- The deployment YAML defines the authorization schema: trusted token sources, permissions, roles, resource types, relationships, inheritance, and management permission policy.
- PostgreSQL stores runtime catalog data, audit records, and reconciliation state. OpenFGA is an internal authorization engine, not the public API contract.
- `run` starts the service; startup verifies the active configuration/model and never performs an implicit migration.
- Management APIs live below `/v1/manage/` and are protected by audience-scoped platform tokens and route permissions. Bootstrap is an explicit, auditable CLI operation.
- External resources are embedded with Go `embed`; avoid runtime file dependencies where an embedded resource is appropriate.
- Prefer the Go standard library and small, well-justified dependencies. Keep browser behavior simple with server-rendered HTML and HTMX where interactivity is needed.

## Working practice

- Read the relevant document in `docs/` before changing behavior, and update documentation in the same change.
- Keep `README.md` high-level. Put command and process-setting details in `docs/USAGE.md`, YAML details in `docs/CONFIG.md`, API contract details in `docs/API.md` and `openapi.yaml`, and architectural rationale in `docs/ARCHITECTURE.md`.
- Treat configuration and authorization changes as security-sensitive. Preserve strict validation, fail-closed startup, resource-scoped grants, auditability, and idempotent reconciliation.
- Verify changes with focused tests plus the repository’s complete Go test/build checks. Integration verification requires a disposable PostgreSQL-compatible environment; browser changes should include Playwright coverage when applicable.
- Preserve existing user changes in a dirty worktree and keep edits within the requested scope.
