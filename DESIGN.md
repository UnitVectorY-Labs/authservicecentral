# Design

This document represents the remaining design work for `authservicecentral`. As functionality is implemented and documented, completed sections are removed from this document. See the `docs/` directory for full documentation of implemented features.

## Remaining Work

No remaining work is currently tracked in this document.

# Progress and Next Steps

## Completed

### Foundation (CLI, Database, Data Plane Discovery)

- CLI structure: `run`, `migrate`, and `version` subcommands
- Database migrations with full schema
- Data plane discovery endpoints (OpenID Configuration, JWKS)
- JWT key management (RSA and ECDSA)
- Health check endpoint
- Documentation: `docs/USAGE.md`, `docs/CONFIG.md`, `docs/DATABASE.md`

### Token Endpoint (`POST /v1/token`)

- Client Credentials grant: Full OAuth 2.0 client credentials flow with credential verification, authorization checks, scope validation, and JWT minting
- JWT Bearer grant: Workload identity authentication via external JWT assertions with JWKS key caching, selector-based claim matching, and support for RSA and ECDSA signatures

### Control Plane Admin UI

- Login/logout with session management (HMAC-signed cookies)
- Bootstrap admin user creation
- Admin dashboard home page
- **Application CRUD**: Create, view, edit applications with type and locked status
- **Scopes management**: Add/remove offered scopes per application
- **Credentials management**: Create/disable client credentials with 2-active limit and one-time secret display
- **Authorization management**: Create/edit/delete outbound authorizations between applications, add/remove scopes per authorization, enable/disable toggle
- **Identity Providers**: Create, view, edit, delete OIDC identity providers
- **Workload management**: Create, view, edit, delete workloads with JSON selector, link/unlink applications to workloads
- HTMX-powered navigation with full page and partial render support
- Tailwind CSS responsive design

## Next Steps

Continue iterative hardening, validation, and UX polish as implementation feedback is received.
