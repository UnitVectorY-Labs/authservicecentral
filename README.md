# authservicecentral

`authservicecentral` is a single-deployment authorization and OAuth 2.0 token-exchange service for human and workload identities. It exchanges JWTs from explicitly trusted issuers for short-lived, audience-scoped platform JWTs and evaluates resource permissions through an embedded OpenFGA engine.

Authorization is deployment-configured: YAML declares trusted token sources, permissions, roles, resource types, relationships, and inheritance. Runtime APIs manage audiences, resource instances, groups, memberships, and resource-scoped grants. PostgreSQL stores the application catalog, audit/outbox state, and OpenFGA data.

The service is intentionally batch-first and permission-centric. Applications check capabilities such as `document.read`; they do not duplicate role or hierarchy logic.

See [usage](docs/USAGE.md), the [`ctl` command-line client](docs/CTL.md), [API documentation](docs/API.md), the [OpenAPI specification](openapi.yaml), [configuration](docs/CONFIG.md), [database operations](docs/DATABASE.md), and [validation](docs/VALIDATION.md).
