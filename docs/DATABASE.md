# Database

PostgreSQL 18 is the supported persistent store. One database contains two ownership domains: application-owned `platform.*` tables and OpenFGA-owned tables. Application code accesses and migrates OpenFGA data only through official OpenFGA v1.18.1 APIs; it never queries private tables.

## Local PostgreSQL 18 with `container`

```bash
container run --name authservicecentral-postgres \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=authservicecentral -p 5432:5432 -d postgres:18

container logs authservicecentral-postgres
```

Use `container stop authservicecentral-postgres` when finished. Project instructions intentionally use `container`, never Docker or Podman.

## Migrations

```bash
go run . migrate --config examples/serviceauth.yaml \
  --database-url 'postgres://postgres:postgres@localhost:5432/authservicecentral?sslmode=disable'
```

The command validates/fingerprints YAML, applies embedded application migrations with a checksum ledger, invokes OpenFGA's supported embedded migrator, writes a new immutable model only when required, and activates its fingerprint/model ID. There is no automatic down command. Back up PostgreSQL before upgrades.

## Application schema

- `configuration_versions`: fingerprint, immutable OpenFGA model ID, and sole active pointer.
- `audiences`: runtime audiences, TTL, and delegation mode.
- `resources` and `resource_relationships`: typed catalog and graph edges.
- `groups` and `group_memberships`: principal and nested-group membership.
- `grants`: resource-scoped role assignments.
- `authorization_operations`: idempotent transactional outbox for tuple writes/deletes.
- `audit_events`: append-only management mutation history.

Catalog rows retain exact tuple object/relation/subject values. Foreign keys cascade catalog cleanup; the reconciler applies queued tuple mutations through OpenFGA and records completion/retry errors. Schema evolution does not silently delete historical authorization state.

## Startup and readiness

`run` requires completed migration/model activation, drains a bounded amount of outbox work, then starts periodic reconciliation. Startup and `/health/ready` fail if PostgreSQL is unavailable, signing material cannot publish a JWK, or the supplied YAML fingerprint differs from the active model.

## Integration-test isolation

`SERVICEAUTH_TEST_DATABASE_URL` must identify an administrative PostgreSQL database whose user may create/drop databases. The guarded integration test creates a random database, applies both migration systems, and drops it afterward. Never point it at irreplaceable production infrastructure.
