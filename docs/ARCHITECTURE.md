---
layout: default
title: Architecture
nav_order: 6
permalink: /architecture
---

# Architecture

authservicecentral is a single-deployment authorization universe. One process owns the trust configuration, token exchange, runtime resource catalog, and permission checks for that deployment. PostgreSQL provides durable catalog and reconciliation state; an embedded OpenFGA engine evaluates the configured authorization model.

This document preserves the design decisions that are important when operating, extending, or integrating with the service. The normative command and API details live in [USAGE.md](USAGE.md), [API.md](API.md), and [CONFIG.md](CONFIG.md).

## Design goals

The service is designed to:

- accept JWTs only from explicitly configured issuers;
- normalize human and workload identities into one principal model;
- issue short-lived, audience-scoped platform JWTs;
- express application authorization as stable permissions rather than role names;
- evaluate permissions over resources, relationships, inheritance, groups, and delegation;
- keep application APIs independent of token-source and role implementation details; and
- make model changes, management mutations, and reconciliation observable and auditable.

The service is intentionally not a general-purpose identity provider, user directory, policy editor, or raw OpenFGA proxy.

## Three authorization planes

```text
Trust plane       external JWT -> issuer/key/claim validation -> principal
Token plane       principal + audience -> audience permissions -> platform JWT
Authorization     platform JWT + permission + resource -> OpenFGA -> allow/deny
```

The planes are related but have different lifecycles. Deployment YAML defines trust and the authorization schema. Runtime APIs create audiences, resources, groups, relationships, and grants. A platform token carries an audience-level permission snapshot; fine-grained resource checks use current authorization state.

## Runtime components

### Configuration loader and compiler

The loader parses one strict YAML document, rejects unknown fields and duplicate or multiple documents, validates cross-references, and computes a canonical SHA-256 fingerprint. The compiler turns the validated schema into an OpenFGA model. The active model and fingerprint are recorded during `migrate`.

`run` verifies that the supplied YAML fingerprint matches the active model before serving traffic. A mismatch or missing activation fails closed. Configuration is not changed through runtime APIs.

### Trust manager

Each token source has an HTTPS issuer, one key acquisition mode, an algorithm allowlist, and a subject claim/prefix. Keys may be discovered, loaded from a JWKS URL, supplied inline, or configured as a public key. Audience and arbitrary claim matchers run before the token establishes identity. Claim propagation is an explicit allowlist and cannot overwrite platform claims.

The normalized principal is conceptually:

```text
<configured identity prefix>:<external subject>
```

Principals do not need pre-provisioning. A grant may refer to a principal before its first successful token exchange; authentication confirms the principal but does not create its authority.

### Token issuer and delegation

RFC 8693 token exchange validates an external subject token and produces a short-lived platform JWT for a registered runtime audience. A platform token contains the issuer, readable subject, one audience, timestamps, a JWT ID, sorted audience permissions, and signed authorization context. Delegated exchange adds actor context and applies the target audience’s configured delegation mode.

The signer is abstracted from token issuance. Local asymmetric keys are suitable for development and controlled deployments; GCP KMS can sign without exporting private material. Active and configured inactive public keys are exposed through JWKS so tokens remain verifiable during rotation.

### Resource catalog and OpenFGA

The catalog stores runtime instances of YAML-defined resource types, relationship edges, groups, memberships, audiences, and resource-scoped grants. OpenFGA stores the corresponding authorization tuples and evaluates direct access, group expansion, nested groups, resource traversal, and inherited permissions.

Application-specific resource types and permissions cannot be invented by API callers. The management API validates every type, relation, target, role, and grant against the active YAML model.

Successful catalog mutations are written transactionally with reconciliation work and audit information. The service reconciles the resulting tuple changes synchronously before returning success and retries incomplete work through a background outbox reconciler.

## Authorization model

### Permissions and roles

Permissions are the application-facing contract, for example `document.read` or `api.invoke`. Each permission names one or more applicable resource types. A role is a YAML-defined bundle of permissions. Roles are management conveniences; callers should ask whether a permission is allowed rather than inspect a role name.

Every grant is resource-scoped. A grant assigns a role to a principal or group for one resource reference. A role may contain permissions for several resource types, but a grant is rejected when none of that role’s permissions apply to the target resource.

### Resources and relationships

YAML defines resource types and their allowed relationships. Runtime APIs create instances such as `folder:finance` or `document:123`. Relationships may have one or many cardinality and may be required by lifecycle policy. Inheritance maps a relationship to permissions on the child resource.

Moving a resource changes relationship tuples and therefore changes future authorization results. Deleting a resource removes its catalog state, associated grants, and relationship state so stale tuples cannot grant access.

`audience`, `group`, and `principal` are intrinsic resource concepts. Application resource types are declared under `resources`; audiences and groups are created through their dedicated management operations.

### Batch authorization checks

`POST /v1/check` is the application-facing check surface. It accepts an ordered batch of permission/resource checks and derives subject and optional actor exclusively from the signed platform token. A legitimate denial is a successful response containing `allowed: false`; malformed requests, unknown permissions, incompatible resource types, and dependency failures are errors.

## HTTP surface and management boundary

The API separates application authorization from control-plane mutations:

- OAuth metadata and OpenID discovery-compatible metadata are exposed at the standard well-known paths, alongside token exchange at the OAuth path;
- `/v1/check` is the authenticated application authorization surface; and
- all audience, resource, relationship, group, membership, and grant mutations are below `/v1/manage/`.

Management operations require a platform JWT whose audience is the configured management audience and whose audience-level permissions include the route’s required management permission. The standard requirements are `management.<family>.read` and `management.<family>.write`. YAML may replace those requirements per family under `management.permissions`; the replacement must itself be an audience-applicable permission.

The root Swagger UI and `/openapi.yaml` are optional documentation surfaces controlled by `SERVICEAUTH_SWAGGER_UI` or `--swagger-ui`. They describe the HTTP contract but do not weaken authentication. The UI is disabled in deployments that do not want a browser-facing API reference.

The `config-docs` command is a separate build-time documentation surface. It reads and validates one YAML file, renders a static site for its token sources, permissions, roles, resources, management mappings, and safe full configuration, and writes no runtime or database state. Private key parameters and secret-like values are redacted before output. Generated pages use Go templates and HTMX navigation and can be served by any static file server.

## Bootstrap and safe startup

Management authorization has a deliberate bootstrap sequence:

1. `validate` checks the YAML and generated model without changing runtime state.
2. `migrate` applies the embedded database migrations, creates or reuses the compiled OpenFGA model, and activates the matching fingerprint.
3. `bootstrap` verifies that activation, creates the configured management audience, and creates an idempotent, deterministic grant for the selected trusted principal and role.
4. The principal performs a normal token exchange for the management audience and uses that platform token to call `/v1/manage/...`.
5. `run` starts only after verifying the same active model and drains a bounded amount of pending reconciliation work.

There is no permanent unauthenticated bootstrap endpoint. `--insecure-management` exists only for isolated development and bypasses management authentication; it must not be enabled in production.

The bootstrap role must be declared in YAML and contain at least one management permission applicable to `audience`. With conventional defaults this is a `management.*` permission; when management permissions are customized, the role must contain the configured permission that grants the bootstrap principal enough authority for the intended management operations.

## Versioning and consistency

The YAML fingerprint identifies the complete authorization schema. A changed schema produces a new immutable model activation while existing runtime catalog data remains durable. Data that no longer fits the new model must not silently become effective; reconciliation and validation determine whether it can remain active.

PostgreSQL ownership is divided between application tables and OpenFGA-managed tables. Application code uses the supported OpenFGA APIs and does not depend on private OpenFGA table details. The application outbox is the bridge between catalog transactions and tuple reconciliation.

## Security invariants

These properties are architectural contracts:

- external JWT trust is explicit and issuer-bound;
- algorithms, audiences, claims, and claim propagation are allowlisted;
- humans and workloads use the same principal and grant model;
- no global, unscoped role grant exists;
- applications authorize with permissions, not role names;
- OpenFGA remains internal and management APIs remain higher-level;
- platform JWTs are short-lived and independently verifiable;
- authorization checks never accept a caller-supplied identity in place of signed token context;
- startup fails closed on unavailable or mismatched authorization state; and
- security-sensitive mutations produce audit records and are safe to retry where documented.
