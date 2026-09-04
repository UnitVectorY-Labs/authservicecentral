---
layout: default
title: YAML configuration reference
nav_order: 4
permalink: /config
---

# YAML configuration reference

This document describes the deployment authorization YAML only. Process flags and `SERVICEAUTH_*` environment variables belong in [USAGE.md](USAGE.md). Runtime catalog objects such as audiences, resources, groups, and grants belong in [API.md](API.md).

The file is one strict YAML document with `version: 1`. Unknown fields, duplicate keys, and multiple YAML documents are rejected. The validated document is canonicalized and fingerprinted; that fingerprint is tied to the active OpenFGA model during `migrate` and must match during `run`.

## Top-level shape

```yaml
version: 1
token_sources: {}
permissions: {}
roles: {}
resources: {}
management:
  permissions: {}
```

The recognized top-level sections are `version`, `token_sources`, `permissions`, `roles`, `resources`, and optional `management`. `version` must be `1`; `permissions` and `roles` must be non-empty. `token_sources` and `resources` may be empty when a deployment does not use external token sources or application resources. Omitted management permission entries use the standard names described below.

Identifiers for token sources, roles, resource types, and relationship names use lowercase letters, digits, and underscores and begin with a letter. Permission names contain at least two lowercase dot-separated segments. `principal`, `group`, and `audience` are reserved resource concepts and cannot be declared under `resources`; `audience` is available as a permission target.

## `version`

The schema version integer. The current and only accepted value is `1`.

## `token_sources`

Defines which external JWT issuers may establish principals.

```yaml
token_sources:
  corporate:
    issuer: https://id.example.com
    keys:
      discovery: true
    algorithms: [RS256]
    identity:
      subject_claim: sub
      prefix: corporate
    validation:
      audience:
        any_of: [https://auth.example.com]
      claims:
        organization:
          equals: example
    propagate_claims:
      email:
        from: email
```

Each source has these attributes:

| Attribute | Purpose and constraints |
|---|---|
| `issuer` | Absolute HTTPS issuer URL. The JWT issuer must match this configured value. |
| `keys` | Exactly one key mode: `discovery`, `jwks_url`, inline `jwks`, or PEM `public_key`. Key modes are mutually exclusive. |
| `keys.discovery` | Set `true` to discover issuer metadata and JWKS. Discovery verifies issuer equality. |
| `keys.jwks_url` | Absolute HTTPS JWKS URL when keys are maintained at a known endpoint. |
| `keys.jwks` | Inline JWKS object for deployments that distribute key material with the configuration. |
| `keys.public_key` | PEM-encoded public key for a static external signing key. This is public verification material, not a private signing key. |
| `algorithms` | Non-empty allowlist of supported asymmetric JWT algorithms: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, or `ES512`. |
| `identity.subject_claim` | External JWT claim used as the subject. It is required and is read before the principal is normalized. |
| `identity.prefix` | Unique lowercase principal prefix used to distinguish subjects from different issuers. |
| `validation` | Optional audience and claim rules evaluated before identity is accepted. |
| `propagate_claims` | Optional allowlist of external claims to copy to platform JWT claims. Each output maps to a source claim using `from`. |

Remote keys are cached. An unknown key ID may cause a bounded refresh, but a token is never trusted merely because the issuer is configured. Claim propagation cannot overwrite reserved platform claims such as `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `act`, `permissions`, or `authorization_context`.

### Validation matchers

`validation.audience` accepts one matcher. Each `validation.claims.<name>` entry also accepts exactly one matcher operation:

| Matcher | Meaning |
|---|---|
| `exists: true` or `false` | Require the claim to exist or not exist. |
| `equals: value` | Require an exact scalar/structured value. |
| `not_equals: value` | Reject an exact value. |
| `one_of: [values]` | Match one of the listed values. |
| `any_of: [values]` | Match any configured accepted value; commonly used for audiences. |
| `prefix: text` | Require a string prefix. |
| `suffix: text` | Require a string suffix. |
| `regex: expression` | Match a valid regular expression. |
| `contains: value` | Require the claim to contain the value according to its supported representation. |

Do not combine operations in one matcher. Empty `one_of` or `any_of` lists and invalid regular expressions are rejected.

## `permissions`

Defines the capabilities that applications and management routes can request. Each permission must apply to at least one resource type, and every permission must be included by at least one role.

```yaml
permissions:
  api.invoke:
    resources: [audience]
  document.read:
    resources: [document]
  document.write:
    resources: [document]
```

`resources` is a non-empty list of declared resource types or the intrinsic `audience` type. A permission may apply to more than one type. The same permission name can therefore be evaluated at different resource kinds, but a grant is effective only for the applicable target type.

## `roles`

Defines named bundles of permissions used by runtime grants and bootstrap.

```yaml
roles:
  editor:
    permissions: [api.invoke, document.read, document.write]
```

Every role needs at least one known permission. Role names are identifiers and role membership is not itself an application authorization contract; application callers should use permission names.

## `resources`

Defines application resource types, their relationships, and inherited permissions. Runtime instances are created through the management API.

```yaml
resources:
  folder:
    relationships: {}
  document:
    relationships:
      parent:
        targets: [folder]
        cardinality: one
        required: false
    inheritance:
      - relationship: parent
        permissions: [document.read]
```

### Resource attributes

| Attribute | Purpose and constraints |
|---|---|
| `relationships` | Map of relation names to allowed target types and lifecycle constraints. It may be empty. |
| `relationships.<name>.targets` | Non-empty list of declared resource types. Unknown or duplicate targets are rejected. |
| `relationships.<name>.cardinality` | `one` permits one target; `many` permits multiple targets. |
| `relationships.<name>.required` | Whether lifecycle validation requires a relationship value. |
| `inheritance` | Optional list of permissions inherited through a relationship. |
| `inheritance[].relationship` | Relationship defined on the same resource type. |
| `inheritance[].permissions` | Non-empty list of known permissions that applies to the current resource type. |

Relationship names cannot use reserved `role_` or `permission_` prefixes. The service rejects invalid references, self-inconsistent inheritance, unsupported cardinality, and nested-group cycles. Resource relationships are runtime data; the YAML defines what is legal, not which instances currently exist.

## `management`

Configures the permission required by each family of authenticated management endpoints. This is deployment policy layered on top of the authorization model and is the explicit bootstrap escape from the meta-permission problem.

```yaml
management:
  permissions:
    audiences:
      read: management.audiences.read
      write: management.audiences.write
    resources:
      read: management.resources.read
      write: management.resources.write
    groups:
      read: management.groups.read
      write: management.groups.write
    grants:
      read: management.grants.read
      write: management.grants.write
```

The supported families are `audiences`, `resources`, `groups`, and `grants`; each may define `read` and `write`. An omitted value uses the corresponding conventional name:

| Route family | Read default | Write default |
|---|---|---|
| audiences | `management.audiences.read` | `management.audiences.write` |
| resources | `management.resources.read` | `management.resources.write` |
| groups | `management.groups.read` | `management.groups.write` |
| grants | `management.grants.read` | `management.grants.write` |

Every explicitly configured permission must exist under `permissions` and must apply to `audience`. The bootstrap role must include a management permission that applies to `audience`; when custom management permissions are used, ensure the bootstrap role includes the intended custom permission.

The conventional default names are not generated as implicit permission definitions. If a route uses a default, declare that permission under `permissions` and include it in the role that should receive the corresponding management capability.

## Validation and lifecycle

`validate` is the safe preflight for this document. `migrate` compiles and activates the resulting model. `run` verifies the same fingerprint and fails closed if the database has not been migrated to it.

Changing YAML is a schema change, not a runtime catalog mutation. Review permission applicability, role coverage, relationship targets, inheritance, token trust, and bootstrap authority together. Never place a private platform signing key in this file; local private key paths and KMS key references are process settings described in [USAGE.md](USAGE.md).
