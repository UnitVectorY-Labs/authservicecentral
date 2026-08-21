# ServiceAuthCentral Successor
## Technical and Business Design Specification

**Status:** Proposed architecture  
**Implementation language:** Go  
**Authorization engine:** OpenFGA, embedded in-process  
**Primary datastore:** PostgreSQL  
**Deployment model:** Single tenant per deployment  
**Protocol foundation:** OAuth 2.0 Token Exchange and JWT  
**Working relationship to predecessor:** Spiritual successor to ServiceAuthCentral

---

# 1. Executive Summary

This system is a successor to ServiceAuthCentral that preserves its core objective of centralized, secret-minimized service authentication while replacing its coarse client-to-client authorization model with a resource-oriented, permission-centric authorization system.

The original ServiceAuthCentral primarily answers the question:

> Is client A authorized to obtain a JWT whose audience is service B?

If authorized, ServiceAuthCentral issues the token and the receiving API can rely on that token as evidence that the caller was authorized to contact it. The existing implementation uses OAuth 2.0 Client Credentials concepts, supports JWT-based client authentication as an alternative to shared secrets, separates token and management planes, and can use GCP KMS for signing. citeturn976777view0

The successor changes the core authorization question to:

> Does principal P have permission X on resource Y?

An audience is itself a special resource. Therefore an audience-level authorization decision is simply a particular instance of the general resource authorization model.

The system supports both:

- Low-cardinality audience permissions that can be evaluated during token exchange and embedded into the issued JWT.
- High-cardinality fine-grained permissions, such as access to an individual document, folder, video, project, or other application-defined resource, that are evaluated through an authorization API when the resource is accessed.

OpenFGA provides the underlying relationship-based authorization engine. OpenFGA is inspired by Google Zanzibar, supports PostgreSQL, supports Batch Check, and can be embedded directly as a Go library. citeturn329260search1turn250717search0

The system deliberately does **not** define application resource types in Go source code. Its authorization model is defined in a deployment-time YAML schema. That schema is compiled into an OpenFGA authorization model.

Runtime entities such as audiences, resource instances, groups, memberships, role grants, and resource relationships are managed through the API and stored in PostgreSQL and OpenFGA.

---

# 2. Product Goals

The product exists to provide five closely related capabilities behind one API.

## 2.1 Trusted JWT exchange

Accept JWTs from explicitly configured external issuers and exchange them for platform-issued JWTs.

Examples include:

- Google Cloud workload identities
- GitHub-issued JWTs
- Corporate OIDC identity providers
- Kubernetes workload identity systems
- Other systems capable of issuing signed JWTs

Each source has independently configured trust, validation, identity-mapping, and claim-transfer rules.

## 2.2 Unified identity model

Humans and workloads are indistinguishable to the authorization system.

Both are simply **principals** derived from a trusted JWT issuer and subject.

The authorization system does not intrinsically contain separate `user` and `workload` authorization types.

## 2.3 Permission-based authorization

Applications authorize operations using permissions rather than role names.

For example:

```text
document.read
document.write
video.view
invoice.create
customer.billing.read
```

Applications ask whether a principal possesses a permission on a resource.

Roles exist as the administrative mechanism through which permissions are granted.

## 2.4 Fine-grained resource authorization

Applications can define arbitrary resource types in YAML and create arbitrary instances at runtime.

Examples might include:

```text
document:123
folder:finance
video:456
project:alpha
invoice:789
```

The Go application contains no hard-coded knowledge of these application resource types.

## 2.5 Delegated and on-behalf-of token exchange

The system supports exchanging a token representing a subject together with an identity representing an actor, producing a downstream token that can retain both identities.

This follows the concepts defined by OAuth 2.0 Token Exchange, including the distinction between subject and actor and the JWT `act` claim. citeturn329260search36

---

# 3. Design Principles

## 3.1 Permissions are the application contract

Applications SHOULD depend on permission names.

Applications SHOULD NOT make authorization decisions based directly on role names.

A role is an administrative grouping of permissions.

For example:

```text
role: viewer
  document.read

role: editor
  document.read
  document.write

role: administrator
  document.read
  document.write
  document.delete
```

An API endpoint checks:

```text
document.write
```

It does not check:

```text
editor OR administrator
```

The authorization engine determines whether any effective role or inherited relationship provides `document.write`.

## 3.2 Every authorization grant is resource-scoped

There are no unscoped global role assignments.

The fundamental grant is:

```text
principal P
has role R
on resource X
```

Examples:

```text
github:alice
has editor
on document:123
```

```text
gcp:service-a
has caller
on audience:billing-api
```

```text
group:engineering
has reader
on folder:finance
```

If a deployment needs a platform-wide administrative concept, that should still be represented by an explicit resource rather than by introducing unscoped grants.

## 3.3 Authorization schema is deployment configuration

The YAML schema defines:

- resource types
- permissions
- roles
- role-to-permission mappings
- resource relationships
- allowed relationship target types
- relationship cardinality constraints
- inheritance semantics
- trusted JWT sources
- JWT validation policies
- JWT claim-transfer policies

These concepts are not dynamically created through the runtime API.

## 3.4 Runtime data instantiates the configured schema

Runtime API data includes:

- audience registrations
- resource instances
- resource relationships
- groups
- nested group memberships
- role grants
- audience delegation settings

## 3.5 Audience authorization and resource authorization use one permission model

There is no separate "JWT authorization model."

An audience is an intrinsic resource type.

If a principal has a configured permission on the requested audience, that permission is eligible to be materialized into the issued JWT.

For other resource instances, permission checks occur through the authorization API.

## 3.6 JWT permissions are cached authorization results

Permissions embedded in a JWT represent authorization decisions evaluated when the token was issued.

They are therefore subject to token lifetime.

Fine-grained authorization checks are evaluated against current OpenFGA state and can reflect authorization changes more quickly.

## 3.7 APIs should not care how a token was obtained

A target API's primary authorization concerns are:

1. Is the token cryptographically valid?
2. Was it issued by the expected issuer?
3. Does its audience include this API?
4. Does it contain the required audience-level permission?
5. For resource-level access, does the authorization service report the required permission?

Whether the subject originated as:

- a human
- a service account
- a CI/CD workload
- a delegated human through another service

should normally be irrelevant to application permission checks.

---

# 4. Deployment and Tenancy Model

Each deployment represents exactly one authorization universe.

There is no tenant ID included in resource identifiers, OpenFGA relationships, grants, or API requests.

If independently administered authorization domains are required, they should run separate deployments.

Each deployment has one canonical issuer URL.

For example:

```text
https://auth.example.com
```

Another independent authorization universe would use another deployment and issuer:

```text
https://auth.other.example.com
```

This avoids introducing tenant isolation semantics into every resource, tuple, token, query, database table, and authorization decision.

---

# 5. High-Level Architecture

```text
                  External JWT Issuers
                 /        |          \
              GCP       GitHub      OIDC
               |           |          |
               +-----------+----------+
                           |
                           v
                  +------------------+
                  | JWT Trust Layer  |
                  | Validation       |
                  | Normalization    |
                  +--------+---------+
                           |
                           v
                  +------------------+
                  | Token Exchange   |
                  | RFC 8693         |
                  +--------+---------+
                           |
             +-------------+-------------+
             |                           |
             v                           v
    Audience permission             Platform JWT
    evaluation                      issued
             |
             v
       Embedded OpenFGA
             |
             v
         PostgreSQL
```

Runtime fine-grained checks:

```text
Application API
     |
     | platform JWT
     | permission
     | resource
     v
Authorization API
     |
     v
Embedded OpenFGA
     |
     v
PostgreSQL
```

The OpenFGA project explicitly supports use as an embedded Go library and exposes datastore abstractions that can operate against PostgreSQL. citeturn329260search1turn329260search4

---

# 6. Major Components

The Go process contains the following logical components.

## 6.1 HTTP API

Exposes:

- OAuth metadata
- JWKS
- token exchange
- permission checks
- audience management
- resource management
- relationship management
- group management
- role-grant management
- administrative inspection
- health and readiness endpoints

## 6.2 Configuration loader

Loads and validates the deployment YAML.

It produces an immutable in-memory representation of the active authorization schema.

## 6.3 Authorization-model compiler

Transforms the application YAML into an OpenFGA authorization model.

## 6.4 Embedded OpenFGA engine

OpenFGA performs:

- direct relationship checks
- group expansion
- nested group resolution
- role-to-permission resolution
- resource hierarchy traversal
- inherited permission calculation
- batch authorization checks

OpenFGA's Batch Check endpoint currently supports multiple user-object-relation decisions in one request and is designed specifically to reduce authorization-check network overhead. citeturn250717search0turn250717search1

Because OpenFGA is embedded here, the application's public API can use the underlying server/command capabilities without exposing OpenFGA itself as an external service.

## 6.5 Resource catalog

Stores application resource instances and resource metadata in PostgreSQL.

## 6.6 JWT trust manager

Maintains configured issuer trust.

Responsibilities include:

- JWKS discovery and refresh
- static public-key support
- algorithm restrictions
- issuer verification
- audience verification
- expiration and not-before validation
- arbitrary claim validation
- principal mapping
- claim propagation

## 6.7 Token issuer

Issues platform JWT access tokens.

Signing should be abstracted behind a Go interface so implementations may include:

- local asymmetric signing key
- GCP Cloud KMS signing

GCP KMS should be a first-class supported production mode because it preserves the predecessor's secret-minimization philosophy.

## 6.8 Delegation engine

Processes subject and actor identities and determines effective authorization semantics for on-behalf-of exchanges.

---

# 7. Identity Model

## 7.1 Principal

A principal represents any identity capable of being established by a trusted token source.

A principal is fundamentally:

```text
<token-source-id>:<normalized-subject>
```

Examples:

```text
github:repo:example/project:ref:refs/heads/main
google:service-account@example.iam.gserviceaccount.com
corp:248173
```

No semantic distinction between human and workload identity is required.

## 7.2 Principal existence is implicit

Principals do not need to be pre-provisioned.

An administrator may grant access to:

```text
google:future-service@example.iam.gserviceaccount.com
```

before that identity has ever exchanged a JWT.

The first successful authentication does not create the authorization identity. The authorization identity already exists logically because grants reference it.

The implementation MAY maintain auxiliary principal-observation metadata for auditing, such as:

- first seen
- last seen
- source
- most recently observed claims

Such metadata MUST NOT be required for authorization.

## 7.3 Canonical encoding

Because arbitrary JWT subjects may contain punctuation or delimiters, the application MUST define an unambiguous canonical representation before passing identities to OpenFGA.

The external API should generally accept:

```json
{
  "source": "github",
  "subject": "repo:example/project:ref:refs/heads/main"
}
```

rather than requiring clients to construct an internal OpenFGA identifier.

The issued JWT `sub` may retain the readable:

```text
github:<subject>
```

format.

---

# 8. Groups

Groups are intrinsic runtime authorization objects.

Groups may contain:

- principals
- other groups

Example:

```text
github:alice
  member of group:backend

group:backend
  member of group:engineering
```

A role grant to `group:engineering` therefore applies transitively to Alice.

Nested groups map naturally to OpenFGA usersets and recursive group membership.

The authorization service should delegate membership expansion to OpenFGA rather than implementing a separate group-expansion engine.

---

# 9. Resources

## 9.1 Resource types

Application-specific resource types are defined only in YAML.

Example:

```yaml
resources:
  folder:
    relationships: {}

  document:
    relationships:
      parent:
        targets:
          - folder
          - workspace
        cardinality: one
        required: false

  video:
    relationships:
      parent:
        targets:
          - folder
        cardinality: one
        required: false
```

## 9.2 Resource instances

Runtime instances are created through the API.

Examples:

```text
folder:finance
document:123
video:456
```

A resource instance MUST reference a configured resource type.

## 9.3 Explicit resource creation

The API supports creation of a resource with no grants:

```http
POST /v1/resources

{
  "type": "document",
  "id": "123"
}
```

## 9.4 Creation with relationships

Resource creation MAY include relationships:

```json
{
  "type": "document",
  "id": "123",
  "relationships": {
    "parent": {
      "type": "folder",
      "id": "finance"
    }
  }
}
```

## 9.5 Resources without parents

A resource may be parentless whenever permitted by the configured relationship constraints.

## 9.6 Moving resources

Resource relationships are mutable.

Moving:

```text
document:123
```

from:

```text
folder:finance
```

to:

```text
folder:legal
```

changes the underlying relationship tuples.

OpenFGA then evaluates future inherited access through the new graph.

## 9.7 Multiple possible parent types

A relationship may support multiple target resource types if explicitly declared in YAML.

For example:

```yaml
parent:
  targets:
    - folder
    - workspace
```

The runtime API MUST reject targets outside this configured set.

## 9.8 Relationship cardinality

OpenFGA describes relationship possibilities, while this application additionally enforces configured lifecycle invariants.

Example:

```yaml
parent:
  targets: [folder, workspace]
  cardinality: one
```

The service ensures that no document simultaneously receives multiple `parent` values.

Other relationships MAY permit multiple targets.

## 9.9 Resource creation during grant

The grant API supports a configurable request option:

```json
{
  "create_resource_if_missing": true
}
```

If false, the target resource must already exist.

If true, resource creation and grant creation SHOULD behave atomically from the API caller's perspective.

## 9.10 Resource deletion

Deleting a resource removes:

- its resource-catalog record
- direct grants on the resource
- resource relationship tuples originating from it
- resource relationship tuples targeting it
- authorization associations whose userset references that resource

The API MUST prevent orphaned active OpenFGA relationships from affecting future authorization.

Deletion SHOULD be implemented as an idempotent operation.

---

# 10. Audience Model

`audience` is an intrinsic resource type.

Audience instances are runtime data.

Example:

```text
audience:billing-api
audience:documents-api
```

An audience registration describes an API capable of receiving platform-issued access tokens.

Possible metadata includes:

```json
{
  "id": "documents-api",
  "display_name": "Documents API",
  "token_ttl_seconds": 900,
  "delegation": {
    "enabled": true,
    "mode": "subject"
  }
}
```

Audience records are not defined in deployment YAML because applications are runtime entities.

---

# 11. Permissions

## 11.1 Permissions are static schema

The complete set of possible permissions is defined in YAML.

Permissions cannot be invented through the runtime API.

## 11.2 Atomic semantics

A permission represents one atomic application capability.

Examples:

```text
document.read
document.write
video.view
video.edit
customer.profile.read
customer.billing.read
audience.invoke
```

Business APIs determine how combinations of permission results affect application behavior.

The authorization service does not expose a generic Boolean policy language.

## 11.3 Resource applicability

Each permission declares which resource type or types it applies to.

Example:

```yaml
permissions:
  document.read:
    resources:
      - document

  media.read:
    resources:
      - document
      - video

  audience.invoke:
    resources:
      - audience
```

A permission check against an incompatible resource type is a request validation error rather than a denied authorization result.

---

# 12. Roles

Roles are defined in YAML.

Roles cannot be dynamically created through the API.

A role contains one or more configured permissions.

Example:

```yaml
roles:
  reader:
    permissions:
      - document.read
      - video.view
      - audience.invoke

  editor:
    permissions:
      - document.read
      - document.write
      - video.view
      - video.edit
      - audience.invoke
```

Roles may intentionally span multiple resource types.

When a role is granted on a resource, only permissions applicable to that resource type become effective.

For example:

```text
editor on document:123

effective:
  document.read
  document.write
```

while:

```text
editor on video:456

effective:
  video.view
  video.edit
```

A grant MUST be rejected if the selected role has zero permissions applicable to the target resource type.

---

# 13. Grants

The fundamental authorization assignment is:

```text
subject
role
resource
```

The subject may be:

- principal
- group

Examples:

```text
principal github:alice
role editor
resource document:123
```

```text
group engineering
role reader
resource folder:finance
```

The API SHOULD expose roles because they are the administrative grant unit.

Applications performing authorization checks SHOULD use permissions.

---

# 14. OpenFGA Model Compilation

The YAML authorization schema is compiled into an OpenFGA model.

A conceptual generated model for a document might resemble:

```text
type principal

type group
  relations
    define member: [principal, group#member]

type folder
  relations
    define role_reader: [principal, group#member]
    define role_editor: [principal, group#member]

    define read:
      role_reader or role_editor

    define write:
      role_editor

type document
  relations
    define parent: [folder]

    define role_reader: [principal, group#member]
    define role_editor: [principal, group#member]

    define read:
      role_reader
      or role_editor
      or read from parent

    define write:
      role_editor
      or write from parent
```

The exact generated DSL is an implementation concern, but the compiler MUST preserve these principles:

- roles are grant relationships
- permissions are checkable relations
- groups are usersets
- hierarchy uses OpenFGA relationship semantics
- inherited permissions are modeled using OpenFGA
- application code does not manually traverse authorization graphs

---

# 15. Authorization Model Versioning

OpenFGA authorization models are immutable versions.

A changed model is written as a new authorization model and receives a new model ID.

This does not prohibit adding new resource types, roles, or permissions. It means schema evolution produces a new version.

Existing tuple data can continue to reside in the store.

OpenFGA's normal authorization workflow allows checks to pin a specific authorization model ID. citeturn250717search0

The platform SHOULD maintain:

```text
configuration fingerprint
OpenFGA model ID
activation timestamp
schema version
```

in application metadata.

## 15.1 Startup behavior

Recommended production behavior:

```text
migrate
  -> database migrations
  -> validate YAML
  -> compile OpenFGA model
  -> write model if changed
  -> activate model

api
  -> validate YAML
  -> calculate configuration fingerprint
  -> verify active model matches
  -> start serving
```

The `api` command SHOULD fail readiness if the active database authorization model does not correspond to the supplied YAML.

An optional automatic model-migration mode may be introduced later, but explicit migration is the safer production default.

## 15.2 Orphaned runtime data

Schema evolution may make historical runtime records ineffective.

Examples include:

- removed role
- removed permission
- removed resource type
- renamed token source
- removed relationship

Such records may remain physically stored while becoming semantically inactive.

The application SHOULD eventually provide a diagnostic command to identify these records.

It SHOULD NOT automatically delete historical authorization state merely because a configuration version stops referencing it.

---

# 16. Token Source Configuration

A token source defines a JWT trust relationship.

Example:

```yaml
token_sources:
  github:
    issuer: "https://token.actions.githubusercontent.com"

    keys:
      discovery: true

    algorithms:
      - RS256

    identity:
      subject_claim: sub
      prefix: github

    validation:
      audience:
        any_of:
          - "https://auth.example.com"

      claims:
        repository_owner:
          equals: example-org

        event_name:
          one_of:
            - push
            - workflow_dispatch

        ref:
          prefix: "refs/heads/"

    propagate_claims:
      repository:
        from: repository

      workflow:
        from: workflow

      ref:
        from: ref
```

The exact YAML grammar should be finalized during implementation, but these capabilities are required.

---

# 17. JWT Key Discovery

Each token source may configure one of:

1. OIDC/OAuth discovery
2. explicit JWKS URL
3. inline static JWK set
4. explicit static public key

Discovery MUST validate that discovered issuer metadata matches the configured issuer.

JWKS data SHOULD be cached and refreshed according to HTTP cache semantics where practical.

Unknown `kid` values SHOULD trigger a bounded refresh before failing validation.

Algorithms MUST be allowlisted.

The application MUST NOT trust the JWT `alg` value by itself to select arbitrary verification behavior.

---

# 18. Arbitrary Claim Validation

Configured JWT sources may enforce arbitrary claim rules.

The initial matcher vocabulary SHOULD remain deliberately constrained.

Recommended initial operations:

```text
exists
equals
not_equals
one_of
prefix
suffix
regex
contains
```

Type-aware numeric/date matchers may be added if required.

The configuration parser MUST reject unsupported match operations rather than ignoring them.

Validation occurs before the external JWT can establish a principal.

---

# 19. Claim Propagation

A token source may explicitly allow claims from the external JWT to be propagated into platform-issued tokens.

Propagation is allowlist-only.

There MUST NOT be a "copy all claims" default.

Reserved JWT claims such as:

```text
iss
sub
aud
exp
iat
nbf
jti
act
```

cannot be overridden by incoming propagated data.

Propagated claims represent identity or contextual metadata.

They do not independently grant permissions.

---

# 20. Platform JWT Format

A normal issued token might resemble:

```json
{
  "iss": "https://auth.example.com",
  "sub": "github:alice",
  "aud": "documents-api",
  "iat": 1787353200,
  "exp": 1787354100,
  "jti": "01K...",
  "permissions": [
    "document.create",
    "document.list"
  ],
  "repository": "example/documents"
}
```

The exact custom claim namespace should be documented and versioned.

Recommended custom claims include:

```text
permissions
act
authorization_context
```

Audience permissions are generated from current authorization state during exchange.

---

# 21. Audience-Level Permission Materialization

When issuing a JWT for:

```text
audience:documents-api
```

the token service identifies every configured permission applicable to the `audience` resource type.

It then checks which of those permissions the effective principal possesses on:

```text
audience:documents-api
```

OpenFGA Batch Check is an appropriate mechanism for efficiently performing these independent checks. OpenFGA's current Batch Check API is explicitly designed to evaluate multiple independent tuples concurrently. citeturn250717search0

Every allowed audience permission is placed in the JWT `permissions` claim.

For example:

```json
{
  "permissions": [
    "documents.invoke",
    "documents.create"
  ]
}
```

A downstream API can authorize these operations locally.

---

# 22. Fine-Grained Permission Checks

High-cardinality resource grants are not embedded in the JWT.

The receiving application sends the platform JWT to the authorization service along with one or more permission/resource questions.

Example:

```http
POST /v1/check
Authorization: Bearer <platform-jwt>
Content-Type: application/json
```

```json
{
  "checks": [
    {
      "id": "profile",
      "permission": "customer.profile.read",
      "resource": {
        "type": "customer",
        "id": "123"
      }
    },
    {
      "id": "billing",
      "permission": "customer.billing.read",
      "resource": {
        "type": "customer",
        "id": "123"
      }
    }
  ]
}
```

Response:

```json
{
  "results": [
    {
      "id": "profile",
      "allowed": true
    },
    {
      "id": "billing",
      "allowed": false
    }
  ]
}
```

This deliberately resembles OpenFGA's Batch Check behavior, including correlation between independent checks. OpenFGA itself uses correlation IDs for batch results. citeturn250717search0

---

# 23. Authorization Check HTTP Semantics

Authorization denial is a valid authorization result.

Therefore:

```text
HTTP 200
allowed = false
```

is correct.

The API MUST NOT use HTTP `403` merely because a permission check evaluates to false.

HTTP errors represent request-level failures.

Examples:

### 400 Bad Request

- malformed request
- unknown permission
- unknown resource type
- permission does not apply to supplied resource type
- invalid batch size

### 401 Unauthorized

- missing JWT
- malformed JWT
- expired JWT
- invalid JWT signature
- unexpected issuer

### 403 Forbidden

Reserved for situations in which the caller is not authorized to invoke the authorization API itself, if such a distinction becomes necessary.

### 404 Not Found

May be used by management APIs for nonexistent resources.

Permission-check semantics SHOULD carefully avoid leaking resource existence unnecessarily.

### 500 / 503

- PostgreSQL failure
- OpenFGA engine unavailable
- unexpected authorization-model failure

---

# 24. Application-Side Authorization Pattern

Simple API:

```text
POST /documents

required permission:
  document.create
```

The API verifies that its audience token contains:

```text
document.create
```

and performs the operation without another authorization request.

Resource API:

```text
GET /documents/123

required permission:
  document.read
on:
  document:123
```

The API calls `/v1/check`.

Composite API:

```text
GET /customers/123
```

may separately check:

```text
customer.profile.read
customer.billing.read
customer.audit.read
```

The authorization platform returns independent results.

The business API decides whether to:

- fail the request
- omit unauthorized fields
- partially populate the response
- perform another business-specific behavior

That business policy stays outside the authorization service.

---

# 25. Token Exchange Protocol

The primary token endpoint SHOULD follow OAuth 2.0 Token Exchange, RFC 8693.

Recommended endpoint:

```text
POST /oauth2/token
```

Request:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<jwt>
subject_token_type=urn:ietf:params:oauth:token-type:jwt
audience=documents-api
```

Response:

```json
{
  "access_token": "...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900
}
```

RFC 8693 explicitly models token exchange using subject tokens and target audiences/resources. citeturn329260search36

---

# 26. Direct Token Exchange Flow

```text
External JWT
     |
     v
Identify configured token source
     |
     v
Validate signature
     |
     v
Validate issuer / audience / time
     |
     v
Validate arbitrary configured claims
     |
     v
Normalize source + subject -> principal
     |
     v
Validate requested audience
     |
     v
Evaluate audience permissions
     |
     v
Propagate allowed claims
     |
     v
Sign platform JWT
```

A principal does not need previous platform registration.

---

# 27. Delegated / On-Behalf-Of Exchange

RFC 8693 distinguishes the subject whose authority is being exercised from the actor performing the action and defines the JWT `act` claim for representing the actor. citeturn329260search36

A typical flow is:

```text
Alice
  |
  | token for service-a
  v
Service A

Service A workload identity
  +
Alice's service-a token
  |
  v
Token Exchange

target audience:
  service-b
```

Issued token:

```json
{
  "iss": "https://auth.example.com",
  "sub": "corp:alice",
  "aud": "service-b",
  "act": {
    "sub": "gcp:service-a"
  }
}
```

The target API does not need to implement delegation semantics.

The authorization platform owns those semantics.

---

# 28. Audience Delegation Configuration

Delegation behavior is runtime audience configuration because audiences themselves are runtime registrations.

Recommended initial modes:

```text
disabled
subject
intersection
actor
union
```

### disabled

Delegated exchange into the audience is prohibited.

### subject

Authorization derives from the original subject.

The actor exists as provenance and must satisfy whatever requirements are necessary to perform the exchange.

### intersection

A permission is effective only when both subject and actor possess it.

### actor

Authorization derives from the actor while retaining subject context.

This can support workflows where the end-user identity is informational but the service's own authority controls the operation.

### union

A permission may be effective if either subject or actor possesses it.

This mode can increase privilege and MUST require explicit configuration.

It SHOULD NOT be the default.

The exact initial set may be reduced during implementation, but delegation policy MUST remain a runtime audience property rather than being hard-coded.

---

# 29. Delegated Fine-Grained Checks

The authorization API receives the platform JWT rather than a caller-supplied principal identifier.

This prevents the consuming API from asserting an arbitrary identity.

For a direct token:

```text
sub = corp:alice
```

the service performs OpenFGA checks for Alice.

For an intersection delegation token:

```text
sub = corp:alice
act.sub = gcp:service-a
```

the service evaluates the requested permission for both identities and combines the decisions according to the delegation mode.

The target application still receives only:

```json
{
  "allowed": true
}
```

or:

```json
{
  "allowed": false
}
```

It does not need to understand why.

---

# 30. OAuth Authorization Server Metadata

The deployment SHOULD expose OAuth Authorization Server Metadata through the standard well-known endpoint:

```text
/.well-known/oauth-authorization-server
```

Representative response:

```json
{
  "issuer": "https://auth.example.com",
  "token_endpoint": "https://auth.example.com/oauth2/token",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "grant_types_supported": [
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "subject_types_supported": [
    "public"
  ]
}
```

The deployment should not claim to be a full OpenID Connect Provider unless it actually implements the required OpenID Connect behavior.

---

# 31. JWKS Endpoint

Recommended endpoint:

```text
/.well-known/jwks.json
```

The JWKS contains public keys corresponding to active token-signing keys.

Key rotation SHOULD permit multiple simultaneously published public keys so previously issued tokens remain verifiable until expiry.

JWTs MUST include `kid`.

---

# 32. Management API

The management API is deliberately higher-level than raw OpenFGA.

OpenFGA SHOULD NOT be exposed directly to normal consuming applications.

Proposed API families follow.

## 32.1 Audiences

```text
POST   /v1/audiences
GET    /v1/audiences
GET    /v1/audiences/{id}
PATCH  /v1/audiences/{id}
DELETE /v1/audiences/{id}
```

## 32.2 Resources

```text
POST   /v1/resources
GET    /v1/resources/{type}/{id}
PATCH  /v1/resources/{type}/{id}
DELETE /v1/resources/{type}/{id}
```

## 32.3 Resource relationships

```text
PUT    /v1/resources/{type}/{id}/relationships/{relation}
DELETE /v1/resources/{type}/{id}/relationships/{relation}
```

Plural relationship variants may be required for many-cardinality relationships.

## 32.4 Groups

```text
POST   /v1/groups
GET    /v1/groups/{id}
DELETE /v1/groups/{id}
```

## 32.5 Group membership

```text
POST   /v1/groups/{id}/members
DELETE /v1/groups/{id}/members
```

Membership subjects may be principals or groups.

## 32.6 Grants

```text
POST   /v1/grants
DELETE /v1/grants/{id}
GET    /v1/grants
```

Representative grant:

```json
{
  "subject": {
    "type": "principal",
    "source": "github",
    "subject": "alice"
  },
  "role": "editor",
  "resource": {
    "type": "document",
    "id": "123"
  },
  "create_resource_if_missing": false
}
```

## 32.7 Authorization

```text
POST /v1/check
```

Batch-first.

---

# 33. Configuration Validation

The application MUST fully validate YAML before serving API traffic.

Validation includes at least:

- duplicate token source identifiers
- duplicate resource types
- duplicate permissions
- duplicate roles
- unknown permissions referenced by roles
- unknown resource types referenced by permissions
- unknown resource targets referenced by relationships
- invalid inheritance references
- relationship cycles that violate configured constraints
- roles with zero permissions
- impossible role/resource combinations where statically detectable
- reserved identifiers
- invalid token-source matchers
- invalid JWT algorithm configuration
- claim propagation into reserved claims
- unsupported OpenFGA model constructs
- generated OpenFGA model validation

A configuration-validation CLI command SHOULD be provided.

---

# 34. PostgreSQL Data Ownership

One PostgreSQL database can host both:

1. application-owned tables
2. OpenFGA-owned tables

Logical separation SHOULD be maintained.

For example:

```text
platform schema
  audiences
  resources
  groups
  configuration_versions
  audit_events
  migrations

OpenFGA storage
  authorization models
  tuples
  changelog
  assertions
  OpenFGA internal tables
```

Application code MUST NOT directly manipulate OpenFGA internal tables.

All OpenFGA state mutations should use OpenFGA's supported Go interfaces.

---

# 35. Consistency Between Resource Catalog and OpenFGA

PostgreSQL and OpenFGA are backed by the same database technology but remain logically distinct persistence layers.

Operations that affect both require careful consistency handling.

Examples:

- create resource and initial relationship
- grant with `create_resource_if_missing`
- delete resource and authorization tuples

Preferred strategy:

1. validate all requested changes
2. execute application persistence and OpenFGA mutations through a coordinated service layer
3. make operations idempotent
4. use retry-safe operation IDs where appropriate
5. reconcile partial failures

If a single SQL transaction across both components is not available through stable OpenFGA interfaces, correctness SHOULD be achieved using idempotent state transitions rather than coupling application code to OpenFGA's private schema.

---

# 36. OpenFGA Exposure

The embedded OpenFGA network API SHOULD NOT be publicly exposed by default.

The application should use OpenFGA as an internal authorization engine.

Reasons:

- preserve the product's permission-centric contract
- enforce configured resource lifecycle rules
- enforce role/resource compatibility
- prevent bypassing the resource catalog
- prevent runtime mutation of the YAML-defined model
- maintain auditability
- retain freedom to change internal OpenFGA mappings

An optional localhost-only diagnostic OpenFGA endpoint MAY be useful in development but should not form part of the supported external contract.

---

# 37. CLI Design

The product is a single Go executable.

Working command name:

```text
serviceauth
```

The final project name may change.

Required subcommands:

```text
serviceauth api
serviceauth migrate
serviceauth validate
```

Recommended additional utilities:

```text
serviceauth model
serviceauth doctor
serviceauth version
```

## 37.1 `api`

Runs the HTTP service.

```text
serviceauth api
```

Responsibilities:

- load configuration
- validate configuration
- initialize PostgreSQL
- initialize embedded OpenFGA
- verify active model
- initialize JWT validation
- initialize signing
- expose HTTP endpoints
- expose health/readiness
- handle graceful shutdown

## 37.2 `migrate`

```text
serviceauth migrate
```

Responsibilities:

- apply application database migrations
- apply required OpenFGA datastore migrations
- validate YAML schema
- compile authorization model
- compare model fingerprint
- create new OpenFGA model when required
- persist active model information

## 37.3 `validate`

```text
serviceauth validate
```

Performs configuration and model compilation validation without modifying runtime state.

This is suitable for:

- CI
- Kubernetes init validation
- deployment pipelines
- local development

## 37.4 `model`

Recommended:

```text
serviceauth model
```

Outputs the generated OpenFGA model for inspection.

Potential options:

```text
--format=fga
--format=json
```

This is valuable for troubleshooting the YAML compiler.

## 37.5 `doctor`

Recommended:

```text
serviceauth doctor
```

Checks:

- PostgreSQL connectivity
- signing backend
- configured remote JWKS endpoints
- active OpenFGA model
- YAML/model fingerprint
- orphaned schema references
- resource/relationship consistency

---

# 38. CLI and Environment Configuration

Every operational CLI flag MUST have a corresponding environment variable.

Recommended convention:

```text
SERVICEAUTH_<UPPER_SNAKE_CASE_NAME>
```

Examples:

```text
--config
SERVICEAUTH_CONFIG

--database-url
SERVICEAUTH_DATABASE_URL

--issuer
SERVICEAUTH_ISSUER

--listen-address
SERVICEAUTH_LISTEN_ADDRESS

--signing-provider
SERVICEAUTH_SIGNING_PROVIDER

--gcp-kms-key
SERVICEAUTH_GCP_KMS_KEY

--log-level
SERVICEAUTH_LOG_LEVEL
```

Precedence should be:

```text
CLI flag
>
environment variable
>
default
```

The YAML authorization schema remains a file because it describes a structured model rather than simple operational settings.

The path to that file is configurable by flag/environment variable.

---

# 39. Signing Configuration

Recommended interface:

```go
type Signer interface {
    Sign(ctx context.Context, payload []byte) ([]byte, error)
    Algorithm() string
    KeyID() string
    PublicJWK(ctx context.Context) (JWK, error)
}
```

Initial implementations:

```text
local
gcp-kms
```

The rest of the token issuer must not depend on the signing backend.

GCP KMS support SHOULD rely on Application Default Credentials and IAM rather than stored service-account key files whenever possible.

---

# 40. Management API Authorization

The control plane must itself be permission protected.

It should use the same system rather than introducing a separate authorization framework.

A built-in management audience can be created, for example:

```text
audience:serviceauth-management
```

YAML may define management permissions such as:

```text
management.audiences.read
management.audiences.write
management.resources.read
management.resources.write
management.groups.write
management.grants.write
management.schema.read
```

Management clients obtain a token for the management audience and receive the appropriate audience-level permissions.

This preserves the invariant that every grant remains resource-scoped.

---

# 41. Bootstrap

The system needs one controlled mechanism for establishing initial management authority.

Recommended approaches, in preference order:

1. migration-time bootstrap principal configuration
2. explicit one-time CLI bootstrap command
3. narrowly scoped deployment bootstrap credential

A permanent unauthenticated management API MUST NOT exist.

A possible future command:

```text
serviceauth bootstrap grant-admin \
  --source=corp \
  --subject=alice
```

could create the first management-audience grant.

This operation should be auditable and safe to disable after deployment.

---

# 42. Auditability

Security-sensitive mutations SHOULD generate audit records.

At minimum:

- audience created/updated/deleted
- resource created/deleted
- resource relationship changed
- group created/deleted
- membership added/removed
- role grant added/removed
- authorization model activated
- bootstrap authorization operation
- token exchange failure category
- administrative API authentication failure

Audit records SHOULD capture:

```text
timestamp
request ID
actor principal
operation
target
result
relevant previous/new values
```

Sensitive JWT bodies and raw bearer tokens MUST NOT be logged.

---

# 43. Observability

Recommended metrics:

```text
token_exchange_requests_total
token_exchange_failures_total
token_exchange_duration_seconds

authorization_checks_total
authorization_checks_allowed_total
authorization_checks_denied_total
authorization_batch_size

jwks_refresh_total
jwks_refresh_failures_total

openfga_check_duration_seconds
openfga_errors_total

database_operation_duration_seconds
```

Health endpoints:

```text
/health/live
/health/ready
```

Readiness should include:

- PostgreSQL reachable
- OpenFGA datastore initialized
- configured authorization model active
- signing key usable

Remote third-party JWKS providers SHOULD NOT necessarily be required for readiness once valid cached keys exist.

---

# 44. Security Properties

## 44.1 No implicit external trust

A JWT issuer is untrusted unless explicitly defined in YAML.

## 44.2 Strict issuer matching

Issuer comparison must be exact according to JWT/OAuth expectations.

## 44.3 Algorithm allowlist

Each source defines allowed algorithms.

## 44.4 Key origin enforcement

A JWT from one configured source may not use another source's key material.

## 44.5 Audience validation

Incoming JWT audience requirements are source-configurable.

Issued platform JWTs are explicitly audience-scoped.

## 44.6 Short token lifetime

Audience-level permission materialization introduces revocation delay.

Issued token lifetime should therefore remain reasonably short and configurable per deployment or audience.

## 44.7 No caller-specified principal during authorization checks

The permission-check endpoint obtains the effective identity from the validated platform JWT.

This avoids applications asking authorization questions about arbitrary principals.

## 44.8 Fail closed

Any uncertainty in:

- signature validation
- source matching
- authorization-model validation
- permission evaluation

results in denial or request failure.

---

# 45. Business Benefits

## 45.1 Removes service-specific authorization duplication

Applications do not need to independently implement:

- group membership
- role inheritance
- nested groups
- resource hierarchies
- permission stores

## 45.2 Preserves low-latency API authorization

Audience-level permissions can be validated directly from JWT claims.

This avoids forcing every request through a central authorization call.

## 45.3 Supports high-cardinality authorization safely

Document-level, video-level, project-level, and other fine-grained grants remain outside JWTs.

## 45.4 Unifies humans and machines

A service does not need separate IAM models for workforce and workload identity.

## 45.5 Configuration-driven product

Different deployments can represent entirely different application domains without recompiling the Go application.

## 45.6 Evolvable authorization schema

New resource types, permissions, roles, and hierarchy structures can be introduced through new YAML configuration and corresponding versioned OpenFGA models.

## 45.7 Secret minimization

JWT-based workload authentication and GCP KMS signing allow deployments to avoid distributing long-lived client secrets and private signing keys.

---

# 46. Explicit Non-Goals

The initial system is not intended to provide:

- multi-tenancy within one deployment
- dynamic creation of permissions
- dynamic creation of roles
- runtime mutation of the resource schema
- a general-purpose policy programming language
- browser login pages
- password authentication
- user directories
- user provisioning
- full OpenID Provider functionality
- arbitrary direct access to OpenFGA
- unscoped global roles
- automatic application business-rule composition
- embedding high-cardinality resource grants in JWTs

---

# 47. Example Complete Schema

The following is illustrative rather than final syntax:

```yaml
version: 1

token_sources:
  github:
    issuer: "https://token.actions.githubusercontent.com"

    keys:
      discovery: true

    algorithms:
      - RS256

    identity:
      prefix: github
      subject_claim: sub

    validation:
      audience:
        one_of:
          - "https://auth.example.com"

      claims:
        repository_owner:
          equals: example-org

    propagate_claims:
      repository:
        from: repository
      workflow:
        from: workflow

  google:
    issuer: "https://accounts.google.com"

    keys:
      discovery: true

    algorithms:
      - RS256

    identity:
      prefix: google
      subject_claim: sub

permissions:
  api.invoke:
    resources:
      - audience

  document.read:
    resources:
      - document

  document.write:
    resources:
      - document

  folder.read:
    resources:
      - folder

  video.view:
    resources:
      - video

  video.edit:
    resources:
      - video

roles:
  reader:
    permissions:
      - api.invoke
      - document.read
      - folder.read
      - video.view

  editor:
    permissions:
      - api.invoke
      - document.read
      - document.write
      - folder.read
      - video.view
      - video.edit

resources:
  folder:
    relationships:
      parent:
        targets:
          - folder
        cardinality: one
        required: false

  workspace:
    relationships: {}

  document:
    relationships:
      parent:
        targets:
          - folder
          - workspace
        cardinality: one
        required: false

    inheritance:
      - relationship: parent
        permissions:
          - document.read

  video:
    relationships:
      parent:
        targets:
          - folder
        cardinality: one
        required: false
```

Again, the final syntax should be chosen according to how cleanly it compiles into OpenFGA rather than treating this example as fixed.

---

# 48. Example End-to-End Scenario

Assume:

```text
principal:
  corp:alice

group:
  engineering

resource:
  folder:project-x
  document:requirements

audience:
  documents-api
```

Membership:

```text
corp:alice
member of
group:engineering
```

Grant:

```text
group:engineering
has role editor
on folder:project-x
```

Relationship:

```text
document:requirements
parent
folder:project-x
```

Audience grant:

```text
group:engineering
has role reader
on audience:documents-api
```

Alice exchanges her corporate JWT for:

```text
audience=documents-api
```

The token service verifies the corporate JWT and determines that Alice, through Engineering, possesses the audience permission:

```text
api.invoke
```

The issued JWT contains:

```json
{
  "sub": "corp:alice",
  "aud": "documents-api",
  "permissions": [
    "api.invoke"
  ]
}
```

The Documents API can therefore locally authorize API invocation.

Alice requests:

```text
GET /documents/requirements
```

The API calls:

```json
{
  "checks": [
    {
      "permission": "document.read",
      "resource": {
        "type": "document",
        "id": "requirements"
      }
    }
  ]
}
```

OpenFGA resolves:

```text
corp:alice
-> member of engineering
-> editor on folder:project-x
-> inherited permission
-> document:requirements
```

and returns:

```json
{
  "results": [
    {
      "allowed": true
    }
  ]
}
```

The Documents API does not need to know the role, group, or inheritance path.

---

# 49. Recommended Go Package Layout

A possible internal structure:

```text
cmd/
  root.go
  api.go
  migrate.go
  validate.go
  model.go
  doctor.go

internal/
  api/
    http/
    middleware/

  authn/
    jwt.go
    source.go
    jwks.go
    claims.go
    principal.go

  token/
    exchange.go
    issuer.go
    delegation.go

  signing/
    signer.go
    local/
    gcpkms/

  authorization/
    check.go
    grants.go
    compiler.go
    model.go

  openfga/
    engine.go
    datastore.go

  resources/
    service.go
    repository.go

  groups/
    service.go

  audiences/
    service.go

  config/
    load.go
    validate.go
    schema.go

  database/
    postgres.go
    migrations/

  audit/
  observability/
```

Package boundaries should follow domain responsibilities rather than mirroring HTTP paths.

---

# 50. Testing Strategy

## 50.1 Configuration compiler tests

Given YAML, assert the expected OpenFGA model.

Test:

- roles
- permissions
- nested groups
- parent inheritance
- multi-target relationships
- invalid relationships
- incompatible roles

## 50.2 Authorization conformance tests

For each model fixture:

```text
given tuples
when permission checked
then allowed / denied
```

## 50.3 Token-source validation tests

Cover:

- valid key
- wrong issuer
- wrong audience
- expired token
- future nbf
- unsupported algorithm
- missing required claim
- arbitrary claim mismatch
- successful propagation
- reserved claim propagation rejection

## 50.4 Token exchange tests

Cover:

- direct principal
- audience permission materialization
- principal with no audience permissions
- group-derived audience permissions
- token expiration
- signing rotation

## 50.5 Delegation tests

Cover each enabled delegation policy.

## 50.6 Resource lifecycle tests

Cover:

- create
- create-if-missing
- parent assignment
- move
- invalid parent type
- cardinality violation
- delete
- cascade tuple cleanup

## 50.7 Migration tests

Verify an existing deployment can move from model N to N+1 without losing existing valid relationships.

---

# 51. Implementation Phases

## Phase 1: Foundation

Implement:

- Go CLI
- PostgreSQL
- configuration loading
- OpenFGA embedding
- migration framework
- YAML-to-OpenFGA compiler
- basic resource catalog

## Phase 2: Authorization

Implement:

- groups
- nested groups
- role grants
- resource relationships
- resource deletion
- batch permission checks

## Phase 3: JWT Exchange

Implement:

- configured token sources
- JWKS
- claim validation
- principal normalization
- platform token issuance
- audience permission materialization
- discovery metadata
- platform JWKS

## Phase 4: Delegation

Implement:

- platform-token subject exchange
- actor token
- `act`
- runtime audience delegation configuration
- delegated audience permission calculation
- delegated fine-grained checks

## Phase 5: Production Hardening

Implement:

- GCP KMS
- audit system
- metrics
- diagnostics
- signing rotation
- JWKS resilience
- orphan detection
- rate limiting
- extensive migration tests

---

# 52. Core Invariants

The following should be treated as architectural invariants unless deliberately changed in a future design revision.

1. One deployment is one authorization universe.

2. The YAML configuration defines the authorization schema.

3. The Go source code does not define application-specific resource types.

4. Permissions and roles are deployment-time definitions.

5. Resource instances are runtime data.

6. Audiences are runtime resources.

7. Groups are runtime authorization entities.

8. Principals do not require provisioning.

9. Humans and workloads are both principals.

10. Groups can contain principals or other groups.

11. Every role grant targets a resource.

12. No unscoped global role grants exist.

13. Roles can contain permissions spanning multiple resource types.

14. A role grant is rejected if none of its permissions apply to the target resource type.

15. Applications authorize using permissions, not role names.

16. Audience permissions are evaluated at token issuance and may be embedded in the JWT.

17. Fine-grained resource permissions are evaluated through the authorization API.

18. The authorization-check API is batch-first.

19. Permission denial returns a normal successful check result rather than an HTTP authorization error.

20. Application business logic composes permission results.

21. OpenFGA handles graph traversal, inheritance, groups, and permission evaluation.

22. OpenFGA remains an internal implementation component rather than the public API contract.

23. External JWT trust is explicit and configuration-driven.

24. Arbitrary JWT claim validation is supported.

25. Claim propagation is explicitly allowlisted.

26. Delegation policy is controlled by runtime audience configuration.

27. Target APIs do not need to understand delegation mechanics.

28. Platform-issued JWTs are the identity context presented to the fine-grained authorization API.

29. Authorization-model changes are versioned.

30. Schema changes may leave historical runtime records orphaned and ineffective rather than automatically deleting them.

---

# 53. Architectural Summary

The resulting system can be summarized as three planes.

## Trust plane

```text
External JWT
     |
configured issuer trust
     |
claim validation
     |
principal normalization
```

## Token plane

```text
principal
     |
requested audience
     |
OpenFGA audience permission checks
     |
delegation policy if applicable
     |
platform JWT
```

## Authorization plane

```text
platform JWT
     +
permission
     +
resource
     |
     v
OpenFGA
     |
     v
allowed / denied
```

This architecture preserves the strongest property of the original ServiceAuthCentral design, a centralized trust point that vends independently verifiable JWTs, while expanding the authorization model from client-to-client access into a configurable Zanzibar-style resource and permission system.

OpenFGA is not merely attached to the system. It becomes the graph evaluation engine behind both audience permission materialization and fine-grained resource checks, while the Go application supplies the product-specific layers OpenFGA intentionally does not provide: JWT trust, OAuth token exchange, schema compilation, resource lifecycle, audience registration, delegation policy, configuration management, and the opinionated permission-centric API.