# Glossary

This glossary gives the service-specific meaning of common identity and authorization terms.

| Term | Meaning in authservicecentral |
|---|---|
| Actor | The identity acting on behalf of a subject during delegated token exchange or a delegated authorization check. |
| Audience | A runtime identifier for an API that receives platform tokens. It is also the intrinsic resource on which audience-level permissions are evaluated. |
| Audience permission | A permission evaluated for an audience during token exchange and copied into the resulting platform JWT. |
| Authorization context | Signed platform-token claims describing the subject, optional actor, audience, delegation mode, and permission materialization used by later checks. |
| Bootstrap | The explicit CLI operation that creates the initial management audience grant after the model has been migrated and activated. |
| Claim propagation | Allowlisted copying of selected external JWT claims into a platform JWT. It never grants authority and cannot replace reserved platform claims. |
| Delegation | An on-behalf-of exchange in which a subject token and actor token are combined according to the target audience’s configured mode. |
| Fine-grained authorization | Permission evaluation for a particular resource instance and its current relationship graph, rather than only for an application or audience. |
| Grant | A runtime, resource-scoped assignment of a YAML role to a principal or group. |
| Group | A runtime authorization object that can contain principals and nested groups. OpenFGA expands membership transitively. |
| Inheritance | A YAML rule saying that a permission on a child resource may be obtained through a configured relationship to another resource. |
| Management API | The authenticated control-plane API below `/v1/manage/` for changing runtime audiences, resources, relationships, groups, memberships, and grants. |
| Management permission | An audience-applicable permission protecting one management API family and operation, conventionally named `management.<family>.read` or `.write`. |
| OpenFGA | The embedded relationship-based authorization engine that evaluates the compiled model and runtime tuples. It is an implementation detail, not the public API contract. |
| Permission | A stable capability name such as `document.read` or `api.invoke`. Applications ask for permissions; they do not need to understand role composition. |
| Platform JWT | A short-lived JWT issued by this service after trusted token exchange. It carries audience-scoped permissions and signed authorization context. |
| Principal | A normalized identity, whether human or workload, represented using a configured token-source prefix and external subject. |
| Resource instance | A runtime object such as `document:123` created from a YAML-defined resource type. |
| Resource type | A YAML-defined class of runtime object with relationships and inherited permissions, such as `document` or `folder`. |
| Relationship | A named edge between resource instances, for example a document’s `parent` folder. Cardinality, targets, and requiredness are configured in YAML. |
| Role | A YAML-defined bundle of permissions used when creating grants. A role is not an application authorization API. |
| Token exchange | The RFC 8693 operation that validates a trusted external JWT and issues a platform JWT for a registered audience. |
| Token source | A configured external issuer, key source, algorithm policy, identity mapping, claim validation, and optional claim propagation rule set. |
| Trust plane | The part of the system that verifies external issuer/key material and turns a valid external subject into a normalized principal. |
| Userset | OpenFGA terminology for a set represented by a relation, commonly used here for group membership and relationship traversal. |

