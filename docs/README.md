---
layout: default
title: authservicecentral
nav_order: 1
permalink: /
---

# authservicecentral

One service for authorization and OAuth 2.0 token exchange across human and workload identities.

**authservicecentral** exchanges JWTs from explicitly trusted issuers for short-lived, audience-scoped platform JWTs and evaluates fine-grained resource permissions through an embedded OpenFGA engine. Authorization is declared once in deployment YAML: trusted token sources, permissions, roles, resource types, relationships, and inheritance.

## Key Features

- **Audience-scoped platform JWTs** — short-lived tokens with explicit audience and scope control
- **YAML-defined authorization model** — permissions, roles, and resource relationships declared in one strict config file
- **Fine-grained checks** — batched, permission-centric checks like `document.read`; no duplicated role or hierarchy logic
- **Durable and auditable** — PostgreSQL-backed catalog, audit records, and idempotent reconciliation
