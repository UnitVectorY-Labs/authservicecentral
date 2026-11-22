[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![Active](https://img.shields.io/badge/Status-Active-green)](https://guide.unitvectorylabs.com/bestpractices/status/#active) 

# authservicecentral

Centralized OAuth 2.0 authorization for service-to-service JWT access tokens, with explicit audience and scope-based access control.

The service is intentionally batch-first and permission-centric. Applications check capabilities such as `document.read`; they do not duplicate role or hierarchy logic.

See [usage](docs/USAGE.md), the [`ctl` command-line client](docs/CTL.md), [API documentation](docs/API.md), the [OpenAPI specification](openapi.yaml), [configuration](docs/CONFIG.md), [database operations](docs/DATABASE.md), and [validation](docs/VALIDATION.md).
