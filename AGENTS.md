This is a Go application that provides an OAuth 2.0 authorization server for a data plane as well as a HTMX based user interface for managing the authorizations for the control plane.

The main.go file is the entry point and the rest of the code is organized under the `internal/` directory. Any external files needed by the application such as a database schema / migration files and the HTML templates and other resources are to be included in the compiled binary using the embed package.

The main application web is launched using the "run" sub-command.

## Technology Stack

- Go programming language
- Docker for containerization
- PostgreSQL for database storage
- Database migrations handled with "migrate" sub-command using `golang-migrate/migrate` library
- HTMX for dynamic web components
- Tailwind CSS CLI for build-time stylesheet generation only (compiled CSS is committed and embedded)
- No additional JavaScript frameworks beyond HTMX (radical simplicity as design philosophy)

Minimize the use of external dependencies relying on the Go standard library as much as possible.

Tailwind is used only to generate CSS at build time. This is not a JavaScript project.

- Use Tailwind CLI to compile tailwind.css into a single committed stylesheet.
- The generated CSS must not be minified.
- Do not add or commit JavaScript project artifacts: package.json, lockfiles, node_modules/, PostCSS configs, etc.
- On Ubuntu, prefer the standalone Tailwind binary install. If you do use Node, use it only to run the Tailwind command.

CLI build command:

```
tailwindcss -i ./internal/web/static/tailwind.css -o ./internal/web/static/style.css
```

npx example (no project setup, no files committed):

```
npx --yes tailwindcss@3.4.17 \
  -i ./internal/web/static/tailwind.css \
  -o ./internal/web/static/style.css
```

The icons used by this project are embedded SVGs taken from https://github.com/tabler/tabler-icons and are included as inline SVG in the HTML templates.

Environment variables are paired with command line flags for all configuration options to allow flexibility in deployment and usage. These are all clearly documented alongside the commands they apply to in `docs/`.

## Documentation

All functionality is clearly and concisely documented in the `docs/` directory. When changes are made ensure the documentation is updated accordingly.

Documentation Files:

- `README.md` the high level marketing style overview of the project and its features
- `USAGE.md` the detailed usage instructions for all commands and features
- `CONFIG.md` the detailed configuration options (environment variables and flags) and their usage
- `DATABASE.md` the information about the database including migration instructions and the details of the schema

The projects main README.md should be kept concise and high level not being updated to reference new functionality or features, just sticking to a clear overview of the project.

## Testing

When performing testing and verification of the functionality, use a docker container running the `postgres:18` to allow for a complete testing environment.
Playwright is used for testing of the web interface when new functionality is added.
