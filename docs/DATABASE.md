# Database

`authservicecentral` uses PostgreSQL for persistent storage.

## Setup

Start a PostgreSQL instance:

```bash
docker run --name authservicecentral-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=appdb \
  -p 5432:5432 \
  -d postgres:18
```

## Migrations

Database migrations are embedded in the binary and managed using the `migrate` subcommand.

```bash
# Apply migrations
authservicecentral migrate up

# Roll back migrations
authservicecentral migrate down
```

Migrations use [golang-migrate](https://github.com/golang-migrate/migrate) with SQL files embedded via Go's `embed` package.

## Schema

TODO
