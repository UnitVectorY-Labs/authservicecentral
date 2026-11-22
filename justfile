
# Commands for authservicecentral
default:
  @just --list
# Build authservicecentral with Go
build:
  go build ./...

# Run tests for authservicecentral with Go
test:
  go clean -testcache
  go test ./...

# Serve documentation locally for testing (bootstraps local Jekyll setup)
docs-serve:
  #!/usr/bin/env bash
  set -euo pipefail
  cd docs

  if [[ ! -f Gemfile ]]; then
    printf '%s\n' \
      'source "https://rubygems.org"' \
      '' \
      'gem "github-pages", group: :jekyll_plugins' \
      'gem "jekyll-remote-theme"' \
      'gem "webrick"' > Gemfile
  fi

  bundle config set --local path vendor/bundle
  bundle check >/dev/null || bundle install
  bundle exec jekyll serve --host 127.0.0.1 --port 4000 --livereload

# Repository-specific commands
set dotenv-load := true

DB_USER := env_var_or_default("DB_USER", "postgres")
DB_PASSWORD := env_var_or_default("DB_PASSWORD", "postgres")
DB_NAME := env_var_or_default("DB_NAME", "authservicecentral")
CONFIG := env_var_or_default("SERVICEAUTH_CONFIG", "serviceauth.yaml")

# Run database migrations
migrate:
  go run . migrate --config "{{CONFIG}}"

# Start the server locally with a generated signing key
serve:
  if [ ! -f dev-key.pem ]; then openssl genpkey -algorithm RSA -out dev-key.pem -pkeyopt rsa_keygen_bits:2048; fi
  go run . run --config "{{CONFIG}}" --signing-key-file dev-key.pem --insecure-management

# Run a local Postgres container for development
postgres-container:
  container run --name authservicecentral-local-postgres \
    -e POSTGRES_USER="{{DB_USER}}" \
    -e POSTGRES_PASSWORD="{{DB_PASSWORD}}" \
    -e POSTGRES_DB="{{DB_NAME}}" \
    -p 5432:5432 \
    -d postgres:18
