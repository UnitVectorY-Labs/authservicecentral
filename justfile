
set dotenv-load := true

DB_USER := env_var_or_default("DB_USER", "postgres")
DB_PASSWORD := env_var_or_default("DB_PASSWORD", "postgres")
DB_NAME := env_var_or_default("DB_NAME", "authservicecentral")
CONFIG := env_var_or_default("SERVICEAUTH_CONFIG", "serviceauth.yaml")

# List all available commands
default:
  @just --list

# Build the Go application
build:
  go build ./...

# Run the Go tests
test:
  go test ./...

# Run database migrations
migrate:
  go run . migrate --config "{{CONFIG}}"

# Start the server
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
