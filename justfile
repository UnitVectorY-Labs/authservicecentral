
set dotenv-load := true

DB_USER := env("DB_USER")
DB_PASSWORD := env("DB_PASSWORD")
DB_NAME := env("DB_NAME")

# List all available commands
default:
  @just --list

tailwind:
  tailwindcss -i ./internal/web/static/tailwind.css -o ./internal/web/static/style.css

# Build the Go application
build:
  go build ./...

# Run the Go tests
test:
  go test ./...

# Run database migrations
migrate:
  go run . migrate up

# Start the server
serve:
  if [ ! -f dev-key.pem ]; then openssl genpkey -algorithm RSA -out dev-key.pem -pkeyopt rsa_keygen_bits:2048; fi
  go run . run --jwt-signing-key-file dev-key.pem --bootstrap-admin-password admin

# Run a local Postgres container for development
postgres-container:
  container rm -f authservicecentral-local-postgres || true
  container run --name authservicecentral-local-postgres \
    -e POSTGRES_USER="{{DB_USER}}" \
    -e POSTGRES_PASSWORD="{{DB_PASSWORD}}" \
    -e POSTGRES_DB="{{DB_NAME}}" \
    -p 5432:5432 \
    -d postgres:18