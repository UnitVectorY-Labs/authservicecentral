// Package operational contains process-level configuration. Authorization
// schema remains in the deployment YAML handled by internal/config.
package operational

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ConfigPath              string
	DatabaseURL             string
	Issuer                  string
	ListenAddress           string
	SigningKeyFile          string
	SigningProvider         string
	GCPKMSKey               string
	InactiveSigningKeyFiles []string
	ManagementOpen          bool
	SwaggerUI               bool
	MaxBatchSize            int
	HTTPTimeout             time.Duration
	ShutdownTimeout         time.Duration
	ReconcileInterval       time.Duration
	ReconcileBatch          int
	Metrics                 bool
	RateLimitPerSecond      float64
	RateLimitBurst          int
	BootstrapSource         string
	BootstrapSubject        string
	BootstrapRole           string
	ManagementAudience      string
	ManagementDisplayName   string
	ManagementTTL           int
}

func Parse(command string, args []string) (Config, error) {
	c := Config{
		ConfigPath:            env("SERVICEAUTH_CONFIG", "serviceauth.yaml"),
		DatabaseURL:           env("SERVICEAUTH_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/authservicecentral?sslmode=disable"),
		Issuer:                env("SERVICEAUTH_ISSUER", "http://localhost:8080"),
		ListenAddress:         env("SERVICEAUTH_LISTEN_ADDRESS", ":8080"),
		SigningKeyFile:        os.Getenv("SERVICEAUTH_SIGNING_KEY_FILE"),
		SigningProvider:       env("SERVICEAUTH_SIGNING_PROVIDER", "local"),
		GCPKMSKey:             os.Getenv("SERVICEAUTH_GCP_KMS_KEY"),
		ManagementOpen:        envBool("SERVICEAUTH_INSECURE_MANAGEMENT", false),
		SwaggerUI:             envBool("SERVICEAUTH_SWAGGER_UI", true),
		MaxBatchSize:          envInt("SERVICEAUTH_MAX_BATCH_SIZE", 100),
		HTTPTimeout:           envDuration("SERVICEAUTH_HTTP_TIMEOUT", 15*time.Second),
		ShutdownTimeout:       envDuration("SERVICEAUTH_SHUTDOWN_TIMEOUT", 15*time.Second),
		ReconcileInterval:     envDuration("SERVICEAUTH_RECONCILE_INTERVAL", 2*time.Second),
		ReconcileBatch:        envInt("SERVICEAUTH_RECONCILE_BATCH", 100),
		Metrics:               envBool("SERVICEAUTH_METRICS", true),
		RateLimitPerSecond:    envFloat("SERVICEAUTH_RATE_LIMIT_PER_SECOND", 0),
		RateLimitBurst:        envInt("SERVICEAUTH_RATE_LIMIT_BURST", 0),
		BootstrapSource:       os.Getenv("SERVICEAUTH_BOOTSTRAP_SOURCE"),
		BootstrapSubject:      os.Getenv("SERVICEAUTH_BOOTSTRAP_SUBJECT"),
		BootstrapRole:         os.Getenv("SERVICEAUTH_BOOTSTRAP_ROLE"),
		ManagementAudience:    env("SERVICEAUTH_MANAGEMENT_AUDIENCE", "serviceauth-management"),
		ManagementDisplayName: env("SERVICEAUTH_MANAGEMENT_DISPLAY_NAME", "ServiceAuth Management"),
		ManagementTTL:         envInt("SERVICEAUTH_MANAGEMENT_TTL", 900),
	}
	inactiveKeys := os.Getenv("SERVICEAUTH_INACTIVE_SIGNING_KEY_FILES")
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.StringVar(&c.ConfigPath, "config", c.ConfigPath, "deployment authorization YAML")
	fs.StringVar(&c.DatabaseURL, "database-url", c.DatabaseURL, "PostgreSQL connection URL")
	fs.StringVar(&c.Issuer, "issuer", c.Issuer, "canonical platform JWT issuer URL")
	fs.StringVar(&c.ListenAddress, "listen-address", c.ListenAddress, "HTTP listen address")
	fs.StringVar(&c.SigningKeyFile, "signing-key-file", c.SigningKeyFile, "PEM private signing key")
	fs.StringVar(&c.SigningProvider, "signing-provider", c.SigningProvider, "signing provider: local or gcp-kms")
	fs.StringVar(&c.GCPKMSKey, "gcp-kms-key", c.GCPKMSKey, "GCP KMS asymmetric key version resource name")
	fs.StringVar(&inactiveKeys, "inactive-signing-key-files", inactiveKeys, "comma-separated inactive local signing keys published for verification")
	fs.BoolVar(&c.ManagementOpen, "insecure-management", c.ManagementOpen, "allow unauthenticated management API (development only)")
	fs.BoolVar(&c.SwaggerUI, "swagger-ui", c.SwaggerUI, "serve the Swagger UI and OpenAPI document at the application root")
	fs.IntVar(&c.MaxBatchSize, "max-batch-size", c.MaxBatchSize, "maximum checks per authorization request")
	fs.DurationVar(&c.HTTPTimeout, "http-timeout", c.HTTPTimeout, "HTTP server read/write timeout")
	fs.DurationVar(&c.ShutdownTimeout, "shutdown-timeout", c.ShutdownTimeout, "graceful HTTP shutdown timeout")
	fs.DurationVar(&c.ReconcileInterval, "reconcile-interval", c.ReconcileInterval, "authorization outbox reconciliation interval")
	fs.IntVar(&c.ReconcileBatch, "reconcile-batch", c.ReconcileBatch, "authorization outbox reconciliation batch size")
	fs.BoolVar(&c.Metrics, "metrics", c.Metrics, "enable the metrics endpoint")
	fs.Float64Var(&c.RateLimitPerSecond, "rate-limit-per-second", c.RateLimitPerSecond, "global HTTP request rate limit; zero disables")
	fs.IntVar(&c.RateLimitBurst, "rate-limit-burst", c.RateLimitBurst, "global HTTP rate-limit burst; zero disables")
	fs.StringVar(&c.BootstrapSource, "source", c.BootstrapSource, "bootstrap principal token-source prefix")
	fs.StringVar(&c.BootstrapSubject, "subject", c.BootstrapSubject, "bootstrap principal subject")
	fs.StringVar(&c.BootstrapRole, "role", c.BootstrapRole, "management-capable role to grant")
	fs.StringVar(&c.ManagementAudience, "management-audience", c.ManagementAudience, "management audience ID")
	fs.StringVar(&c.ManagementDisplayName, "management-display-name", c.ManagementDisplayName, "management audience display name")
	fs.IntVar(&c.ManagementTTL, "management-ttl", c.ManagementTTL, "management audience token TTL in seconds")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if len(fs.Args()) != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	for _, path := range strings.Split(inactiveKeys, ",") {
		if path = strings.TrimSpace(path); path != "" {
			c.InactiveSigningKeyFiles = append(c.InactiveSigningKeyFiles, path)
		}
	}
	if c.ConfigPath == "" {
		return Config{}, fmt.Errorf("--config is required")
	}
	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("--database-url is required")
	}
	issuerURL, err := url.Parse(c.Issuer)
	if err != nil || (issuerURL.Scheme != "http" && issuerURL.Scheme != "https") || issuerURL.Host == "" {
		return Config{}, fmt.Errorf("--issuer must be an absolute HTTP(S) URL")
	}
	if c.ListenAddress == "" {
		return Config{}, fmt.Errorf("--listen-address is required")
	}
	if c.MaxBatchSize < 1 || c.MaxBatchSize > 1000 {
		return Config{}, fmt.Errorf("--max-batch-size must be between 1 and 1000")
	}
	if c.HTTPTimeout <= 0 {
		return Config{}, fmt.Errorf("--http-timeout must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return Config{}, fmt.Errorf("--shutdown-timeout must be positive")
	}
	if c.ReconcileInterval <= 0 {
		return Config{}, fmt.Errorf("--reconcile-interval must be positive")
	}
	if c.ReconcileBatch < 1 || c.ReconcileBatch > 1000 {
		return Config{}, fmt.Errorf("--reconcile-batch must be between 1 and 1000")
	}
	if c.RateLimitPerSecond < 0 || c.RateLimitBurst < 0 {
		return Config{}, fmt.Errorf("rate limits cannot be negative")
	}
	if (c.RateLimitPerSecond == 0) != (c.RateLimitBurst == 0) {
		return Config{}, fmt.Errorf("rate limit and burst must both be zero or both be positive")
	}
	needsSigner := command == "run" || command == "api" || command == "doctor"
	switch c.SigningProvider {
	case "local":
		if c.GCPKMSKey != "" {
			return Config{}, fmt.Errorf("--gcp-kms-key requires --signing-provider=gcp-kms")
		}
		if needsSigner && c.SigningKeyFile == "" {
			return Config{}, fmt.Errorf("--signing-key-file is required for the local signing provider")
		}
	case "gcp-kms":
		if c.SigningKeyFile != "" {
			return Config{}, fmt.Errorf("--signing-key-file cannot be used with --signing-provider=gcp-kms")
		}
		if needsSigner && c.GCPKMSKey == "" {
			return Config{}, fmt.Errorf("--gcp-kms-key is required for the GCP KMS signing provider")
		}
	default:
		return Config{}, fmt.Errorf("--signing-provider must be local or gcp-kms")
	}
	if command == "bootstrap" {
		if strings.TrimSpace(c.BootstrapSource) == "" {
			return Config{}, fmt.Errorf("--source is required")
		}
		if strings.TrimSpace(c.BootstrapSubject) == "" {
			return Config{}, fmt.Errorf("--subject is required")
		}
		if strings.TrimSpace(c.BootstrapRole) == "" {
			return Config{}, fmt.Errorf("--role is required")
		}
		if strings.TrimSpace(c.ManagementAudience) == "" {
			return Config{}, fmt.Errorf("--management-audience is required")
		}
		if c.ManagementTTL <= 0 {
			return Config{}, fmt.Errorf("--management-ttl must be positive")
		}
	}
	return c, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}
func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return parsed
}
func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}
func envFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return parsed
}
