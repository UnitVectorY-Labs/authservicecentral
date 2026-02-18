package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Database
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	// Server
	HTTPAddr string
	HTTPPort int

	// Planes
	ControlPlaneEnabled bool
	DataPlaneEnabled    bool

	// Bootstrap
	BootstrapAdminPassword string

	// JWT
	JWTIssuer                  string
	JWTTTL                     time.Duration
	JWTSigningKeyFile          string
	JWTInactiveSigningKeyFiles []string
	JWTVerifyKeyFiles          []string
}

// DatabaseDSN returns the Postgres connection string
func (c *Config) DatabaseDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.DBHost, c.DBPort, c.DBUser, c.DBPassword, c.DBName, c.DBSSLMode,
	)
}

// DatabaseURL returns the Postgres connection URL for migrations
func (c *Config) DatabaseURL() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName, c.DBSSLMode,
	)
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envOrDefaultInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}

func envOrDefaultBool(key string, defaultVal bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return defaultVal
}

func envOrDefaultDuration(key string, defaultVal time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultVal
}

// ParseDBFlags parses the common database flags
func ParseDBFlags(fs *flag.FlagSet, cfg *Config) {
	fs.StringVar(&cfg.DBHost, "db-host", envOrDefault("DB_HOST", "localhost"), "Postgres host")
	fs.IntVar(&cfg.DBPort, "db-port", envOrDefaultInt("DB_PORT", 5432), "Postgres port")
	fs.StringVar(&cfg.DBUser, "db-user", envOrDefault("DB_USER", "postgres"), "Postgres user")
	fs.StringVar(&cfg.DBPassword, "db-password", envOrDefault("DB_PASSWORD", "postgres"), "Postgres password")
	fs.StringVar(&cfg.DBName, "db-name", envOrDefault("DB_NAME", "appdb"), "Postgres database name")
	fs.StringVar(&cfg.DBSSLMode, "db-sslmode", envOrDefault("DB_SSLMODE", "disable"), "Postgres SSL mode")
}

// ParseRunFlags parses the run subcommand flags
func ParseRunFlags(args []string) (*Config, error) {
	cfg := &Config{}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)

	ParseDBFlags(fs, cfg)

	fs.StringVar(&cfg.HTTPAddr, "http-addr", envOrDefault("HTTP_ADDR", "0.0.0.0"), "Bind address")
	fs.IntVar(&cfg.HTTPPort, "http-port", envOrDefaultInt("HTTP_PORT", 8080), "Bind port")
	fs.BoolVar(&cfg.ControlPlaneEnabled, "control-plane-enabled", envOrDefaultBool("CONTROL_PLANE_ENABLED", true), "Enable control plane")
	fs.BoolVar(&cfg.DataPlaneEnabled, "data-plane-enabled", envOrDefaultBool("DATA_PLANE_ENABLED", true), "Enable data plane")
	fs.StringVar(&cfg.BootstrapAdminPassword, "bootstrap-admin-password", envOrDefault("BOOTSTRAP_ADMIN_PASSWORD", ""), "Bootstrap admin password")

	fs.StringVar(&cfg.JWTIssuer, "jwt-issuer", envOrDefault("JWT_ISSUER", "http://localhost:8080"), "JWT issuer claim")

	ttlDefault := envOrDefaultDuration("JWT_TTL", 60*time.Minute)
	fs.DurationVar(&cfg.JWTTTL, "jwt-ttl", ttlDefault, "JWT lifetime")

	fs.StringVar(&cfg.JWTSigningKeyFile, "jwt-signing-key-file", envOrDefault("JWT_SIGNING_KEY_FILE", ""), "Path to private signing key")

	var inactiveKeys string
	fs.StringVar(&inactiveKeys, "jwt-inactive-signing-key-files", envOrDefault("JWT_INACTIVE_SIGNING_KEY_FILES", ""), "Comma-separated paths to inactive signing keys")

	var verifyKeys string
	fs.StringVar(&verifyKeys, "jwt-verify-key-files", envOrDefault("JWT_VERIFY_KEY_FILES", ""), "Comma-separated paths to verify-only public keys")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if inactiveKeys != "" {
		cfg.JWTInactiveSigningKeyFiles = strings.Split(inactiveKeys, ",")
	}
	if verifyKeys != "" {
		cfg.JWTVerifyKeyFiles = strings.Split(verifyKeys, ",")
	}

	return cfg, nil
}

// ParseMigrateFlags parses the migrate subcommand flags
func ParseMigrateFlags(args []string) (*Config, string, error) {
	cfg := &Config{}
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)

	ParseDBFlags(fs, cfg)

	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}

	direction := fs.Arg(0)
	if direction != "up" && direction != "down" {
		return nil, "", fmt.Errorf("migrate requires direction: up or down")
	}

	return cfg, direction, nil
}
