package config

import (
	"os"
	"testing"
	"time"
)

func TestParseRunFlagsDefaults(t *testing.T) {
	cfg, err := ParseRunFlags([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DBHost != "localhost" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "localhost")
	}
	if cfg.DBPort != 5432 {
		t.Errorf("DBPort = %d, want %d", cfg.DBPort, 5432)
	}
	if cfg.DBUser != "postgres" {
		t.Errorf("DBUser = %q, want %q", cfg.DBUser, "postgres")
	}
	if cfg.DBPassword != "postgres" {
		t.Errorf("DBPassword = %q, want %q", cfg.DBPassword, "postgres")
	}
	if cfg.DBName != "appdb" {
		t.Errorf("DBName = %q, want %q", cfg.DBName, "appdb")
	}
	if cfg.DBSSLMode != "disable" {
		t.Errorf("DBSSLMode = %q, want %q", cfg.DBSSLMode, "disable")
	}
	if cfg.HTTPAddr != "0.0.0.0" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, "0.0.0.0")
	}
	if cfg.HTTPPort != 8080 {
		t.Errorf("HTTPPort = %d, want %d", cfg.HTTPPort, 8080)
	}
	if !cfg.ControlPlaneEnabled {
		t.Error("ControlPlaneEnabled should default to true")
	}
	if !cfg.DataPlaneEnabled {
		t.Error("DataPlaneEnabled should default to true")
	}
	if cfg.JWTIssuer != "http://localhost:8080" {
		t.Errorf("JWTIssuer = %q, want %q", cfg.JWTIssuer, "http://localhost:8080")
	}
	if cfg.JWTTTL != 60*time.Minute {
		t.Errorf("JWTTTL = %v, want %v", cfg.JWTTTL, 60*time.Minute)
	}
}

func TestParseRunFlagsOverrides(t *testing.T) {
	cfg, err := ParseRunFlags([]string{
		"--db-host", "db.example.com",
		"--db-port", "5433",
		"--http-port", "9090",
		"--jwt-issuer", "https://auth.example.com",
		"--jwt-ttl", "30m",
		"--jwt-signing-key-file", "/path/to/key.pem",
		"--control-plane-enabled=false",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DBHost != "db.example.com" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "db.example.com")
	}
	if cfg.DBPort != 5433 {
		t.Errorf("DBPort = %d, want %d", cfg.DBPort, 5433)
	}
	if cfg.HTTPPort != 9090 {
		t.Errorf("HTTPPort = %d, want %d", cfg.HTTPPort, 9090)
	}
	if cfg.JWTIssuer != "https://auth.example.com" {
		t.Errorf("JWTIssuer = %q, want %q", cfg.JWTIssuer, "https://auth.example.com")
	}
	if cfg.JWTTTL != 30*time.Minute {
		t.Errorf("JWTTTL = %v, want %v", cfg.JWTTTL, 30*time.Minute)
	}
	if cfg.JWTSigningKeyFile != "/path/to/key.pem" {
		t.Errorf("JWTSigningKeyFile = %q, want %q", cfg.JWTSigningKeyFile, "/path/to/key.pem")
	}
	if cfg.ControlPlaneEnabled {
		t.Error("ControlPlaneEnabled should be false")
	}
}

func TestParseRunFlagsEnvVars(t *testing.T) {
	os.Setenv("DB_HOST", "envhost")
	os.Setenv("HTTP_PORT", "7070")
	os.Setenv("JWT_ISSUER", "https://env.example.com")
	defer func() {
		os.Unsetenv("DB_HOST")
		os.Unsetenv("HTTP_PORT")
		os.Unsetenv("JWT_ISSUER")
	}()

	cfg, err := ParseRunFlags([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DBHost != "envhost" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "envhost")
	}
	if cfg.HTTPPort != 7070 {
		t.Errorf("HTTPPort = %d, want %d", cfg.HTTPPort, 7070)
	}
	if cfg.JWTIssuer != "https://env.example.com" {
		t.Errorf("JWTIssuer = %q, want %q", cfg.JWTIssuer, "https://env.example.com")
	}
}

func TestParseRunFlagsFlagsOverrideEnv(t *testing.T) {
	os.Setenv("DB_HOST", "envhost")
	defer os.Unsetenv("DB_HOST")

	cfg, err := ParseRunFlags([]string{"--db-host", "flaghost"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DBHost != "flaghost" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "flaghost")
	}
}

func TestParseMigrateFlags(t *testing.T) {
	cfg, dir, err := ParseMigrateFlags([]string{"up"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dir != "up" {
		t.Errorf("direction = %q, want %q", dir, "up")
	}
	if cfg.DBHost != "localhost" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "localhost")
	}

	_, dir, err = ParseMigrateFlags([]string{"down"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dir != "down" {
		t.Errorf("direction = %q, want %q", dir, "down")
	}
}

func TestParseMigrateFlagsInvalidDirection(t *testing.T) {
	_, _, err := ParseMigrateFlags([]string{"sideways"})
	if err == nil {
		t.Fatal("expected error for invalid direction")
	}
}

func TestDatabaseDSN(t *testing.T) {
	cfg := &Config{
		DBHost:     "myhost",
		DBPort:     5433,
		DBUser:     "myuser",
		DBPassword: "mypass",
		DBName:     "mydb",
		DBSSLMode:  "require",
	}

	dsn := cfg.DatabaseDSN()
	expected := "host=myhost port=5433 user=myuser password=mypass dbname=mydb sslmode=require"
	if dsn != expected {
		t.Errorf("DatabaseDSN() = %q, want %q", dsn, expected)
	}
}

func TestDatabaseURL(t *testing.T) {
	cfg := &Config{
		DBHost:     "myhost",
		DBPort:     5433,
		DBUser:     "myuser",
		DBPassword: "mypass",
		DBName:     "mydb",
		DBSSLMode:  "require",
	}

	url := cfg.DatabaseURL()
	expected := "postgres://myuser:mypass@myhost:5433/mydb?sslmode=require"
	if url != expected {
		t.Errorf("DatabaseURL() = %q, want %q", url, expected)
	}
}
