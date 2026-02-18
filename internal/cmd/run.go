package cmd

import (
	"fmt"
	"log"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/jwt"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/web"
)

// Run executes the run subcommand
func Run(args []string) error {
	cfg, err := config.ParseRunFlags(args)
	if err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	// Validate required configuration
	if cfg.DataPlaneEnabled && cfg.JWTSigningKeyFile == "" {
		return fmt.Errorf("jwt-signing-key-file is required when data plane is enabled")
	}

	// Load JWT keys
	keyStore, err := jwt.LoadKeyStore(cfg)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}

	// Connect to database
	db, err := database.Open(cfg)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer db.Close()

	log.Printf("connected to database %s:%d/%s", cfg.DBHost, cfg.DBPort, cfg.DBName)

	if keyStore.SigningKey != nil {
		log.Printf("signing key loaded: kid=%s alg=%s", keyStore.SigningKey.Kid, keyStore.SigningKey.Algorithm)
	}
	log.Printf("JWKS endpoint will serve %d key(s)", len(keyStore.AllKeys))

	// Start the server
	srv := web.NewServer(cfg, db, keyStore)
	return srv.ListenAndServe()
}
