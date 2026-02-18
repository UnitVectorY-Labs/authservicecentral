package cmd

import (
	"fmt"
	"log"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

// Migrate executes the migrate subcommand
func Migrate(args []string) error {
	cfg, direction, err := config.ParseMigrateFlags(args)
	if err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	log.Printf("running migration %s on %s:%d/%s", direction, cfg.DBHost, cfg.DBPort, cfg.DBName)

	if err := database.Migrate(cfg, direction); err != nil {
		return fmt.Errorf("migration %s: %w", direction, err)
	}

	log.Printf("migration %s completed successfully", direction)
	return nil
}
