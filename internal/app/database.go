package app

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func OpenDatabase(ctx context.Context, databaseURL string) (*database.Store, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("database URL is required")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	store := database.New(db)
	if err := store.Ping(ctx); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}
