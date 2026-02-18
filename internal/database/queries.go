package database

import (
	"context"
	"database/sql"
	"fmt"
)

// Credential represents a row from application_credentials
type Credential struct {
	ID            int64
	ApplicationID int64
	ClientID      string
	SecretHash    string
	DisabledAt    sql.NullTime
}

// Application represents a row from applications
type Application struct {
	ID      int64
	Subject string
	AppType string
	Locked  bool
}

// Authorization represents a row from authorizations
type Authorization struct {
	SubjectApplicationID  int64
	AudienceApplicationID int64
	Enabled               bool
}

// LookupCredentialByClientID retrieves an active credential by client_id
func LookupCredentialByClientID(ctx context.Context, db *sql.DB, clientID string) (*Credential, error) {
	var c Credential
	err := db.QueryRowContext(ctx,
		`SELECT id, application_id, client_id, secret_hash, disabled_at
		 FROM application_credentials
		 WHERE client_id = $1`,
		clientID,
	).Scan(&c.ID, &c.ApplicationID, &c.ClientID, &c.SecretHash, &c.DisabledAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup credential: %w", err)
	}
	return &c, nil
}

// LookupApplicationByID retrieves an application by its ID
func LookupApplicationByID(ctx context.Context, db *sql.DB, id int64) (*Application, error) {
	var a Application
	err := db.QueryRowContext(ctx,
		`SELECT id, subject, app_type, locked
		 FROM applications
		 WHERE id = $1`,
		id,
	).Scan(&a.ID, &a.Subject, &a.AppType, &a.Locked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup application by id: %w", err)
	}
	return &a, nil
}

// LookupApplicationBySubject retrieves an application by its subject
func LookupApplicationBySubject(ctx context.Context, db *sql.DB, subject string) (*Application, error) {
	var a Application
	err := db.QueryRowContext(ctx,
		`SELECT id, subject, app_type, locked
		 FROM applications
		 WHERE subject = $1`,
		subject,
	).Scan(&a.ID, &a.Subject, &a.AppType, &a.Locked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup application by subject: %w", err)
	}
	return &a, nil
}

// LookupAuthorization checks if a subject application is authorized to access an audience application
func LookupAuthorization(ctx context.Context, db *sql.DB, subjectAppID, audienceAppID int64) (*Authorization, error) {
	var auth Authorization
	err := db.QueryRowContext(ctx,
		`SELECT subject_application_id, audience_application_id, enabled
		 FROM authorizations
		 WHERE subject_application_id = $1 AND audience_application_id = $2`,
		subjectAppID, audienceAppID,
	).Scan(&auth.SubjectApplicationID, &auth.AudienceApplicationID, &auth.Enabled)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup authorization: %w", err)
	}
	return &auth, nil
}

// LookupAuthorizedScopes retrieves the allowed scopes for a subject-audience pair
func LookupAuthorizedScopes(ctx context.Context, db *sql.DB, subjectAppID, audienceAppID int64) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT scope
		 FROM authorization_scopes
		 WHERE subject_application_id = $1 AND audience_application_id = $2`,
		subjectAppID, audienceAppID,
	)
	if err != nil {
		return nil, fmt.Errorf("lookup authorized scopes: %w", err)
	}
	defer rows.Close()

	var scopes []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan scope: %w", err)
		}
		scopes = append(scopes, s)
	}
	return scopes, rows.Err()
}
