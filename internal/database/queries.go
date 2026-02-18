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

// User represents a row from the users table
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Locked       bool
}

// LookupUserByUsername retrieves a user by username
func LookupUserByUsername(ctx context.Context, db *sql.DB, username string) (*User, error) {
	var u User
	err := db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, locked
		 FROM users
		 WHERE username = $1`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Locked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup user: %w", err)
	}
	return &u, nil
}

// CreateUser inserts a new user and returns the created user
func CreateUser(ctx context.Context, db *sql.DB, username, passwordHash string) (*User, error) {
	var u User
	err := db.QueryRowContext(ctx,
		`INSERT INTO users (username, password_hash)
		 VALUES ($1, $2)
		 RETURNING id, username, password_hash, locked`,
		username, passwordHash,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Locked)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &u, nil
}

// UpdateUserLastLogin updates the last_login_at timestamp for a user
func UpdateUserLastLogin(ctx context.Context, db *sql.DB, userID int64) error {
	_, err := db.ExecContext(ctx,
		`UPDATE users SET last_login_at = now() WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	return nil
}

// ApplicationListItem represents an application in a list view
type ApplicationListItem struct {
	ID          int64
	Subject     string
	Description sql.NullString
	AppType     string
	Locked      bool
}

// ListApplications retrieves a paginated list of applications
func ListApplications(ctx context.Context, db *sql.DB, search string, limit, offset int) ([]ApplicationListItem, error) {
	var rows *sql.Rows
	var err error

	if search != "" {
		pattern := "%" + search + "%"
		rows, err = db.QueryContext(ctx,
			`SELECT id, subject, description, app_type, locked
			 FROM applications
			 WHERE subject ILIKE $1 OR description ILIKE $1
			 ORDER BY subject ASC
			 LIMIT $2 OFFSET $3`,
			pattern, limit, offset,
		)
	} else {
		rows, err = db.QueryContext(ctx,
			`SELECT id, subject, description, app_type, locked
			 FROM applications
			 ORDER BY subject ASC
			 LIMIT $1 OFFSET $2`,
			limit, offset,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()

	var apps []ApplicationListItem
	for rows.Next() {
		var a ApplicationListItem
		if err := rows.Scan(&a.ID, &a.Subject, &a.Description, &a.AppType, &a.Locked); err != nil {
			return nil, fmt.Errorf("scan application: %w", err)
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

// CountApplications returns the total number of applications
func CountApplications(ctx context.Context, db *sql.DB, search string) (int, error) {
	var count int
	var err error

	if search != "" {
		pattern := "%" + search + "%"
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM applications
			 WHERE subject ILIKE $1 OR description ILIKE $1`,
			pattern,
		).Scan(&count)
	} else {
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM applications`,
		).Scan(&count)
	}
	if err != nil {
		return 0, fmt.Errorf("count applications: %w", err)
	}
	return count, nil
}
