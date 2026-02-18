package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
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

// ApplicationDetail represents full application details
type ApplicationDetail struct {
	ID          int64
	Subject     string
	Description sql.NullString
	AppType     string
	Locked      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ApplicationScope represents a row from application_scopes
type ApplicationScope struct {
	Scope       string
	Description sql.NullString
	CreatedAt   time.Time
}

// ApplicationCredential represents a credential for display (no secret hash)
type ApplicationCredential struct {
	ID            int64
	ApplicationID int64
	ClientID      string
	Label         sql.NullString
	CreatedAt     time.Time
	DisabledAt    sql.NullTime
}

// AuthorizationListItem represents an authorization with subject/audience info
type AuthorizationListItem struct {
	SubjectApplicationID  int64
	AudienceApplicationID int64
	SubjectSubject        string
	AudienceSubject       string
	Enabled               bool
	Description           sql.NullString
}

// IdentityProviderListItem represents an identity provider in a list view
type IdentityProviderListItem struct {
	ID           int64
	Name         string
	ProviderType string
	IssuerURL    string
	CreatedAt    time.Time
}

// IdentityProvider represents a full identity provider row
type IdentityProvider struct {
	ID           int64
	Name         string
	ProviderType string
	IssuerURL    string
	JWKSURL      sql.NullString
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// WorkloadListItem represents a workload in a list view
type WorkloadListItem struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

// Workload represents a full workload row
type Workload struct {
	ID                 int64
	IdentityProviderID int64
	Name               string
	Selector           json.RawMessage
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// ApplicationWorkloadItem represents a workload linked to an application
type ApplicationWorkloadItem struct {
	WorkloadID         int64
	WorkloadName       string
	IdentityProviderID int64
	ProviderName       string
}

// JWKCacheEntry represents a cached JWK
type JWKCacheEntry struct {
	JWKSURL   string
	KID       string
	Found     bool
	JWK       json.RawMessage
	FetchedAt time.Time
	ExpiresAt time.Time
}

// WorkloadWithProvider represents a workload with its provider info
type WorkloadWithProvider struct {
	WorkloadID         int64
	Selector           json.RawMessage
	IdentityProviderID int64
	IssuerURL          string
	JWKSURL            sql.NullString
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

// CreateApplication inserts a new application and returns it
func CreateApplication(ctx context.Context, db *sql.DB, subject, description, appType string) (*Application, error) {
	var a Application
	err := db.QueryRowContext(ctx,
		`INSERT INTO applications (subject, description, app_type)
		 VALUES ($1, $2, $3)
		 RETURNING id, subject, app_type, locked`,
		subject, description, appType,
	).Scan(&a.ID, &a.Subject, &a.AppType, &a.Locked)
	if err != nil {
		return nil, fmt.Errorf("create application: %w", err)
	}
	return &a, nil
}

// UpdateApplication updates an application's description and locked status
func UpdateApplication(ctx context.Context, db *sql.DB, id int64, description string, locked bool) error {
	_, err := db.ExecContext(ctx,
		`UPDATE applications SET description = $1, locked = $2, updated_at = now()
		 WHERE id = $3`,
		description, locked, id,
	)
	if err != nil {
		return fmt.Errorf("update application: %w", err)
	}
	return nil
}

// GetApplicationDetail retrieves full application details by subject
func GetApplicationDetail(ctx context.Context, db *sql.DB, subject string) (*ApplicationDetail, error) {
	var a ApplicationDetail
	err := db.QueryRowContext(ctx,
		`SELECT id, subject, description, app_type, locked, created_at, updated_at
		 FROM applications
		 WHERE subject = $1`,
		subject,
	).Scan(&a.ID, &a.Subject, &a.Description, &a.AppType, &a.Locked, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get application detail: %w", err)
	}
	return &a, nil
}

// ListApplicationScopes retrieves all scopes for an application
func ListApplicationScopes(ctx context.Context, db *sql.DB, applicationID int64) ([]ApplicationScope, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT scope, description, created_at
		 FROM application_scopes
		 WHERE application_id = $1
		 ORDER BY scope ASC`,
		applicationID,
	)
	if err != nil {
		return nil, fmt.Errorf("list application scopes: %w", err)
	}
	defer rows.Close()

	var scopes []ApplicationScope
	for rows.Next() {
		var s ApplicationScope
		if err := rows.Scan(&s.Scope, &s.Description, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan application scope: %w", err)
		}
		scopes = append(scopes, s)
	}
	return scopes, rows.Err()
}

// CreateApplicationScope adds a scope to an application
func CreateApplicationScope(ctx context.Context, db *sql.DB, applicationID int64, scope, description string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO application_scopes (application_id, scope, description)
		 VALUES ($1, $2, $3)`,
		applicationID, scope, description,
	)
	if err != nil {
		return fmt.Errorf("create application scope: %w", err)
	}
	return nil
}

// DeleteApplicationScope removes a scope from an application
func DeleteApplicationScope(ctx context.Context, db *sql.DB, applicationID int64, scope string) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM application_scopes
		 WHERE application_id = $1 AND scope = $2`,
		applicationID, scope,
	)
	if err != nil {
		return fmt.Errorf("delete application scope: %w", err)
	}
	return nil
}

// ListApplicationCredentials retrieves credentials for an application
func ListApplicationCredentials(ctx context.Context, db *sql.DB, applicationID int64) ([]ApplicationCredential, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, application_id, client_id, label, created_at, disabled_at
		 FROM application_credentials
		 WHERE application_id = $1
		 ORDER BY created_at DESC`,
		applicationID,
	)
	if err != nil {
		return nil, fmt.Errorf("list application credentials: %w", err)
	}
	defer rows.Close()

	var creds []ApplicationCredential
	for rows.Next() {
		var c ApplicationCredential
		if err := rows.Scan(&c.ID, &c.ApplicationID, &c.ClientID, &c.Label, &c.CreatedAt, &c.DisabledAt); err != nil {
			return nil, fmt.Errorf("scan application credential: %w", err)
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

// CreateApplicationCredential creates a new credential for an application
func CreateApplicationCredential(ctx context.Context, db *sql.DB, applicationID int64, clientID, secretHash, label string) (*ApplicationCredential, error) {
	var c ApplicationCredential
	err := db.QueryRowContext(ctx,
		`INSERT INTO application_credentials (application_id, credential_type, client_id, secret_hash, label)
		 VALUES ($1, 'client_secret', $2, $3, $4)
		 RETURNING id, application_id, client_id, label, created_at, disabled_at`,
		applicationID, clientID, secretHash, label,
	).Scan(&c.ID, &c.ApplicationID, &c.ClientID, &c.Label, &c.CreatedAt, &c.DisabledAt)
	if err != nil {
		return nil, fmt.Errorf("create application credential: %w", err)
	}
	return &c, nil
}

// DisableApplicationCredential sets disabled_at to now for a credential
func DisableApplicationCredential(ctx context.Context, db *sql.DB, credentialID int64) error {
	_, err := db.ExecContext(ctx,
		`UPDATE application_credentials SET disabled_at = now()
		 WHERE id = $1`,
		credentialID,
	)
	if err != nil {
		return fmt.Errorf("disable application credential: %w", err)
	}
	return nil
}

// CountActiveCredentials counts credentials where disabled_at IS NULL
func CountActiveCredentials(ctx context.Context, db *sql.DB, applicationID int64) (int, error) {
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM application_credentials
		 WHERE application_id = $1 AND disabled_at IS NULL`,
		applicationID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active credentials: %w", err)
	}
	return count, nil
}

// ListOutboundAuthorizations lists all audience apps this subject is authorized to access
func ListOutboundAuthorizations(ctx context.Context, db *sql.DB, subjectAppID int64) ([]AuthorizationListItem, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT a.subject_application_id, a.audience_application_id,
		        sa.subject AS subject_subject, aa.subject AS audience_subject,
		        a.enabled, a.description
		 FROM authorizations a
		 JOIN applications sa ON sa.id = a.subject_application_id
		 JOIN applications aa ON aa.id = a.audience_application_id
		 WHERE a.subject_application_id = $1
		 ORDER BY aa.subject ASC`,
		subjectAppID,
	)
	if err != nil {
		return nil, fmt.Errorf("list outbound authorizations: %w", err)
	}
	defer rows.Close()

	var items []AuthorizationListItem
	for rows.Next() {
		var item AuthorizationListItem
		if err := rows.Scan(&item.SubjectApplicationID, &item.AudienceApplicationID,
			&item.SubjectSubject, &item.AudienceSubject,
			&item.Enabled, &item.Description); err != nil {
			return nil, fmt.Errorf("scan outbound authorization: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListInboundAuthorizations lists all subject apps authorized to access this audience
func ListInboundAuthorizations(ctx context.Context, db *sql.DB, audienceAppID int64) ([]AuthorizationListItem, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT a.subject_application_id, a.audience_application_id,
		        sa.subject AS subject_subject, aa.subject AS audience_subject,
		        a.enabled, a.description
		 FROM authorizations a
		 JOIN applications sa ON sa.id = a.subject_application_id
		 JOIN applications aa ON aa.id = a.audience_application_id
		 WHERE a.audience_application_id = $1
		 ORDER BY sa.subject ASC`,
		audienceAppID,
	)
	if err != nil {
		return nil, fmt.Errorf("list inbound authorizations: %w", err)
	}
	defer rows.Close()

	var items []AuthorizationListItem
	for rows.Next() {
		var item AuthorizationListItem
		if err := rows.Scan(&item.SubjectApplicationID, &item.AudienceApplicationID,
			&item.SubjectSubject, &item.AudienceSubject,
			&item.Enabled, &item.Description); err != nil {
			return nil, fmt.Errorf("scan inbound authorization: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// CreateAuthorization inserts a new authorization
func CreateAuthorization(ctx context.Context, db *sql.DB, subjectAppID, audienceAppID int64, description string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO authorizations (subject_application_id, audience_application_id, description)
		 VALUES ($1, $2, $3)`,
		subjectAppID, audienceAppID, description,
	)
	if err != nil {
		return fmt.Errorf("create authorization: %w", err)
	}
	return nil
}

// UpdateAuthorization updates the enabled status of an authorization
func UpdateAuthorization(ctx context.Context, db *sql.DB, subjectAppID, audienceAppID int64, enabled bool) error {
	_, err := db.ExecContext(ctx,
		`UPDATE authorizations SET enabled = $1, updated_at = now()
		 WHERE subject_application_id = $2 AND audience_application_id = $3`,
		enabled, subjectAppID, audienceAppID,
	)
	if err != nil {
		return fmt.Errorf("update authorization: %w", err)
	}
	return nil
}

// DeleteAuthorization deletes an authorization (cascades to scopes)
func DeleteAuthorization(ctx context.Context, db *sql.DB, subjectAppID, audienceAppID int64) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM authorizations
		 WHERE subject_application_id = $1 AND audience_application_id = $2`,
		subjectAppID, audienceAppID,
	)
	if err != nil {
		return fmt.Errorf("delete authorization: %w", err)
	}
	return nil
}

// CreateAuthorizationScope adds a scope to an authorization
func CreateAuthorizationScope(ctx context.Context, db *sql.DB, subjectAppID, audienceAppID int64, scope string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO authorization_scopes (subject_application_id, audience_application_id, scope)
		 VALUES ($1, $2, $3)`,
		subjectAppID, audienceAppID, scope,
	)
	if err != nil {
		return fmt.Errorf("create authorization scope: %w", err)
	}
	return nil
}

// DeleteAuthorizationScope removes a scope from an authorization
func DeleteAuthorizationScope(ctx context.Context, db *sql.DB, subjectAppID, audienceAppID int64, scope string) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM authorization_scopes
		 WHERE subject_application_id = $1 AND audience_application_id = $2 AND scope = $3`,
		subjectAppID, audienceAppID, scope,
	)
	if err != nil {
		return fmt.Errorf("delete authorization scope: %w", err)
	}
	return nil
}

// ListIdentityProviders retrieves a paginated list of identity providers
func ListIdentityProviders(ctx context.Context, db *sql.DB, limit, offset int) ([]IdentityProviderListItem, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, provider_type, issuer_url, created_at
		 FROM identity_providers
		 ORDER BY name ASC
		 LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list identity providers: %w", err)
	}
	defer rows.Close()

	var providers []IdentityProviderListItem
	for rows.Next() {
		var p IdentityProviderListItem
		if err := rows.Scan(&p.ID, &p.Name, &p.ProviderType, &p.IssuerURL, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan identity provider: %w", err)
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

// CountIdentityProviders returns the total number of identity providers
func CountIdentityProviders(ctx context.Context, db *sql.DB) (int, error) {
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM identity_providers`,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count identity providers: %w", err)
	}
	return count, nil
}

// GetIdentityProvider retrieves an identity provider by ID
func GetIdentityProvider(ctx context.Context, db *sql.DB, id int64) (*IdentityProvider, error) {
	var p IdentityProvider
	err := db.QueryRowContext(ctx,
		`SELECT id, name, provider_type, issuer_url, jwks_url, created_at, updated_at
		 FROM identity_providers
		 WHERE id = $1`,
		id,
	).Scan(&p.ID, &p.Name, &p.ProviderType, &p.IssuerURL, &p.JWKSURL, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get identity provider: %w", err)
	}
	return &p, nil
}

// CreateIdentityProvider inserts a new identity provider and returns it
func CreateIdentityProvider(ctx context.Context, db *sql.DB, name, providerType, issuerURL, jwksURL string) (*IdentityProvider, error) {
	var p IdentityProvider
	err := db.QueryRowContext(ctx,
		`INSERT INTO identity_providers (name, provider_type, issuer_url, jwks_url)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, name, provider_type, issuer_url, jwks_url, created_at, updated_at`,
		name, providerType, issuerURL, jwksURL,
	).Scan(&p.ID, &p.Name, &p.ProviderType, &p.IssuerURL, &p.JWKSURL, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create identity provider: %w", err)
	}
	return &p, nil
}

// UpdateIdentityProvider updates an identity provider
func UpdateIdentityProvider(ctx context.Context, db *sql.DB, id int64, name, issuerURL, jwksURL string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE identity_providers SET name = $1, issuer_url = $2, jwks_url = $3, updated_at = now()
		 WHERE id = $4`,
		name, issuerURL, jwksURL, id,
	)
	if err != nil {
		return fmt.Errorf("update identity provider: %w", err)
	}
	return nil
}

// DeleteIdentityProvider deletes an identity provider by ID
func DeleteIdentityProvider(ctx context.Context, db *sql.DB, id int64) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM identity_providers WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete identity provider: %w", err)
	}
	return nil
}

// ListWorkloads retrieves all workloads for an identity provider
func ListWorkloads(ctx context.Context, db *sql.DB, identityProviderID int64) ([]WorkloadListItem, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, created_at
		 FROM workloads
		 WHERE identity_provider_id = $1
		 ORDER BY name ASC`,
		identityProviderID,
	)
	if err != nil {
		return nil, fmt.Errorf("list workloads: %w", err)
	}
	defer rows.Close()

	var workloads []WorkloadListItem
	for rows.Next() {
		var w WorkloadListItem
		if err := rows.Scan(&w.ID, &w.Name, &w.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan workload: %w", err)
		}
		workloads = append(workloads, w)
	}
	return workloads, rows.Err()
}

// GetWorkload retrieves a workload by ID
func GetWorkload(ctx context.Context, db *sql.DB, id int64) (*Workload, error) {
	var w Workload
	err := db.QueryRowContext(ctx,
		`SELECT id, identity_provider_id, name, selector, created_at, updated_at
		 FROM workloads
		 WHERE id = $1`,
		id,
	).Scan(&w.ID, &w.IdentityProviderID, &w.Name, &w.Selector, &w.CreatedAt, &w.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get workload: %w", err)
	}
	return &w, nil
}

// CreateWorkload inserts a new workload and returns it
func CreateWorkload(ctx context.Context, db *sql.DB, identityProviderID int64, name string, selector json.RawMessage) (*Workload, error) {
	var w Workload
	err := db.QueryRowContext(ctx,
		`INSERT INTO workloads (identity_provider_id, name, selector)
		 VALUES ($1, $2, $3)
		 RETURNING id, identity_provider_id, name, selector, created_at, updated_at`,
		identityProviderID, name, selector,
	).Scan(&w.ID, &w.IdentityProviderID, &w.Name, &w.Selector, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create workload: %w", err)
	}
	return &w, nil
}

// UpdateWorkload updates a workload's name and selector
func UpdateWorkload(ctx context.Context, db *sql.DB, id int64, name string, selector json.RawMessage) error {
	_, err := db.ExecContext(ctx,
		`UPDATE workloads SET name = $1, selector = $2, updated_at = now()
		 WHERE id = $3`,
		name, selector, id,
	)
	if err != nil {
		return fmt.Errorf("update workload: %w", err)
	}
	return nil
}

// DeleteWorkload deletes a workload by ID
func DeleteWorkload(ctx context.Context, db *sql.DB, id int64) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM workloads WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete workload: %w", err)
	}
	return nil
}

// ListApplicationWorkloads lists workloads linked to an application
func ListApplicationWorkloads(ctx context.Context, db *sql.DB, applicationID int64) ([]ApplicationWorkloadItem, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT w.id, w.name, w.identity_provider_id, ip.name
		 FROM application_workloads aw
		 JOIN workloads w ON w.id = aw.workload_id
		 JOIN identity_providers ip ON ip.id = w.identity_provider_id
		 WHERE aw.application_id = $1
		 ORDER BY ip.name ASC, w.name ASC`,
		applicationID,
	)
	if err != nil {
		return nil, fmt.Errorf("list application workloads: %w", err)
	}
	defer rows.Close()

	var items []ApplicationWorkloadItem
	for rows.Next() {
		var item ApplicationWorkloadItem
		if err := rows.Scan(&item.WorkloadID, &item.WorkloadName, &item.IdentityProviderID, &item.ProviderName); err != nil {
			return nil, fmt.Errorf("scan application workload: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// LinkApplicationWorkload links an application to a workload
func LinkApplicationWorkload(ctx context.Context, db *sql.DB, applicationID, workloadID int64) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO application_workloads (application_id, workload_id)
		 VALUES ($1, $2)`,
		applicationID, workloadID,
	)
	if err != nil {
		return fmt.Errorf("link application workload: %w", err)
	}
	return nil
}

// UnlinkApplicationWorkload unlinks an application from a workload
func UnlinkApplicationWorkload(ctx context.Context, db *sql.DB, applicationID, workloadID int64) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM application_workloads
		 WHERE application_id = $1 AND workload_id = $2`,
		applicationID, workloadID,
	)
	if err != nil {
		return fmt.Errorf("unlink application workload: %w", err)
	}
	return nil
}

// WorkloadApplicationItem represents an application linked to a workload
type WorkloadApplicationItem struct {
	ApplicationID int64
	Subject       string
	Description   sql.NullString
}

// ListWorkloadApplications lists applications linked to a workload
func ListWorkloadApplications(ctx context.Context, db *sql.DB, workloadID int64) ([]WorkloadApplicationItem, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT a.id, a.subject, a.description
		 FROM application_workloads aw
		 JOIN applications a ON a.id = aw.application_id
		 WHERE aw.workload_id = $1
		 ORDER BY a.subject ASC`,
		workloadID,
	)
	if err != nil {
		return nil, fmt.Errorf("list workload applications: %w", err)
	}
	defer rows.Close()

	var items []WorkloadApplicationItem
	for rows.Next() {
		var item WorkloadApplicationItem
		if err := rows.Scan(&item.ApplicationID, &item.Subject, &item.Description); err != nil {
			return nil, fmt.Errorf("scan workload application: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// LookupJWKCacheEntry looks up a cached JWK by JWKS URL and key ID
func LookupJWKCacheEntry(ctx context.Context, db *sql.DB, jwksURL, kid string) (*JWKCacheEntry, error) {
	var e JWKCacheEntry
	err := db.QueryRowContext(ctx,
		`SELECT jwks_url, kid, found, jwk, fetched_at, expires_at
		 FROM jwk_cache
		 WHERE jwks_url = $1 AND kid = $2`,
		jwksURL, kid,
	).Scan(&e.JWKSURL, &e.KID, &e.Found, &e.JWK, &e.FetchedAt, &e.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup jwk cache entry: %w", err)
	}
	return &e, nil
}

// UpsertJWKCacheEntry inserts or updates a JWK cache entry
func UpsertJWKCacheEntry(ctx context.Context, db *sql.DB, jwksURL, kid string, found bool, jwk json.RawMessage, expiresAt time.Time) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO jwk_cache (jwks_url, kid, found, jwk, fetched_at, expires_at)
		 VALUES ($1, $2, $3, $4, now(), $5)
		 ON CONFLICT (jwks_url, kid)
		 DO UPDATE SET found = $3, jwk = $4, fetched_at = now(), expires_at = $5`,
		jwksURL, kid, found, jwk, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("upsert jwk cache entry: %w", err)
	}
	return nil
}

// LookupWorkloadsForApplication retrieves all workloads linked to an application with provider info
func LookupWorkloadsForApplication(ctx context.Context, db *sql.DB, applicationID int64) ([]WorkloadWithProvider, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT w.id, w.selector, w.identity_provider_id, ip.issuer_url, ip.jwks_url
		 FROM application_workloads aw
		 JOIN workloads w ON w.id = aw.workload_id
		 JOIN identity_providers ip ON ip.id = w.identity_provider_id
		 WHERE aw.application_id = $1`,
		applicationID,
	)
	if err != nil {
		return nil, fmt.Errorf("lookup workloads for application: %w", err)
	}
	defer rows.Close()

	var workloads []WorkloadWithProvider
	for rows.Next() {
		var w WorkloadWithProvider
		if err := rows.Scan(&w.WorkloadID, &w.Selector, &w.IdentityProviderID, &w.IssuerURL, &w.JWKSURL); err != nil {
			return nil, fmt.Errorf("scan workload with provider: %w", err)
		}
		workloads = append(workloads, w)
	}
	return workloads, rows.Err()
}
