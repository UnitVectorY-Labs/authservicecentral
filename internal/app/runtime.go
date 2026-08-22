package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/api"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
	engine "github.com/UnitVectorY-Labs/authservicecentral/internal/openfga"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/operational"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/service"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/token"
)

type Runtime struct {
	Handler   http.Handler
	Store     *database.Store
	Engine    *engine.Engine
	Service   *service.Service
	Readiness *Readiness
	Signing   *SigningBundle
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// BuildRuntime wires an already-migrated deployment. It never writes an
// authorization model: a missing or mismatched activation fails closed.
func BuildRuntime(ctx context.Context, op operational.Config, cfg *config.Config) (*Runtime, error) {
	if cfg == nil {
		return nil, errors.New("runtime configuration is required")
	}
	fingerprint, err := cfg.Fingerprint()
	if err != nil {
		return nil, err
	}
	store, err := OpenDatabase(ctx, op.DatabaseURL)
	if err != nil {
		return nil, err
	}
	fga, err := engine.NewPostgres(ctx, engine.PostgresConfig{URI: op.DatabaseURL, Activations: ActivationStore{DB: store}, MaxOpenConns: 20, MinOpenConns: 2, PingTimeout: 5 * time.Second})
	if err != nil {
		store.Close()
		return nil, err
	}
	cleanup := func() { fga.Close(); store.Close() }
	if _, err = fga.VerifyFingerprint(ctx, fingerprint); err != nil {
		cleanup()
		return nil, fmt.Errorf("verify active authorization model: %w", err)
	}
	signingBundle, err := BuildSigning(ctx, op)
	if err != nil {
		cleanup()
		return nil, err
	}
	cleanupSigning := func() { _ = signingBundle.Close(); cleanup() }
	trustClient := &http.Client{Timeout: op.HTTPTimeout}
	validator, err := BuildValidator(cfg, trustClient)
	if err != nil {
		cleanupSigning()
		return nil, err
	}
	domain, err := service.New(store, cfg, ServiceEngine{Engine: fga})
	if err != nil {
		cleanupSigning()
		return nil, err
	}
	issuer := &token.Issuer{Issuer: op.Issuer, Signer: signingBundle.Active, Published: signingBundle.Published}
	algorithms := []string{signingBundle.Active.Algorithm()}
	for _, inactive := range signingBundle.Published {
		algorithms = append(algorithms, inactive.Algorithm())
	}
	parser := &token.Parser{Issuer: op.Issuer, Algorithms: algorithms, Keys: signingBundle.Keys, ClockSkew: 30 * time.Second}
	exchanger := &token.Exchanger{Validator: ExchangeValidator{External: validator, Platform: parser}, Audiences: TokenAudienceLookup{Service: domain}, Permissions: TokenPermissionLookup{Service: domain}, Issuer: issuer}
	ready := NewReadiness(store, fga, signingBundle.Active, fingerprint)
	backend := &Backend{Service: domain, DB: store, Exchanger: exchanger, Issuer: issuer, ReadyState: ready, IssuerURL: op.Issuer, ReconcileBatch: op.ReconcileBatch}
	handler, err := api.New(backend, PlatformAuthenticator{Parser: parser}, api.Options{MaxBatchSize: op.MaxBatchSize, InsecureManagement: op.ManagementOpen, ManagementAudience: op.ManagementAudience, ManagementPermissions: cfg.Management.ManagementPermissionMap(), SwaggerUI: op.SwaggerUI, Issuer: op.Issuer, Metrics: op.Metrics, RateLimitPerSecond: op.RateLimitPerSecond, RateLimitBurst: op.RateLimitBurst})
	if err != nil {
		cleanupSigning()
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime := &Runtime{Handler: handler, Store: store, Engine: fga, Service: domain, Readiness: ready, Signing: signingBundle, cancel: cancel}
	if err := DrainOutbox(runCtx, domain, op.ReconcileBatch, 3); err != nil {
		runtime.Close()
		return nil, fmt.Errorf("initial authorization reconciliation: %w", err)
	}
	runtime.startReconciler(runCtx, op.ReconcileInterval, op.ReconcileBatch)
	return runtime, nil
}

// DrainOutbox performs a bounded synchronous drain. A permanently failing
// engine cannot trap startup in an unbounded retry loop.
func DrainOutbox(ctx context.Context, domain *service.Service, batch, maxRounds int) error {
	if batch <= 0 || maxRounds <= 0 {
		return errors.New("outbox batch and rounds must be positive")
	}
	var last error
	for round := 0; round < maxRounds; round++ {
		completed, err := domain.Reconcile(ctx, service.Mutation{OperationID: fmt.Sprintf("startup-reconcile-%d", round)}, batch)
		if err != nil {
			last = err
			continue
		}
		if completed < batch {
			return nil
		}
	}
	if last != nil {
		return last
	}
	return errors.New("authorization outbox did not drain within the configured bound")
}

func (r *Runtime) startReconciler(ctx context.Context, interval time.Duration, batch int) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				cycleCtx, cancel := context.WithTimeout(ctx, interval)
				_, _ = r.Service.Reconcile(cycleCtx, service.Mutation{OperationID: "background-reconcile-" + now.UTC().Format("20060102T150405.000000000")}, batch)
				cancel()
			}
		}
	}()
}

func (r *Runtime) BeginShutdown() {
	if r != nil && r.Readiness != nil {
		r.Readiness.Stop()
	}
}
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.BeginShutdown()
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	var errs []error
	if r.Signing != nil {
		errs = append(errs, r.Signing.Close())
	}
	if r.Engine != nil {
		r.Engine.Close()
	}
	if r.Store != nil {
		errs = append(errs, r.Store.Close())
	}
	return errors.Join(errs...)
}
