// Package openfga embeds OpenFGA's official server and datastore APIs without
// exposing OpenFGA's network protocol.
package openfga

import (
	"context"
	"errors"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	fgaserver "github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage"
)

const DefaultStoreName = "authservicecentral"

type Options struct {
	Datastore   storage.OpenFGADatastore
	StoreName   string
	Activations ActivationStore
}

type Engine struct {
	ds          storage.OpenFGADatastore
	server      *fgaserver.Server
	storeID     string
	activations ActivationStore
}

func New(ctx context.Context, opts Options) (*Engine, error) {
	if opts.Datastore == nil {
		return nil, errors.New("initialize OpenFGA: datastore is required")
	}
	if opts.StoreName == "" {
		opts.StoreName = DefaultStoreName
	}
	if opts.Activations == nil {
		opts.Activations = NewMemoryActivationStore()
	}
	ready, err := opts.Datastore.IsReady(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize OpenFGA: datastore readiness: %w", err)
	}
	if !ready.IsReady {
		return nil, fmt.Errorf("initialize OpenFGA: datastore is not ready: %s", ready.Message)
	}
	s, err := fgaserver.NewServerWithOpts(fgaserver.WithContext(ctx), fgaserver.WithDatastore(opts.Datastore))
	if err != nil {
		return nil, fmt.Errorf("initialize embedded OpenFGA server: %w", err)
	}
	e := &Engine{ds: opts.Datastore, server: s, activations: opts.Activations}
	e.storeID, err = findOrCreateStore(ctx, opts.Datastore, s, opts.StoreName)
	if err != nil {
		s.Close()
		return nil, err
	}
	return e, nil
}

func (e *Engine) StoreID() string { return e.storeID }

func (e *Engine) Close() {
	if e == nil {
		return
	}
	if e.server != nil {
		e.server.Close()
	}
	if e.ds != nil {
		e.ds.Close()
	}
}

func findOrCreateStore(ctx context.Context, ds storage.OpenFGADatastore, s *fgaserver.Server, name string) (string, error) {
	var found []*openfgav1.Store
	continuation := ""
	for {
		stores, next, err := ds.ListStores(ctx, storage.ListStoresOptions{Name: name, Pagination: storage.NewPaginationOptions(100, continuation)})
		if err != nil {
			return "", fmt.Errorf("list OpenFGA stores: %w", err)
		}
		found = append(found, stores...)
		if next == "" {
			break
		}
		continuation = next
	}
	if len(found) > 1 {
		return "", fmt.Errorf("multiple OpenFGA stores named %q", name)
	}
	if len(found) == 1 {
		return found[0].GetId(), nil
	}
	created, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: name})
	if err != nil {
		return "", fmt.Errorf("create OpenFGA store: %w", err)
	}
	return created.GetId(), nil
}
