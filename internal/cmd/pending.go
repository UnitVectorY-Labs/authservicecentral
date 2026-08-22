package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/app"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/operational"
)

// API starts the runtime for both the historical "run" command and its "api"
// alias. Startup never performs implicit migrations or model activation.
func API(args []string) error {
	op, err := operational.Parse("run", args)
	if err != nil {
		return err
	}
	cfg, err := loadSchema(op.ConfigPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runtime, err := app.BuildRuntime(ctx, op, cfg)
	if err != nil {
		return err
	}
	defer runtime.Close()
	server := &http.Server{Addr: op.ListenAddress, Handler: runtime.Handler, ReadHeaderTimeout: min(op.HTTPTimeout, 5*time.Second), ReadTimeout: op.HTTPTimeout, WriteTimeout: op.HTTPTimeout, IdleTimeout: 2 * op.HTTPTimeout, MaxHeaderBytes: 1 << 20}
	serveErr := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()
	fmt.Printf("listening on %s\n", op.ListenAddress)
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		runtime.BeginShutdown()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), op.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("graceful HTTP shutdown: %w", err)
		}
		return <-serveErr
	}
}
