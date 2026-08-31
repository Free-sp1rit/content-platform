package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

func (a *App) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", a.server.Addr)
	if err != nil {
		return errors.Join(fmt.Errorf("listen on %s: %w", a.server.Addr, err), a.closeResources())
	}
	return a.Serve(ctx, listener)
}

func (a *App) Serve(ctx context.Context, listener net.Listener) error {
	if a.logger != nil {
		a.logger.Info("HTTP server started", "address", listener.Addr().String())
	}

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- a.server.Serve(listener)
	}()

	select {
	case err := <-serveErrors:
		closeErr := a.closeResources()
		if errors.Is(err, http.ErrServerClosed) {
			return closeErr
		}
		return errors.Join(fmt.Errorf("serve HTTP: %w", err), closeErr)
	case <-ctx.Done():
		if a.logger != nil {
			a.logger.Info("HTTP server shutdown started")
		}

		shutdownContext, cancel := context.WithTimeout(context.Background(), a.shutdownTimeout)
		shutdownErr := a.server.Shutdown(shutdownContext)
		cancel()

		var forceCloseErr error
		if shutdownErr != nil {
			forceCloseErr = a.server.Close()
		}

		serveErr := <-serveErrors
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		} else if serveErr != nil {
			serveErr = fmt.Errorf("serve HTTP: %w", serveErr)
		}
		closeErr := a.closeResources()
		result := errors.Join(shutdownErr, forceCloseErr, serveErr, closeErr)

		if a.logger != nil {
			a.logger.Info("HTTP server shutdown completed")
		}
		return result
	}
}

func (a *App) closeResources() error {
	a.closeOnce.Do(func() {
		var errs []error
		for _, closer := range a.closers {
			if closer == nil {
				continue
			}
			if err := closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		a.closeErr = errors.Join(errs...)
	})
	return a.closeErr
}
