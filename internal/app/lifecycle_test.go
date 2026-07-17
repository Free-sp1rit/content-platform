package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeShutsDownAndClosesResourcesInOrder(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var closeOrder []string
	first := &recordingCloser{name: "redis", order: &closeOrder}
	second := &recordingCloser{name: "postgres", order: &closeOrder}
	application := &App{
		server: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})},
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		shutdownTimeout: time.Second,
		closers:         []io.Closer{first, second},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Serve(ctx, listener) }()

	waitForHTTP(t, listener.Addr().String())
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop")
	}
	if got := first.count; got != 1 {
		t.Fatalf("first closer count = %d", got)
	}
	if got := second.count; got != 1 {
		t.Fatalf("second closer count = %d", got)
	}
	if len(closeOrder) != 2 || closeOrder[0] != "redis" || closeOrder[1] != "postgres" {
		t.Fatalf("close order = %v", closeOrder)
	}
}

func TestServeFailureClosesResources(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	closer := &recordingCloser{name: "resource", order: &[]string{}}
	application := &App{
		server:          &http.Server{Handler: http.NewServeMux()},
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		shutdownTimeout: time.Second,
		closers:         []io.Closer{closer},
	}

	err = application.Serve(context.Background(), listener)

	if err == nil {
		t.Fatal("Serve() expected listener error")
	}
	if closer.count != 1 {
		t.Fatalf("closer count = %d", closer.count)
	}
}

func TestRunListenFailureClosesResources(t *testing.T) {
	closer := &recordingCloser{name: "resource", order: &[]string{}}
	application := &App{
		server:          &http.Server{Addr: "invalid address"},
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		shutdownTimeout: time.Second,
		closers:         []io.Closer{closer},
	}

	err := application.Run(context.Background())

	if err == nil {
		t.Fatal("Run() expected listen error")
	}
	if closer.count != 1 {
		t.Fatalf("closer count = %d", closer.count)
	}
}

func waitForHTTP(t *testing.T, address string) {
	t.Helper()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("http://" + address)
		if err == nil {
			_ = response.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("HTTP server did not become ready")
}

type recordingCloser struct {
	name  string
	order *[]string
	count int
	err   error
}

func (c *recordingCloser) Close() error {
	c.count++
	*c.order = append(*c.order, c.name)
	return c.err
}

var _ io.Closer = (*recordingCloser)(nil)

func TestCloseResourcesJoinsErrorsAndOnlyRunsOnce(t *testing.T) {
	firstErr := errors.New("first close")
	secondErr := errors.New("second close")
	first := &recordingCloser{name: "first", order: &[]string{}, err: firstErr}
	second := &recordingCloser{name: "second", order: &[]string{}, err: secondErr}
	application := &App{closers: []io.Closer{first, second}}

	err := application.closeResources()
	secondCallErr := application.closeResources()

	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("closeResources() error = %v", err)
	}
	if !errors.Is(secondCallErr, firstErr) || first.count != 1 || second.count != 1 {
		t.Fatalf("second close result = %v, counts = %d/%d", secondCallErr, first.count, second.count)
	}
}
