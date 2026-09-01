package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"
)

var (
	errWorkerCompletedBeforeReady = errors.New("worker completed before signaling readiness")
	errResultChannelClosed        = errors.New("result channel closed before delivering a value")
)

const repositoryWorkerCleanupTimeout = 2 * time.Second

func waitForWorkerReady(ctx context.Context, ready <-chan struct{}, done <-chan error) (bool, error) {
	select {
	case <-ready:
		return false, nil
	case err, ok := <-done:
		if !ok || err == nil {
			return true, errWorkerCompletedBeforeReady
		}
		return true, err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func receiveBeforeContextDone[T any](ctx context.Context, result <-chan T) (T, error) {
	select {
	case value, ok := <-result:
		if !ok {
			var zero T
			return zero, errResultChannelClosed
		}
		return value, nil
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

func cleanupErrorWorker(t *testing.T, label string, result <-chan error) {
	t.Helper()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), repositoryWorkerCleanupTimeout)
	defer cancel()
	workerErr, waitErr := receiveBeforeContextDone(cleanupCtx, result)
	if waitErr != nil {
		t.Errorf("%s did not finish during bounded cleanup: %v", label, waitErr)
		return
	}
	if workerErr != nil {
		t.Errorf("%s failed during cleanup: %v", label, workerErr)
	}
}

func TestWaitForWorkerReadyReportsFailureBeforeSignal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	holderErr := errors.New("holder failed before acquiring its lock")
	done <- holderErr

	doneConsumed, err := waitForWorkerReady(ctx, ready, done)

	if !doneConsumed {
		t.Fatal("waitForWorkerReady() did not report that worker completion was consumed")
	}
	if !errors.Is(err, holderErr) {
		t.Fatal("waitForWorkerReady() did not return the early worker failure")
	}
}

func TestWaitForWorkerReadyAcceptsReadinessSignal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready := make(chan struct{})
	close(ready)

	doneConsumed, err := waitForWorkerReady(ctx, ready, make(chan error))

	if err != nil {
		t.Fatal("waitForWorkerReady() returned an error after readiness was signaled")
	}
	if doneConsumed {
		t.Fatal("waitForWorkerReady() consumed worker completion after readiness was signaled")
	}
}

func TestWaitForWorkerReadyRejectsCompletionWithoutSignal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	done <- nil

	doneConsumed, err := waitForWorkerReady(ctx, make(chan struct{}), done)

	if !doneConsumed {
		t.Fatal("waitForWorkerReady() did not consume early worker completion")
	}
	if !errors.Is(err, errWorkerCompletedBeforeReady) {
		t.Fatal("waitForWorkerReady() accepted completion without a readiness signal")
	}
}

func TestWaitForWorkerReadyHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	doneConsumed, err := waitForWorkerReady(ctx, make(chan struct{}), make(chan error))

	if doneConsumed {
		t.Fatal("waitForWorkerReady() reported worker completion on context cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("waitForWorkerReady() did not return context cancellation")
	}
}

func TestWaitForWorkerReadyRejectsClosedCompletionChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error)
	close(done)

	doneConsumed, err := waitForWorkerReady(ctx, make(chan struct{}), done)

	if !doneConsumed {
		t.Fatal("waitForWorkerReady() did not consume a closed completion channel")
	}
	if !errors.Is(err, errWorkerCompletedBeforeReady) {
		t.Fatal("waitForWorkerReady() accepted a closed completion channel without readiness")
	}
}

func TestReceiveBeforeContextDoneBoundsChannelWait(t *testing.T) {
	ctx, cancelTest := context.WithTimeout(context.Background(), time.Second)
	defer cancelTest()
	result := make(chan int, 1)
	result <- 42

	got, err := receiveBeforeContextDone(ctx, result)
	if err != nil {
		t.Fatal("receiveBeforeContextDone() returned an error for a ready result")
	}
	if got != 42 {
		t.Fatalf("receiveBeforeContextDone() = %d, want 42", got)
	}

	canceledCtx, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	if _, err := receiveBeforeContextDone(canceledCtx, make(chan int)); !errors.Is(err, context.Canceled) {
		t.Fatal("receiveBeforeContextDone() did not bound a blocked receive with context cancellation")
	}

	workerErr := errors.New("worker failed")
	errorResult := make(chan error, 1)
	errorResult <- workerErr
	gotWorkerErr, waitErr := receiveBeforeContextDone(ctx, errorResult)
	if waitErr != nil {
		t.Fatal("receiveBeforeContextDone() conflated worker failure with channel wait failure")
	}
	if !errors.Is(gotWorkerErr, workerErr) {
		t.Fatal("receiveBeforeContextDone() did not preserve the worker result")
	}

	closedResult := make(chan int)
	close(closedResult)
	if _, err := receiveBeforeContextDone(ctx, closedResult); !errors.Is(err, errResultChannelClosed) {
		t.Fatal("receiveBeforeContextDone() did not reject a closed channel without a value")
	}
}
