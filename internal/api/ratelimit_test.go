package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenBucketDeterministicRefillAndRetryAfter(t *testing.T) {
	clock := time.Unix(1_000, 0)
	bucket := newTokenBucket(2, 2)
	bucket.now = func() time.Time { return clock }
	bucket.last = clock
	if ok, _ := bucket.allow(); !ok {
		t.Fatal("first burst token rejected")
	}
	if ok, _ := bucket.allow(); !ok {
		t.Fatal("second burst token rejected")
	}
	if ok, retry := bucket.allow(); ok || retry != 1 {
		t.Fatalf("empty bucket: allowed=%v retry=%d", ok, retry)
	}
	clock = clock.Add(250 * time.Millisecond)
	if ok, retry := bucket.allow(); ok || retry != 1 {
		t.Fatalf("partial refill: allowed=%v retry=%d", ok, retry)
	}
	clock = clock.Add(250 * time.Millisecond)
	if ok, _ := bucket.allow(); !ok {
		t.Fatal("refilled token rejected")
	}
	clock = clock.Add(-time.Hour)
	if ok, _ := bucket.allow(); ok {
		t.Fatal("backward clock movement refilled bucket")
	}
}

func TestTokenBucketConcurrentGlobalBurst(t *testing.T) {
	clock := time.Unix(1_000, 0)
	bucket := newTokenBucket(1, 10)
	bucket.now = func() time.Time { return clock }
	bucket.last = clock
	var allowed atomic.Int32
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if ok, _ := bucket.allow(); ok {
				allowed.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := allowed.Load(); got != 10 {
		t.Fatalf("allowed %d requests from burst of 10", got)
	}
}

func TestRateLimitMiddlewareStructuredResponseBeforeHandler(t *testing.T) {
	backend := &fakeBackend{}
	server := newTestServer(t, backend, Options{RateLimitPerSecond: 1, RateLimitBurst: 1})
	clock := time.Unix(1_000, 0)
	server.limiter.now = func() time.Time { return clock }
	server.limiter.last = clock
	first := perform(server, http.MethodGet, "/.well-known/oauth-authorization-server", "", "")
	if first.Code != http.StatusOK {
		t.Fatalf("first request: %d", first.Code)
	}
	backend.called = ""
	limited := perform(server, http.MethodGet, "/.well-known/oauth-authorization-server", "", "")
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "1" || limited.Header().Get("X-Request-ID") == "" {
		t.Fatalf("limited response: %d headers=%v", limited.Code, limited.Header())
	}
	if backend.called != "" {
		t.Fatalf("backend ran for limited request: %s", backend.called)
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(limited.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != "rate_limited" || envelope.Error.RequestID == "" {
		t.Fatalf("limited body: %s", limited.Body.String())
	}
	clock = clock.Add(time.Second)
	refilled := perform(server, http.MethodGet, "/.well-known/oauth-authorization-server", "", "")
	if refilled.Code != http.StatusOK {
		t.Fatalf("refilled request: %d", refilled.Code)
	}
}

func TestRateLimitZeroDisablesAndNegativeRejected(t *testing.T) {
	for _, options := range []Options{{RateLimitPerSecond: 1}, {RateLimitBurst: 1}, {}} {
		server := newTestServer(t, &fakeBackend{}, options)
		for range 3 {
			if got := perform(server, http.MethodGet, "/health/live", "", "").Code; got != http.StatusOK {
				t.Fatalf("disabled limiter returned %d for %#v", got, options)
			}
		}
	}
	if _, err := New(&fakeBackend{}, fakeAuth{}, Options{RateLimitPerSecond: -1, RateLimitBurst: 1}); err == nil {
		t.Fatal("negative rate accepted")
	}
	if _, err := New(&fakeBackend{}, fakeAuth{}, Options{RateLimitPerSecond: 1, RateLimitBurst: -1}); err == nil {
		t.Fatal("negative burst accepted")
	}
}
