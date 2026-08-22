package api

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// tokenBucket refills lazily and therefore owns no goroutine or shutdown
// lifecycle. One bucket is shared by all requests handled by a Server.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	now := time.Now
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: now(), now: now}
}

func (b *tokenBucket) allow() (bool, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if now.After(b.last) {
		b.tokens = math.Min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := int(math.Ceil((1 - b.tokens) / b.rate))
	if wait < 1 {
		wait = 1
	}
	return false, wait
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	if s.limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, retryAfter := s.limiter.allow()
		if !allowed {
			s.rateLimited.Add(1)
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			s.writeError(w, r, Error(http.StatusTooManyRequests, "rate_limited", "request rate limit exceeded"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
