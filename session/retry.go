package session

import (
	"fmt"
	"strings"
	"time"
)

const retryBackoffFactor = 2.0

var (
	// retryDelay is the initial delay between attempts. Doubles per
	// attempt up to retryMaxDelay. Total worst-case window is bounded
	// by the sum of the backoff schedule (~12.5s with the defaults).
	// Tests override to 0 to keep retry tests instant.
	retryDelay = 500 * time.Millisecond //nolint:gochecknoglobals
	// retryMaxDelay caps the per-attempt delay so a long gateway
	// outage doesn't push the retry window into the tens of seconds.
	retryMaxDelay = 5 * time.Second //nolint:gochecknoglobals
	// retryMaxAttempts is the total number of send attempts (including
	// the first one) before giving up.
	retryMaxAttempts = 6 //nolint:gochecknoglobals
)

// retryConfig is the back-off a Session uses, copied from the package defaults
// when the Session is created. Reading it from the Session instead of the
// package variables keeps a recovery goroutine that outlives its test from
// racing with a later test that changes those variables.
type retryConfig struct {
	delay       time.Duration
	maxDelay    time.Duration
	maxAttempts int
}

func defaultRetryConfig() retryConfig {
	return retryConfig{delay: retryDelay, maxDelay: retryMaxDelay, maxAttempts: retryMaxAttempts}
}

// isShardNotReady reports whether err is a transient "shard not ready" from
// the voice gateway — this happens during the brief window after a channel move
// while the WebSocket handshake hasn't completed yet.
func isShardNotReady(err error) bool {
	return err != nil && strings.Contains(err.Error(), "shard is not ready")
}

// retrySend calls send until it succeeds, fails with anything other than
// "shard is not ready", or runs out of attempts, backing off between them.
// Each attempt holds sendMu and s.mu and the wait holds neither, so the
// back-off never blocks a handler. It gives up once ready or the session
// closes.
func (s *Session) retrySend(ready <-chan struct{}, send func() error) error {
	delay := s.retry.delay

	// retryStart is set the first time we decide to retry (i.e. the first
	// "shard is not ready" failure), not at function entry — a single send
	// call's own latency isn't gateway downtime. Accumulated into
	// Stats.TransportRetryDuration on every exit path via defer so there's
	// one place that does the bookkeeping regardless of how the loop ends.
	var retryStart time.Time

	defer func() {
		if !retryStart.IsZero() {
			s.mu.Lock()
			s.stats.TransportRetryDuration += time.Since(retryStart)
			s.mu.Unlock()
		}
	}()

	for i := range s.retry.maxAttempts {
		err := s.sendAttempt(ready, send)
		if err == nil {
			return nil
		}

		if !isShardNotReady(err) || i == s.retry.maxAttempts-1 {
			return err
		}

		if retryStart.IsZero() {
			retryStart = time.Now()
		}

		s.mu.RLock()
		logger := s.logger
		s.mu.RUnlock()
		logger.Debug("shard not ready, retrying send",
			"attempt", i+1,
			"max_attempts", s.retry.maxAttempts,
			"delay_ms", delay.Milliseconds())

		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ready:
			timer.Stop()

			return errSuperseded
		case <-s.shutdownCtx.Done():
			timer.Stop()

			return s.shutdownCtx.Err()
		}

		// Exponential backoff with cap.
		delay = min(time.Duration(float64(delay)*retryBackoffFactor), s.retry.maxDelay)
	}

	return nil
}

// sendAttempt runs one retrySend attempt with sendMu and s.mu held.
func (s *Session) sendAttempt(ready <-chan struct{}, send func() error) error {
	s.lockMLS()
	defer s.unlockMLS()
	if err := s.shutdownCtx.Err(); err != nil {
		return err
	}
	if isClosed(ready) {
		return errSuperseded
	}

	return send()
}

// sendLocked calls send once with s.mu released, so a callback can call back
// into the session. The caller must hold sendMu and s.mu; sendMu keeps every
// other handler and watchdog out until the send returns.
func (s *Session) sendLocked(send func() error) error {
	s.mu.Unlock()
	defer s.mu.Lock()
	if err := send(); err != nil {
		return fmt.Errorf("%w: %w", errSendFailed, err)
	}

	return nil
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
