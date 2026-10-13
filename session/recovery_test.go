package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/disgoorg/godave"
)

// countingCallbacks counts gateway sends so tests can observe the recovery
// watchdog retrying and giving up.
type countingCallbacks struct {
	mu             sync.Mutex
	invalidCommits int
	keyPackages    int
}

func (c *countingCallbacks) SendMLSKeyPackage([]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyPackages++

	return nil
}
func (c *countingCallbacks) SendMLSCommitWelcome([]byte) error   { return nil }
func (c *countingCallbacks) SendReadyForTransition(uint16) error { return nil }
func (c *countingCallbacks) SendInvalidCommitWelcome(uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidCommits++

	return nil
}

func (c *countingCallbacks) counts() (invalidCommits, keyPackages int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.invalidCommits, c.keyPackages
}

func newRecoveryTestSession(t *testing.T, cb godave.Callbacks) *Session {
	t.Helper()
	s := New("123456789", cb)
	closeAtCleanup(t, s)
	s.recoveryTimeout = 10 * time.Millisecond
	// The session only generates key packages after the gateway selected the
	// DAVE protocol version.
	s.OnSelectProtocolAck(1)

	return s
}

// eventually polls cond until it holds or the deadline expires.
func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestRecoveryWatchdogRetriesThenGivesUp(t *testing.T) {
	cb := &countingCallbacks{}
	s := newRecoveryTestSession(t, cb)

	s.lockMLS()
	s.invalidateAndResendKeyPackageLocked()
	s.unlockMLS()

	// Each timed-out attempt re-signals InvalidCommitWelcome and re-invalidates;
	// after maxRecoveryAttempts the watchdog must stop re-arming.
	eventually(t, func() bool {
		invalid, _ := cb.counts()

		return invalid == maxRecoveryAttempts
	}, "watchdog never exhausted its recovery attempts")

	time.Sleep(5 * s.recoveryTimeout)
	invalid, _ := cb.counts()
	if invalid != maxRecoveryAttempts {
		t.Fatalf("watchdog kept retrying after giving up: %d invalid commits, want %d", invalid, maxRecoveryAttempts)
	}

	s.mu.RLock()
	gotStats := s.stats.RecoveryAttempts
	gotTransport := s.stats.RecoveryAttemptsTransport
	s.mu.RUnlock()
	if gotStats != maxRecoveryAttempts {
		t.Fatalf("Stats.RecoveryAttempts = %d, want %d", gotStats, maxRecoveryAttempts)
	}
	if gotTransport != 0 {
		t.Fatalf("Stats.RecoveryAttemptsTransport = %d, want 0 (this is an MLS fault, not a transport skip)", gotTransport)
	}
}

func TestRecoveryWatchdogStopsWhenEpochActivates(t *testing.T) {
	cb := &countingCallbacks{}
	s := newRecoveryTestSession(t, cb)

	s.lockMLS()
	s.invalidateAndResendKeyPackageLocked()
	// Simulate the epoch activating right after the invalidation.
	s.recoveryAttempts = 0
	s.signalEpochReadyLocked()
	s.unlockMLS()

	time.Sleep(5 * s.recoveryTimeout)
	invalid, _ := cb.counts()
	if invalid != 0 {
		t.Fatalf("watchdog fired despite epoch activation: %d invalid commits", invalid)
	}
}

// shardNotReadyCallbacks simulates a voice gateway that is down: every send
// returns "shard is not ready" until reconnect is called. It counts the key
// packages and invalid_commit_welcome messages the session tried to send.
type shardNotReadyCallbacks struct {
	countingCallbacks
	up       atomic.Bool
	distinct sync.Map
}

func (c *shardNotReadyCallbacks) transportErr() error {
	if c.up.Load() {
		return nil
	}

	return errors.New("shard is not ready")
}

func (c *shardNotReadyCallbacks) SendMLSKeyPackage(kp []byte) error {
	_ = c.countingCallbacks.SendMLSKeyPackage(kp)
	c.distinct.Store(string(kp), struct{}{})

	return c.transportErr()
}

func (c *shardNotReadyCallbacks) SendInvalidCommitWelcome(transitionID uint16) error {
	_ = c.countingCallbacks.SendInvalidCommitWelcome(transitionID)

	return c.transportErr()
}

func (c *shardNotReadyCallbacks) distinctKeyPackages() int {
	n := 0
	c.distinct.Range(func(any, any) bool {
		n++

		return true
	})

	return n
}

func (c *shardNotReadyCallbacks) reconnect() {
	c.up.Store(true)
}

// TestRecoveryWatchdog_BoundedWhileTransportDown verifies that a session whose
// gateway never comes back stops trying: the dropped key package arms the
// recovery watchdog, each firing retries the key package with back-off and
// re-arms, and after maxRecoveryAttempts firings it gives up.
func TestRecoveryWatchdog_BoundedWhileTransportDown(t *testing.T) {
	cb := &shardNotReadyCallbacks{}
	s := newRecoveryTestSession(t, cb)

	eventually(t, func() bool {
		invalid, _ := cb.counts()

		return invalid == maxRecoveryAttempts
	}, "recovery watchdog never exhausted its attempts")

	time.Sleep(5 * s.recoveryTimeout)
	invalid, keyPackages := cb.counts()
	if invalid != maxRecoveryAttempts {
		t.Fatalf("invalid_commit_welcome sent %d times, want %d", invalid, maxRecoveryAttempts)
	}
	// One from select_protocol_ack, then a full back-off per firing.
	if want := 1 + maxRecoveryAttempts*s.retry.maxAttempts; keyPackages != want {
		t.Fatalf("key package sent %d times, want %d", keyPackages, want)
	}
	// Each firing retries the same key package.
	if got, want := cb.distinctKeyPackages(), 1+maxRecoveryAttempts; got != want {
		t.Fatalf("%d distinct key packages, want %d", got, want)
	}
	stats := s.Stats()
	if stats.RecoveryAttempts != maxRecoveryAttempts || stats.RecoveryAttemptsTransport != maxRecoveryAttempts {
		t.Fatalf("RecoveryAttempts = %d, RecoveryAttemptsTransport = %d, want %d each",
			stats.RecoveryAttempts, stats.RecoveryAttemptsTransport, maxRecoveryAttempts)
	}
}

// TestRecoveryWatchdog_SupersededArmsCostNoAttempt verifies that dropped sends
// re-arming the watchdog before it fires don't use up the attempts.
func TestRecoveryWatchdog_SupersededArmsCostNoAttempt(t *testing.T) {
	cb := &shardNotReadyCallbacks{}
	s := newRecoveryTestSession(t, cb)
	s.OnDavePrepareEpoch(1, 1)
	s.OnDavePrepareEpoch(1, 1)

	eventually(t, func() bool {
		invalid, _ := cb.counts()

		return invalid == maxRecoveryAttempts
	}, "recovery watchdog gave up before using its attempts")
}

// TestRecoveryWatchdog_GivesWayToReconnect verifies that a watchdog backing off
// while the gateway is down neither delays a handler nor sends anything once a
// new connection's select_protocol_ack has reset the session.
func TestRecoveryWatchdog_GivesWayToReconnect(t *testing.T) {
	cb := &shardNotReadyCallbacks{}
	s := New("123456789", cb)
	closeAtCleanup(t, s)
	s.recoveryTimeout = 10 * time.Millisecond
	s.retry.delay = time.Hour
	s.OnSelectProtocolAck(1)

	// The watchdog has fired and is waiting out its first back-off.
	eventually(t, func() bool {
		invalid, keyPackages := cb.counts()

		return invalid == 1 && keyPackages == 2
	}, "recovery watchdog never retried the key package")

	cb.reconnect()
	within(t, "OnSelectProtocolAck during the watchdog's back-off", func() { s.OnSelectProtocolAck(1) })

	eventually(t, func() bool {
		return s.Stats().TransportRetryDuration > 0
	}, "watchdog kept backing off after the reset")
	invalid, keyPackages := cb.counts()
	if invalid != 1 || keyPackages != 3 {
		t.Fatalf("after reconnect: %d invalid_commit_welcome, %d key packages; want 1 and 3", invalid, keyPackages)
	}
	if got := s.Stats().RecoveryAttempts; got != 1 {
		t.Fatalf("RecoveryAttempts = %d, want 1 (the superseded watchdog must not re-arm)", got)
	}
}

// readyDroppingCallbacks fails every ready_for_transition send.
type readyDroppingCallbacks struct {
	kpCapturingCallbacks
}

func (c *readyDroppingCallbacks) SendReadyForTransition(uint16) error {
	return errors.New("shard is not ready")
}

// TestReadyForTransitionDropped_ArmsRecoveryWithoutActiveEpoch verifies that a
// dropped ready_for_transition arms the recovery watchdog only when no older
// epoch is active, since recovery would reset a session that still encrypts.
func TestReadyForTransitionDropped_ArmsRecoveryWithoutActiveEpoch(t *testing.T) {
	tests := []struct {
		name                string
		welcomeTransitionID uint16
		peerCommit          bool
		wantArmed           bool
	}{
		{name: "no active epoch", welcomeTransitionID: 5, wantArmed: true},
		{name: "older epoch active", peerCommit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := &readyDroppingCallbacks{}
			s := New("123456789", cb)
			closeAtCleanup(t, s)
			s.SetChannelID(987654321)
			s.OnSelectProtocolAck(1)
			externalSenderPackage := buildExternalSenderPackage(t)
			setExternalSenderPackage(t, s, externalSenderPackage)
			peer, groupID, welcome := newPeerGroupForExternalSender(t, cb.lastKeyPackage(), externalSenderPackage)
			s.OnDaveMLSWelcome(tt.welcomeTransitionID, welcome)
			if tt.peerCommit {
				commit, _, err := peer.CommitPendingProposals(context.Background(), groupID)
				if err != nil {
					t.Fatalf("peer.CommitPendingProposals: %v", err)
				}
				s.OnDaveMLSPrepareCommitTransition(tt.welcomeTransitionID+1, commit)
			}

			stats := s.Stats()
			if stats.WelcomesJoined != 1 || tt.peerCommit && stats.CommitsProcessed != 1 {
				t.Fatalf("WelcomesJoined = %d, CommitsProcessed = %d", stats.WelcomesJoined, stats.CommitsProcessed)
			}
			if armed := stats.RecoveryAttemptsTransport > 0; armed != tt.wantArmed {
				t.Fatalf("recovery armed = %v, want %v", armed, tt.wantArmed)
			}
		})
	}
}
