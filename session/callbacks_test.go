package session

import (
	"sync"
	"testing"
	"time"
)

// gatedCallbacks holds the first key package send until release is closed,
// and closes sending when it starts. Later sends go straight through, so a
// handler that skips sendMu finishes instead of waiting on the gate.
type gatedCallbacks struct {
	kpCapturingCallbacks
	sending chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGatedCallbacks() *gatedCallbacks {
	return &gatedCallbacks{sending: make(chan struct{}), release: make(chan struct{})}
}

func (c *gatedCallbacks) SendMLSKeyPackage(kp []byte) error {
	first := false
	c.once.Do(func() {
		first = true
		close(c.sending)
	})
	if first {
		<-c.release
	}

	return c.kpCapturingCallbacks.SendMLSKeyPackage(kp)
}

// reentrantCallbacks calls back into the session from inside a send.
type reentrantCallbacks struct {
	kpCapturingCallbacks
	s *Session
}

func (c *reentrantCallbacks) SendMLSKeyPackage(kp []byte) error {
	useSession(c.s)

	return c.kpCapturingCallbacks.SendMLSKeyPackage(kp)
}

func useSession(s *Session) {
	_ = s.Ready()
	_ = s.State()
	_ = s.Stats()
	_, _ = s.Encrypt(1, []byte{0x01, 0x02, 0x03}, make([]byte, 128))
	_, _ = s.Decrypt("222222222", []byte{0x01, 0x02, 0x03}, make([]byte, 128))
	s.AddUser("222222222")
	s.RemoveUser("222222222")
}

// within fails the test if fn does not return within a second.
func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s did not return within 1s", what)
	}
}

func TestSend_CallbackMayUseSession(t *testing.T) {
	s, _ := setupActiveSoleMemberSessionWithKey(t)
	cb := &reentrantCallbacks{s: s}
	s.callbacks = cb

	within(t, "OnDavePrepareEpoch", func() { s.OnDavePrepareEpoch(1, 1) })
	if cb.lastKeyPackage() == nil {
		t.Fatal("OnDavePrepareEpoch sent no key package")
	}
}

func TestSend_SessionUsableWhileSending(t *testing.T) {
	s, _ := setupActiveSoleMemberSessionWithKey(t)
	cb := newGatedCallbacks()
	s.callbacks = cb

	handlerDone := make(chan struct{})
	go func() {
		s.OnDavePrepareEpoch(1, 1)
		close(handlerDone)
	}()
	<-cb.sending
	within(t, "the session's methods", func() { useSession(s) })
	close(cb.release)
	<-handlerDone
}

func TestSend_HandlersWaitForSendInProgress(t *testing.T) {
	tests := []struct {
		name    string
		handler func(s *Session)
	}{
		{name: "OnSelectProtocolAck", handler: func(s *Session) { s.OnSelectProtocolAck(1) }},
		{name: "OnDavePrepareTransition", handler: func(s *Session) { s.OnDavePrepareTransition(1, 1) }},
		{name: "OnDaveExecuteTransition", handler: func(s *Session) { s.OnDaveExecuteTransition(1) }},
		{name: "OnDavePrepareEpoch", handler: func(s *Session) { s.OnDavePrepareEpoch(1, 1) }},
		{name: "OnDaveMLSExternalSenderPackage", handler: func(s *Session) { s.OnDaveMLSExternalSenderPackage(nil) }},
		{name: "OnDaveMLSProposals", handler: func(s *Session) { s.OnDaveMLSProposals(nil) }},
		{name: "OnDaveMLSPrepareCommitTransition", handler: func(s *Session) { s.OnDaveMLSPrepareCommitTransition(1, nil) }},
		{name: "OnDaveMLSWelcome", handler: func(s *Session) { s.OnDaveMLSWelcome(1, nil) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := setupActiveSoleMemberSessionWithKey(t)
			cb := newGatedCallbacks()
			s.callbacks = cb

			sendingDone := make(chan struct{})
			go func() {
				s.OnDavePrepareEpoch(1, 1)
				close(sendingDone)
			}()
			<-cb.sending
			handlerDone := make(chan struct{})
			go func() {
				tt.handler(s)
				close(handlerDone)
			}()
			select {
			case <-handlerDone:
				t.Fatal("the handler ran while another handler's send was in progress")
			case <-time.After(50 * time.Millisecond):
			}
			close(cb.release)
			<-sendingDone
			<-handlerDone
		})
	}
}
