package session

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// commitCapture is the Callbacks of a session under test. It keeps every op 28
// payload the session sends.
type commitCapture struct {
	testCallbacks
	mu      sync.Mutex
	commits [][]byte
}

func (c *commitCapture) SendMLSCommitWelcome(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commits = append(c.commits, bytes.Clone(payload))

	return nil
}

func (c *commitCapture) sent() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slices.Clone(c.commits)
}

// batchCall is recorder alone in an established group, expecting users to
// join, with the gateway's signer to propose them.
type batchCall struct {
	s       *Session
	gateway gatewaySender
	sent    *commitCapture
}

func newBatchCall(tb testing.TB, users ...godave.UserID) batchCall {
	tb.Helper()
	pkg, priv := buildExternalSenderPackageWithKey(tb)
	cb := &commitCapture{}
	s := New(recorder, cb)
	closeAtCleanup(tb, s)
	s.SetChannelID(callChannel)
	s.OnSelectProtocolAck(1)
	s.OnDaveMLSExternalSenderPackage(pkg)
	s.OnDavePrepareTransition(0, 1)
	if !s.State().Ready {
		tb.Fatal("setup: recorder is not encrypting alone")
	}
	for _, id := range users {
		s.AddUser(id)
	}

	return batchCall{s: s, gateway: gatewaySender{pkg: pkg, key: ciphersuite.NewSignaturePrivateKey(priv)}, sent: cb}
}

// propose signs p at the group's epoch the way the gateway does. It returns
// the MLSMessage and the ProposalRef a commit cites it by.
func (c batchCall) propose(tb testing.TB, p *group.Proposal) (msg, ref []byte) {
	tb.Helper()
	epoch, err := c.s.mlsClient.client.Epoch(context.Background(), c.s.groupID)
	if err != nil {
		tb.Fatalf("epoch: %v", err)
	}
	msg, ref, err = c.gateway.propose(c.s.groupID, epoch, p)
	if err != nil {
		tb.Fatal(err)
	}

	return msg, ref
}

// add proposes adding id with a fresh key package.
func (c batchCall) add(tb testing.TB, id godave.UserID) (msg, ref []byte) {
	tb.Helper()
	identity, err := userIDToIdentityBytes(id)
	if err != nil {
		tb.Fatal(err)
	}
	kp, err := keypackages.UnmarshalKeyPackage(freshKeyPackageBytesForIdentity(tb, identity))
	if err != nil {
		tb.Fatal(err)
	}

	return c.propose(tb, group.NewAddProposal(kp))
}

// processBatch hands batch to processProposalBatchLocked and returns its error.
func (c batchCall) processBatch(batch []byte) error {
	c.s.lockMLS()
	defer c.s.unlockMLS()

	return c.s.processProposalBatchLocked(batch)
}

// groupState returns the session's stored group state.
func (c batchCall) groupState(tb testing.TB) []byte {
	tb.Helper()
	state, err := c.s.mlsClient.store.LoadGroupState(context.Background(), group.NewGroupID(c.s.groupID))
	if err != nil {
		tb.Fatal(err)
	}

	return state
}

// restoreGroupState puts back a state groupState returned.
func (c batchCall) restoreGroupState(tb testing.TB, state []byte) {
	tb.Helper()
	if err := c.s.mlsClient.store.SaveGroupState(context.Background(), group.NewGroupID(c.s.groupID), state); err != nil {
		tb.Fatal(err)
	}
}

// withSender rewrites the sender of msg without signing it again. The message
// still parses, but it no longer comes from the gateway's external sender.
func withSender(t *testing.T, msg []byte, sender framing.Sender, membershipTag []byte) []byte {
	t.Helper()

	return mutateMLSMessage(t, msg, func(m *framing.MLSMessage) {
		pub, _ := m.AsPublic()
		pub.Content.Sender = sender
		pub.MembershipTag = membershipTag
	})
}

// withOverlongAuthenticatedData encodes the empty authenticated_data of the
// gateway's proposal msg in two bytes instead of one. RFC 9420 §2.1.2 wants
// the shortest encoding, so mls-go won't parse the message, though every
// length in it still adds up.
func withOverlongAuthenticatedData(t *testing.T, msg []byte, groupIDLen int) []byte {
	t.Helper()
	at := 2 + 2 + 1 + groupIDLen + 8 + 1 + 4 // version, wire_format, group_id<V>, epoch, external sender
	if msg[at] != 0x00 {
		t.Fatalf("byte %d of the proposal is %#x, want the empty authenticated_data's length", at, msg[at])
	}
	out := append(slices.Clone(msg[:at]), 0x40, 0x00)

	return append(out, msg[at+1:]...)
}

// TestOnDaveMLSProposals_TakesInEveryProposalInABatch hands a session one op 27
// with several proposals. The session takes in every one DAVE allows, refuses
// the others, and its commit cites exactly the ones it took in.
func TestOnDaveMLSProposals_TakesInEveryProposalInABatch(t *testing.T) {
	tests := []struct {
		name string
		// between builds the message that goes between the adds of speaker and
		// joiner2, and reports whether the session should take it in.
		between func(t *testing.T, c batchCall) (msg, ref []byte, takenIn bool)
	}{
		{
			name: "an add",
			between: func(t *testing.T, c batchCall) ([]byte, []byte, bool) {
				t.Helper()
				msg, ref := c.add(t, joiner1)

				return msg, ref, true
			},
		},
		{
			name: "a proposal type DAVE refuses",
			between: func(t *testing.T, c batchCall) ([]byte, []byte, bool) {
				t.Helper()
				msg, ref := c.propose(t, group.NewPreSharedKeyProposal(1, []byte("psk")))

				return msg, ref, false
			},
		},
		{
			name: "an add from a member sender",
			between: func(t *testing.T, c batchCall) ([]byte, []byte, bool) {
				t.Helper()
				msg, ref := c.add(t, joiner1)
				tag := bytes.Repeat([]byte{0xaa}, 32)

				return withSender(t, msg, framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0}, tag), ref, false
			},
		},
		{
			name: "an add from a new member sender",
			between: func(t *testing.T, c batchCall) ([]byte, []byte, bool) {
				t.Helper()
				msg, ref := c.add(t, joiner1)

				return withSender(t, msg, framing.Sender{Type: framing.SenderTypeNewMemberProposal}, nil), ref, false
			},
		},
		{
			name: "an add mls-go can't parse",
			between: func(t *testing.T, c batchCall) ([]byte, []byte, bool) {
				t.Helper()
				msg, ref := c.add(t, joiner1)

				return withOverlongAuthenticatedData(t, msg, len(c.s.groupID)), ref, false
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newBatchCall(t, speaker, joiner1, joiner2)
			first, firstRef := c.add(t, speaker)
			middle, middleRef, takenIn := tt.between(t, c)
			last, lastRef := c.add(t, joiner2)
			want := [][]byte{firstRef, lastRef}
			var refused uint64
			if takenIn {
				want = append(want, middleRef)
			} else {
				refused = 1
			}

			c.s.OnDaveMLSProposals(buildProposalBatch(bytes.Join([][]byte{first, middle, last}, nil)))

			sent := c.sent.sent()
			if len(sent) != 1 {
				t.Fatalf("the session sent %d commits, want 1", len(sent))
			}
			info, err := parseCommit(recorder, sent[0])
			if err != nil {
				t.Fatalf("the session's op 28: %v", err)
			}
			if !sameRefs(info.refs, want) {
				t.Errorf("the commit cites %d proposals, want the %d the session took in", len(info.refs), len(want))
			}
			if got := c.s.Stats().ProposalsRejected; got != refused {
				t.Errorf("ProposalsRejected = %d, want %d", got, refused)
			}
		})
	}
}

// TestProcessProposalBatch_RefusesAVectorItCannotFrame hands a session an op 27
// whose vector doesn't split into whole messages. Processing fails without a
// panic, and the session takes in none of the batch, so it commits nothing.
func TestProcessProposalBatch_RefusesAVectorItCannotFrame(t *testing.T) {
	c := newBatchCall(t, speaker, joiner1, joiner2)
	first, _ := c.add(t, speaker)
	second, _ := c.add(t, joiner1)
	last, _ := c.add(t, joiner2)
	whole := bytes.Join([][]byte{first, second}, nil)
	refuses := func(t *testing.T, vec []byte) {
		t.Helper()
		batch := buildProposalBatch(vec)
		if err := c.processBatch(batch); err == nil {
			t.Fatal("processing the batch succeeded")
		}
		c.s.OnDaveMLSProposals(batch)
		if n := len(c.sent.sent()); n != 0 {
			t.Fatalf("the session sent %d commits over a batch it can't frame", n)
		}
	}

	t.Run("the last message is cut short", func(t *testing.T) {
		for cut := 1; cut < len(last); cut++ {
			refuses(t, append(slices.Clone(whole), last[:cut]...))
		}
	})
	t.Run("bytes follow the last message", func(t *testing.T) {
		refuses(t, append(slices.Clone(whole), 0xde, 0xad, 0xbe, 0xef))
	})
}

// BenchmarkProcessProposalBatch_FortyAdds times taking in one op 27 that adds
// 40 members, as at the start of an op night.
func BenchmarkProcessProposalBatch_FortyAdds(b *testing.B) {
	users := make([]godave.UserID, 40)
	for i := range users {
		users[i] = godave.UserID(strconv.Itoa(700000000 + i))
	}
	c := newBatchCall(b, users...)
	msgs := make([][]byte, 0, len(users))
	for _, id := range users {
		msg, _ := c.add(b, id)
		msgs = append(msgs, msg)
	}
	vec := bytes.Join(msgs, nil)
	batch := buildProposalBatch(vec)
	alone := c.groupState(b)

	b.Run("frame", func(b *testing.B) {
		for b.Loop() {
			if _, err := splitMLSMessages(vec); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("take in", func(b *testing.B) {
		for b.Loop() {
			b.StopTimer()
			c.restoreGroupState(b, alone)
			b.StartTimer()
			if err := c.processBatch(batch); err != nil {
				b.Fatal(err)
			}
		}
	})
}
