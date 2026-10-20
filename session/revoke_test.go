package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"sync"
	"testing"

	"github.com/thomas-vilte/mls-go/group"
)

// buildRevokeBatch builds a revoke op 27 payload: operation_type 1, then
// ProposalRef proposal_refs<V> (protocol.md:1020-1048). A ProposalRef is an
// opaque HashReference<V>, so each ref carries its own length inside the
// vector, the way mlspp writes it for libdave.
func buildRevokeBatch(refs ...[]byte) []byte {
	var body []byte
	for _, ref := range refs {
		body = append(body, writeVLBytes(ref)...)
	}

	return append([]byte{0x01}, writeVLBytes(body)...)
}

// cachedProposalRefs returns the refs of the proposals s holds that no
// announced commit covers yet. While a commit of its own waits, those are the
// ones that commit cites. Otherwise they are the ones its group holds for its
// next commit. A session with no group holds none.
func cachedProposalRefs(tb testing.TB, s *Session) [][]byte {
	tb.Helper()
	s.lockMLS()
	defer s.unlockMLS()
	if s.mlsClient == nil || len(s.groupID) == 0 {
		return nil
	}
	state := s.preCommitGroupState
	if len(state) == 0 {
		var err error
		state, err = s.mlsClient.store.LoadGroupState(context.Background(), group.NewGroupID(s.groupID))
		if err != nil {
			tb.Fatalf("load group state: %v", err)
		}
	}
	g, err := group.UnmarshalGroupState(state)
	if err != nil {
		tb.Fatalf("unmarshal group state: %v", err)
	}
	stored := g.StoredProposals()
	refs := make([][]byte, 0, len(stored))
	for _, p := range stored {
		refs = append(refs, p.Ref)
	}

	return refs
}

// TestProcessProposalBatch_RevokeWithdrawsTheRefsItNames hands a session that
// holds two proposals a revoke op 27. The session withdraws each proposal the
// revoke names. A revoke it can't read, or one with more refs than
// maxRevokeRefs, withdraws nothing.
func TestProcessProposalBatch_RevokeWithdrawsTheRefsItNames(t *testing.T) {
	c := newBatchCall(t, speaker, joiner1)
	first, firstRef := c.add(t, speaker)
	second, secondRef := c.add(t, joiner1)
	if err := c.processBatch(buildProposalBatch(bytes.Join([][]byte{first, second}, nil))); err != nil {
		t.Fatalf("setup: %v", err)
	}
	both := [][]byte{firstRef, secondRef}
	holding := c.groupState(t)
	// revoke builds a revoke op 27 whose vector holds parts byte for byte, for
	// vectors buildRevokeBatch can't make.
	revoke := func(parts ...[]byte) []byte {
		return append([]byte{0x01}, writeVLBytes(bytes.Join(parts, nil))...)
	}
	// short ends after firstRef, though its vector's length counts secondRef too.
	short := buildRevokeBatch(firstRef, secondRef)
	short = short[:len(short)-len(writeVLBytes(secondRef))]

	tests := []struct {
		name string
		op27 []byte
		left [][]byte // the proposals the session still holds
	}{
		{name: "one ref", op27: buildRevokeBatch(firstRef), left: [][]byte{secondRef}},
		{name: "both refs, the later one first", op27: buildRevokeBatch(secondRef, firstRef)},
		{
			name: "as many refs as maxRevokeRefs",
			op27: buildRevokeBatch(slices.Repeat([][]byte{firstRef}, maxRevokeRefs)...),
			left: [][]byte{secondRef},
		},
		{
			name: "more refs than maxRevokeRefs",
			op27: buildRevokeBatch(slices.Repeat([][]byte{firstRef}, maxRevokeRefs+1)...),
			left: both,
		},
		{name: "the vector ends inside a ref's length", op27: revoke(writeVLBytes(firstRef), []byte{0x40}), left: both},
		{name: "the vector ends inside a ref", op27: revoke(writeVLBytes(firstRef), []byte{0x20}, secondRef[:31]), left: both},
		{name: "the vector runs past the op 27", op27: short, left: both},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.restoreGroupState(t, holding)

			_ = c.processBatch(tt.op27)

			if left := cachedProposalRefs(t, c.s); !sameRefs(left, tt.left) {
				t.Errorf("the session holds %d proposals after the revoke, want %d", len(left), len(tt.left))
			}
		})
	}
}

// TestReadRevokeRefs_ReadsWhatMlsppWrites reads revoke op 27s that mlspp
// encoded, at 1cc50a124a3bc4e143a787ec934280dc70c1034d, the commit libdave
// pins. A short C++ driver, compiled with only mlspp's lib/tls_syntax and
// lib/bytes, wrote the operation type as the bool true and then the refs as a
// std::vector<bytes>, the types libdave's ProcessProposals reads. The op27
// strings are the hex it printed. buildRevokeBatch made none of these bytes,
// so the reader can't pass by sharing a mistake with it.
func TestReadRevokeRefs_ReadsWhatMlsppWrites(t *testing.T) {
	refA := "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	refB := "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324"
	tests := []struct {
		name string
		op27 string
		want []string
	}{
		{
			name: "one ref",
			op27: "012120a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
			want: []string{refA},
		},
		{
			name: "two refs",
			op27: "01404220a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"2005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324",
			want: []string{refA, refB},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op27, err := hex.DecodeString(tt.op27)
			if err != nil {
				t.Fatal(err)
			}

			refs, err := readRevokeRefs(op27[1:]) // the payload after operation_type
			if err != nil {
				t.Fatalf("the reader refused the revoke: %v", err)
			}
			got := make([]string, 0, len(refs))
			for _, ref := range refs {
				got = append(got, hex.EncodeToString(ref))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("read refs %v, want %v", got, tt.want)
			}
		})
	}
}

// TestOnDaveMLSProposals_RevokeSkipsCommit verifies that a revoke batch
// (operation_type=1) with empty refs (the success path) does not trigger
// SendMLSCommitWelcome — the spec only requires committing "if there are one
// or more cached proposals after processing" (protocol.md:176), and revoke
// only removes. We use a real group built by ensureMLSClientLocked so the
// handler doesn't abort on a missing group; with 0 refs, the revoke is a
// no-op by design (idempotent), and our early return skips the commit.
func TestOnDaveMLSProposals_RevokeSkipsCommit(t *testing.T) {
	cb := &commitCountingCallbacks{}
	s := New("123456789", cb)
	s.OnSelectProtocolAck(1) // builds mlsClient

	// Set an arbitrary groupID (not present in the store) to pass the
	// handler's group check. With 0 refs, processRevokeProposalsLocked
	// returns nil before touching the client, so the group doesn't need to
	// actually exist.
	s.mu.Lock()
	s.groupID = []byte("group-X")
	s.mu.Unlock()

	// Reset counters after setup (OnSelectProtocolAck sends a key package but no commit).
	cb.mu.Lock()
	cb.commits = 0
	cb.mu.Unlock()

	// Revoke batch with 0 refs (success/no-op path). The handler must reach
	// the early return in processAndCommitProposalBatchLocked without
	// invoking a commit.
	batch := buildRevokeBatch()
	s.OnDaveMLSProposals(batch)

	cb.mu.Lock()
	got := cb.commits
	cb.mu.Unlock()
	if got != 0 {
		t.Errorf("OnDaveMLSProposals(revoke) invoked SendMLSCommitWelcome %d times; want 0 (revoke doesn't commit)", got)
	}
}

type commitCountingCallbacks struct {
	mu          sync.Mutex
	keyPackages [][]byte
	commits     int
}

func (c *commitCountingCallbacks) SendMLSKeyPackage(kp []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyPackages = append(c.keyPackages, append([]byte(nil), kp...))

	return nil
}

func (c *commitCountingCallbacks) SendMLSCommitWelcome([]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commits++

	return nil
}

func (c *commitCountingCallbacks) SendReadyForTransition(uint16) error   { return nil }
func (c *commitCountingCallbacks) SendInvalidCommitWelcome(uint16) error { return nil }
