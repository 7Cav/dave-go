package session

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/frame"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// Users in the fake call. A DAVE identity is the user's snowflake, so these
// are digits.
const (
	recorder godave.UserID = "123456789"
	speaker  godave.UserID = "222222222"
	joiner1  godave.UserID = "333333333"
	joiner2  godave.UserID = "444444444"
	joiner3  godave.UserID = "555555555"
)

const (
	callChannel godave.ChannelID = 987654321
	// gatewayRecoveryTimeout keeps the commit and recovery watchdogs out of
	// the tests. A commit that should have won and didn't then shows up as no
	// winner, not as a recovery that hides it.
	gatewayRecoveryTimeout = time.Minute
	maxSettleRounds        = 64
	mediaInterval          = 2 * time.Millisecond
)

// clientOp is an opcode a client sends the voice gateway, numbered as
// protocol.md numbers it.
type clientOp uint8

const (
	opReadyForTransition   clientOp = 23
	opKeyPackage           clientOp = 26
	opCommitWelcome        clientOp = 28
	opInvalidCommitWelcome clientOp = 31
)

// clientMessage is one message a client's Session sent the gateway.
type clientMessage struct {
	op           clientOp
	transitionID uint16
	payload      []byte
}

// serverMessage is one message the gateway queued for a client. what names it
// for the history a failure prints, and apply makes the handler call that
// delivers it.
type serverMessage struct {
	what      string
	apply     func(*Session)
	proposals bool // an op 27
}

// gatewaySender is the voice gateway's MLS external sender. It holds the op 25
// package every group names and the key the gateway signs proposals with.
type gatewaySender struct {
	pkg []byte
	key *ciphersuite.SignaturePrivateKey
}

func newGatewaySender(t *testing.T) gatewaySender {
	t.Helper()
	pkg, priv := buildExternalSenderPackageWithKey(t)

	return gatewaySender{pkg: pkg, key: ciphersuite.NewSignaturePrivateKey(priv)}
}

// propose signs p as the external sender for groupID at epoch. It returns the
// MLSMessage op 27 carries and the ProposalRef a commit cites it by. Only
// member senders sign over the group context (RFC 9420 §6.1), so this needs
// nothing from any member's group state.
func (e gatewaySender) propose(groupID []byte, epoch uint64, p *group.Proposal) (msg, ref []byte, err error) {
	content := framing.FramedContent{
		GroupID:           groupID,
		Epoch:             epoch,
		Sender:            framing.Sender{Type: framing.SenderTypeExternal, SenderIndex: 0},
		AuthenticatedData: []byte{},
		Body:              framing.ProposalBody{Data: group.ProposalMarshal(p)},
	}
	pm, err := framing.NewPublicMessage(content, e.key, nil, nil, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		return nil, nil, fmt.Errorf("sign external proposal: %w", err)
	}
	ac := framing.AuthenticatedContent{WireFormat: framing.WireFormatPublicMessage, Content: pm.Content, Auth: pm.Auth}

	return framing.NewMLSMessagePublic(pm).Marshal(), group.ComputeProposalRef(ac.Marshal(), ciphersuite.MLS128DHKEMP256), nil
}

// gatewayProposal is a proposal the gateway broadcast in the current epoch and
// has not revoked.
type gatewayProposal struct {
	what    string
	msg     []byte
	ref     []byte
	to      []*fakeClient
	adds    godave.UserID // the user an add adds; empty for any other proposal
	remove  bool
	removes uint32 // the leaf a remove removes
}

// commitInfo is one op 28 the gateway received.
type commitInfo struct {
	from    godave.UserID
	nth     int // 1 for from's first commit built on this epoch
	groupID []byte
	epoch   uint64
	refs    [][]byte
	inline  bool
	stale   bool // the selection rule refused it when it arrived
	forced  bool // announced by forceWinner
	commit  []byte
	welcome []byte
}

type fakeClient struct {
	id     godave.UserID
	ssrc   uint32
	s      *Session
	kp     []byte // the key package the gateway would add; nil once in the group
	stale  bool   // its leaf in the roster is dead: it sent op 31 or a new key package
	inbox  []serverMessage
	outbox []clientMessage
	// commits counts the op 28s received per epoch, for commitInfo.nth.
	commits map[uint64]int
}

type gatewayTransition struct {
	id      uint16
	epoch   uint64          // the epoch it moves to
	members []godave.UserID // sent op 29 or op 30
	waiting map[godave.UserID]bool
}

type executedTransition struct {
	id      uint16
	epoch   uint64
	members []godave.UserID // sent op 22
	checked bool
}

type gatewayOptions struct {
	proposeDuringTransition bool
	recoveryTimeout         time.Duration
}

type gatewayOption func(*gatewayOptions)

// proposeDuringTransition makes the gateway send proposals for the new epoch
// as soon as it announces a commit, instead of after op 22.
func proposeDuringTransition() gatewayOption {
	return func(o *gatewayOptions) { o.proposeDuringTransition = true }
}

// sessionRecoveryTimeout gives every session the recovery timeout d instead
// of gatewayRecoveryTimeout, for a test that waits for a watchdog to fire or
// not.
func sessionRecoveryTimeout(d time.Duration) gatewayOption {
	return func(o *gatewayOptions) { o.recoveryTimeout = d }
}

// fakeGateway plays Discord's voice gateway for a call between real Sessions.
// It is the MLS external sender, relays the DAVE opcodes, picks the winning
// commit of each epoch by the protocol's rule and runs each transition
// through op 23 and op 22. The test decides when it takes each client's
// messages, so it can put a proposal batch in front of a commit still on the
// wire.
type fakeGateway struct {
	t       *testing.T
	sender  gatewaySender
	groupID []byte
	opts    gatewayOptions
	logs    *lockedBuffer
	logger  *slog.Logger
	media   *mediaPumps

	mu               sync.Mutex
	clients          []*fakeClient // connection order
	epoch            uint64
	established      bool
	roster           map[godave.UserID]uint32 // leaf of each group member
	proposals        []gatewayProposal
	transition       *gatewayTransition
	executed         []executedTransition
	nextTransitionID uint16
	holding          bool
	force            func(commitInfo) bool
	announced        []commitInfo
	restarts         []godave.UserID // op 31 senders, in order
	frames           int
	events           []string // what happened, for failure messages only
}

func newFakeGateway(t *testing.T, opts ...gatewayOption) *fakeGateway {
	t.Helper()
	g := &fakeGateway{
		t:       t,
		sender:  newGatewaySender(t),
		groupID: binary.BigEndian.AppendUint64(nil, uint64(callChannel)),
		logs:    &lockedBuffer{},
		media:   newMediaPumps(),
		roster:  map[godave.UserID]uint32{},
		opts:    gatewayOptions{recoveryTimeout: gatewayRecoveryTimeout},
	}
	for _, opt := range opts {
		opt(&g.opts)
	}
	g.logger = slog.New(slog.NewTextHandler(g.logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	// Registered first, so it runs after every session has closed.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		g.mu.Lock()
		history := strings.Join(g.events, "\n")
		g.mu.Unlock()
		t.Logf("gateway history:\n%s\n\nsession logs:\n%s", history, g.logs.String())
	})
	t.Cleanup(g.media.halt)

	return g
}

// connect adds id to the call the way disgo opens a voice connection. It sets
// the channel ID and SSRC before any message, then queues select_protocol_ack,
// clients_connect and the external sender package in that order.
// Before the group is established the newcomer also gets the adds already in
// flight (protocol.md "Initial Group Creation").
func (g *fakeGateway) connect(id godave.UserID, opts ...Option) *Session {
	g.t.Helper()
	snowflake, err := strconv.ParseUint(string(id), 10, 32)
	if err != nil {
		g.t.Fatalf("user %q: %v", id, err)
	}
	ssrc := uint32(snowflake)
	s := New(id, gatewayConn{gw: g, id: id},
		append([]Option{WithRecoveryTimeout(g.opts.recoveryTimeout), WithLogger(g.logger)}, opts...)...)
	closeAtCleanup(g.t, s)
	// Frames use the newest epoch at once, so a split in the new keys can't
	// hide behind the previous epoch that receivers still hold.
	s.sendRetentionTTL = 0
	s.SetChannelID(callChannel)
	s.AssignSsrcToCodec(ssrc, godave.CodecOpus)

	g.mu.Lock()
	defer g.mu.Unlock()
	others := slices.Clone(g.clients)
	c := &fakeClient{id: id, ssrc: ssrc, s: s, commits: map[uint64]int{}}
	g.clients = append(g.clients, c)
	c.inbox = append(c.inbox, selectProtocolAck(1), clientsConnect(ids(others)), externalSenderPackage(g.sender.pkg))
	if !g.established {
		for i, p := range g.proposals {
			c.inbox = append(c.inbox, proposalsMessage(buildProposalBatch(p.msg), p.what))
			g.proposals[i].to = append(p.to, c)
		}
	}
	for _, o := range others {
		o.inbox = append(o.inbox, clientsConnect([]godave.UserID{id}))
	}
	g.eventf("%s connects", id)
	g.media.start(id, ssrc, s)

	return s
}

// disconnect takes a pending member off the call the way a closed voice
// connection does. The gateway revokes the member's add if one is in flight
// and tells the others it left with op 13.
func (g *fakeGateway) disconnect(id godave.UserID) {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.clientLocked(id)
	if _, member := g.roster[id]; member {
		g.failf("disconnect only models a pending member, and %s is in the group", id)

		return
	}
	g.clients = slices.DeleteFunc(g.clients, func(o *fakeClient) bool { return o == c })
	g.eventf("%s disconnects", id)
	g.revokeAddLocked(c)
	for _, o := range g.clients {
		o.inbox = append(o.inbox, clientDisconnect(id))
	}
	g.media.stop(id)
}

// proposeRefused broadcasts, at the current epoch, a PreSharedKey proposal.
// DAVE doesn't allow the type, so every member refuses it, and no commit can
// win until the gateway revokes it.
func (g *fakeGateway) proposeRefused() {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.proposeLocked(group.NewPreSharedKeyProposal(1, []byte("psk")), gatewayProposal{what: "psk"}, g.membersLocked())
}

// revokeRefused revokes every proposal proposeRefused sent.
func (g *fakeGateway) revokeRefused() {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, p := range slices.Clone(g.proposals) {
		if p.what == "psk" {
			g.revokeLocked(p)
		}
	}
}

// prepareTransitionZero sends prepare_transition(0) to id. A session executes
// that initialization transition at once, which here makes it a sole member.
func (g *fakeGateway) prepareTransitionZero(id godave.UserID) {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.clientLocked(id)
	c.inbox = append(c.inbox, prepareTransition(0, 1))
}

// forceWinner makes the next received commit that pick accepts win its epoch,
// whether or not it cites every proposal. The protocol rules this out. It is
// for the case where the gateway announces a commit we already replaced.
func (g *fakeGateway) forceWinner(pick func(commitInfo) bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.force = pick
}

// proposalsOvertake moves the op 27s queued for id ahead of everything else
// queued for it, as if a batch for the next epoch overtook the op 29 that
// starts the epoch. A gateway that delivers in order can't do this.
func (g *fakeGateway) proposalsOvertake(id godave.UserID) {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.clientLocked(id)
	batches := slices.DeleteFunc(slices.Clone(c.inbox), func(m serverMessage) bool { return !m.proposals })
	c.inbox = append(batches, slices.DeleteFunc(c.inbox, func(m serverMessage) bool { return m.proposals })...)
	g.eventf("%s gets its op 27s first", id)
}

// holdCommits keeps op 28s on the wire until receiveCommits or releaseCommits.
func (g *fakeGateway) holdCommits() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.holding = true
}

// releaseCommits stops holding commits. The next receive takes them.
func (g *fakeGateway) releaseCommits() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.holding = false
}

// receiveCommits takes everything still on the wire from each named client,
// commits included, in the order named. Commits stay held afterwards.
func (g *fakeGateway) receiveCommits(ids ...godave.UserID) {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, id := range ids {
		g.takeLocked(g.clientLocked(id), false)
	}
}

// receive takes what each named client sent, or every client's in connection
// order, and acts on it. While commits are held, a client's messages stop at
// its first op 28. A websocket delivers in order, so a commit still on the
// wire holds back what the client sent after it. It reports how many messages
// it took.
func (g *fakeGateway) receive(ids ...godave.UserID) int {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	from := g.clients
	if len(ids) > 0 {
		from = nil
		for _, id := range ids {
			from = append(from, g.clientLocked(id))
		}
	}
	n := 0
	for _, c := range slices.Clone(from) {
		n += g.takeLocked(c, g.holding)
	}

	return n
}

// deliver hands every queued message to its session, in order, on one
// goroutine per client, all clients at once, and waits for every handler to
// return. Then it checks each transition executed since the last call. It
// reports how many messages it delivered.
func (g *fakeGateway) deliver() int {
	g.t.Helper()
	type batch struct {
		s    *Session
		msgs []serverMessage
	}
	var batches []batch
	n := 0
	g.mu.Lock()
	for _, c := range g.clients {
		if len(c.inbox) == 0 {
			continue
		}
		batches = append(batches, batch{s: c.s, msgs: c.inbox})
		n += len(c.inbox)
		c.inbox = nil
	}
	g.mu.Unlock()

	var wg sync.WaitGroup
	for _, b := range batches {
		wg.Go(func() {
			for _, m := range b.msgs {
				m.apply(b.s)
			}
		})
	}
	wg.Wait()
	g.checkExecuted()

	return n
}

// settle delivers and receives until neither has anything left.
func (g *fakeGateway) settle() {
	g.t.Helper()
	for range maxSettleRounds {
		if g.deliver()+g.receive() == 0 {
			return
		}
	}
	g.t.Fatalf("the call did not settle after %d rounds", maxSettleRounds)
}

// establish connects ids, settles, and requires one established group with
// all of them in it.
func (g *fakeGateway) establish(ids ...godave.UserID) {
	g.t.Helper()
	for _, id := range ids {
		g.connect(id)
	}
	g.settle()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, id := range ids {
		if _, member := g.roster[id]; !member || !g.established {
			g.failf("setup: %s is not in an established group", id)
		}
	}
}

// takeLocked acts on what c sent, in order. With hold, it stops at c's first
// commit, which stays on the wire with everything after it.
func (g *fakeGateway) takeLocked(c *fakeClient, hold bool) int {
	n := 0
	for len(c.outbox) > 0 {
		m := c.outbox[0]
		if hold && m.op == opCommitWelcome {
			break
		}
		c.outbox = c.outbox[1:]
		n++
		switch m.op {
		case opKeyPackage:
			g.keyPackageLocked(c, m.payload)
		case opCommitWelcome:
			g.commitLocked(c, m.payload)
		case opReadyForTransition:
			g.readyLocked(c, m.transitionID)
		case opInvalidCommitWelcome:
			g.invalidLocked(c, m.transitionID)
		}
	}

	return n
}

// keyPackageLocked handles op 26. Before the group is established it sends
// the add to every other pending member. After, it proposes removing the
// sender's old leaf, if it has one, and adding the new key package, unless a
// transition is pending.
func (g *fakeGateway) keyPackageLocked(c *fakeClient, kp []byte) {
	k, err := keypackages.UnmarshalKeyPackage(kp)
	if err != nil {
		g.failf("%s sent a key package that doesn't parse: %v", c.id, err)

		return
	}
	// The gateway requires the credential identity to be the sender's
	// snowflake (protocol.md "Key Packages", "Validation").
	want, err := userIDToIdentityBytes(c.id)
	if err != nil || k.LeafNode == nil || k.LeafNode.Credential == nil || !bytes.Equal(k.LeafNode.Credential.Identity, want) {
		g.failf("%s sent a key package for another identity", c.id)

		return
	}
	g.eventf("%s sends a key package", c.id)
	c.kp = kp
	if _, member := g.roster[c.id]; member {
		c.stale = true
	}
	// A pending member can't use two key packages at once.
	g.revokeAddLocked(c)
	if !g.established {
		g.proposeAddLocked(c, g.othersLocked(c))

		return
	}
	if g.transition == nil || g.opts.proposeDuringTransition {
		g.reproposeLocked()
	}
}

// commitLocked handles op 28. The first commit for the current epoch that the
// selection rule accepts wins, and the gateway drops every other without a
// reply.
func (g *fakeGateway) commitLocked(c *fakeClient, payload []byte) {
	info, err := parseCommit(c.id, payload)
	if err != nil {
		g.failf("%s sent an op 28 the gateway can't read: %v", c.id, err)

		return
	}
	c.commits[info.epoch]++
	info.nth = c.commits[info.epoch]
	ok, why := g.selectableLocked(c, info)
	info.stale = !ok
	if g.force != nil && g.force(info) {
		g.force = nil
		info.forced = true
		if info.epoch != g.epoch {
			g.failf("forced commit from %s is for epoch %d, not the current epoch %d", c.id, info.epoch, g.epoch)

			return
		}
		g.eventf("epoch %d: %s commit %d forced through (the rule says: %s)", g.epoch, c.id, info.nth, cmp.Or(why, "valid"))
		g.announceLocked(info)

		return
	}
	if !ok {
		g.eventf("epoch %d: %s commit %d for epoch %d dropped: %s", g.epoch, c.id, info.nth, info.epoch, why)

		return
	}
	g.announceLocked(info)
}

// selectableLocked applies Commit Ordering and Voice Gateway Commit Validity
// (protocol.md) to a commit as it arrives.
func (g *fakeGateway) selectableLocked(c *fakeClient, info commitInfo) (bool, string) {
	switch {
	case !bytes.Equal(info.groupID, g.groupID):
		return false, "another group"
	case info.epoch != g.epoch:
		return false, "not the current epoch"
	case g.transition != nil:
		return false, "a transition is pending"
	case info.inline:
		return false, "inline proposal"
	case len(info.refs) == 0:
		return false, "no proposal references"
	case !g.eligibleLocked(c):
		return false, "committer not eligible"
	}
	var want [][]byte
	for _, p := range g.proposals {
		// Before the group is established the gateway sends a pending
		// member every add but its own, which it can't commit.
		if !g.established && p.adds == c.id {
			continue
		}
		want = append(want, p.ref)
	}
	if !sameRefs(info.refs, want) {
		return false, fmt.Sprintf("cites %d proposals, and %d unrevoked proposals were broadcast", len(info.refs), len(want))
	}

	return true, ""
}

func (g *fakeGateway) eligibleLocked(c *fakeClient) bool {
	if g.established {
		_, member := g.roster[c.id]

		return member && !c.stale
	}

	return c.kp != nil
}

// announceLocked broadcasts info as the epoch's winner. It sends op 29 to the
// members the commit was built on and op 30 to each member it adds, and the
// transition waits for each of them to send op 23.
func (g *fakeGateway) announceLocked(info commitInfo) {
	cited := make([]gatewayProposal, 0, len(info.refs))
	for _, ref := range info.refs {
		i := slices.IndexFunc(g.proposals, func(p gatewayProposal) bool { return bytes.Equal(p.ref, ref) })
		if i < 0 {
			g.failf("epoch %d: %s commit %d cites a proposal the gateway never sent", g.epoch, info.from, info.nth)

			return
		}
		cited = append(cited, g.proposals[i])
	}
	added := map[godave.UserID]bool{}
	for _, p := range cited {
		if p.adds != "" {
			added[p.adds] = true
		}
	}
	if len(added) > 0 && len(info.welcome) == 0 {
		g.failf("epoch %d: %s commit %d adds members and carries no Welcome", g.epoch, info.from, info.nth)

		return
	}
	// Before the group is established the committer's local group holds only
	// the committer.
	base := g.roster
	if !g.established {
		base = map[godave.UserID]uint32{info.from: 0}
	}
	next := nextRoster(base, cited)

	g.nextTransitionID++
	tr := &gatewayTransition{id: g.nextTransitionID, epoch: info.epoch + 1, waiting: map[godave.UserID]bool{}}
	for _, c := range g.clients {
		_, inBase := base[c.id]
		switch {
		case added[c.id]:
			c.inbox = append(c.inbox, welcome(tr.id, info.welcome))
			c.kp, c.stale = nil, false
		case inBase && !c.stale:
			c.inbox = append(c.inbox, announceCommit(tr.id, info.commit))
			// The first committer's key package is its leaf now.
			c.kp = nil
		default:
			continue
		}
		tr.members = append(tr.members, c.id)
		tr.waiting[c.id] = true
	}
	for _, c := range g.clients {
		// A member the commit removes is pending again.
		if _, was := base[c.id]; was {
			if _, still := next[c.id]; !still {
				c.stale = false
			}
		}
	}
	g.roster, g.epoch, g.established, g.proposals, g.transition = next, info.epoch+1, true, nil, tr
	g.announced = append(g.announced, info)
	g.eventf("epoch %d: %s commit %d wins; transition %d to epoch %d, roster %s",
		info.epoch, info.from, info.nth, tr.id, tr.epoch, formatRoster(next))
	if g.opts.proposeDuringTransition {
		g.reproposeLocked()
	}
}

// readyLocked handles op 23 and executes the transition once every member
// it waits for is ready. The fake has no transition timeout.
func (g *fakeGateway) readyLocked(c *fakeClient, id uint16) {
	tr := g.transition
	if tr == nil || tr.id != id || !tr.waiting[c.id] {
		g.eventf("%s ready for transition %d, which isn't waiting for it", c.id, id)

		return
	}
	delete(tr.waiting, c.id)
	g.eventf("%s ready for transition %d", c.id, id)
	if len(tr.waiting) == 0 {
		g.executeLocked()
	}
}

// executeLocked sends op 22 to every member of the pending transition whose
// leaf isn't stale.
func (g *fakeGateway) executeLocked() {
	tr := g.transition
	g.transition = nil
	x := executedTransition{id: tr.id, epoch: tr.epoch}
	for _, id := range tr.members {
		c := g.clientLocked(id)
		if c == nil || c.stale {
			continue
		}
		c.inbox = append(c.inbox, executeTransition(tr.id))
		x.members = append(x.members, id)
	}
	g.executed = append(g.executed, x)
	g.eventf("transition %d to epoch %d executed by %v", tr.id, tr.epoch, x.members)
	if !g.opts.proposeDuringTransition {
		g.reproposeLocked()
	}
}

// invalidLocked handles op 31. The sender's leaf is dead, and the gateway
// proposes removing it (protocol.md "Recovery from Invalid Commit or
// Welcome").
func (g *fakeGateway) invalidLocked(c *fakeClient, id uint16) {
	g.restarts = append(g.restarts, c.id)
	g.eventf("%s flags transition %d as invalid (op 31)", c.id, id)
	if _, member := g.roster[c.id]; member {
		c.stale = true
	}
	if tr := g.transition; tr != nil && tr.id == id && tr.waiting[c.id] {
		delete(tr.waiting, c.id)
		if len(tr.waiting) == 0 {
			g.executeLocked()
		}
	}
	if g.transition == nil || g.opts.proposeDuringTransition {
		g.reproposeLocked()
	}
}

// reproposeLocked proposes, at the current epoch, a remove for each stale
// member's leaf, then an add for each client holding a key package, in
// connection order. Each goes in an op 27 of its own to the members whose
// leaves aren't stale. Proposals already in flight aren't sent again.
func (g *fakeGateway) reproposeLocked() {
	if !g.established {
		return
	}
	to := g.membersLocked()
	for _, c := range g.clients {
		leaf, member := g.roster[c.id]
		pending := slices.ContainsFunc(g.proposals, func(p gatewayProposal) bool { return p.remove && p.removes == leaf })
		if member && c.stale && !pending {
			g.proposeLocked(group.NewRemoveProposal(group.LeafNodeIndex(leaf)),
				gatewayProposal{what: fmt.Sprintf("remove(%s@%d)", c.id, leaf), remove: true, removes: leaf}, to)
		}
	}
	for _, c := range g.clients {
		if c.kp != nil && !slices.ContainsFunc(g.proposals, func(p gatewayProposal) bool { return p.adds == c.id }) {
			g.proposeAddLocked(c, to)
		}
	}
}

func (g *fakeGateway) proposeAddLocked(c *fakeClient, to []*fakeClient) {
	k, err := keypackages.UnmarshalKeyPackage(c.kp)
	if err != nil {
		g.failf("add %s: %v", c.id, err)

		return
	}
	g.proposeLocked(group.NewAddProposal(k), gatewayProposal{what: fmt.Sprintf("add(%s)", c.id), adds: c.id}, to)
}

// proposeLocked signs p at the gateway's epoch, records it and sends it to to,
// in an op 27 of its own. dave-go can take in only one proposal per append
// batch with mls-go v1.6.0, and sending them one at a time also means every
// batch after the first in an epoch reaches a member whose commit waits.
func (g *fakeGateway) proposeLocked(p *group.Proposal, meta gatewayProposal, to []*fakeClient) {
	msg, ref, err := g.sender.propose(g.groupID, g.epoch, p)
	if err != nil {
		g.failf("%s: %v", meta.what, err)

		return
	}
	meta.msg, meta.ref, meta.to = msg, ref, to
	g.proposals = append(g.proposals, meta)
	for _, c := range to {
		c.inbox = append(c.inbox, proposalsMessage(buildProposalBatch(msg), meta.what))
	}
	g.eventf("epoch %d: propose %s to %v", g.epoch, meta.what, ids(to))
}

// revokeAddLocked revokes c's add if one is in flight.
func (g *fakeGateway) revokeAddLocked(c *fakeClient) {
	if i := slices.IndexFunc(g.proposals, func(p gatewayProposal) bool { return p.adds == c.id }); i >= 0 {
		g.revokeLocked(g.proposals[i])
	}
}

func (g *fakeGateway) revokeLocked(p gatewayProposal) {
	g.proposals = slices.DeleteFunc(g.proposals, func(q gatewayProposal) bool { return bytes.Equal(q.ref, p.ref) })
	for _, c := range p.to {
		if slices.Contains(g.clients, c) {
			c.inbox = append(c.inbox, proposalsMessage(buildRevokeBatch(p.ref), "revoke "+p.what))
		}
	}
	g.eventf("epoch %d: revoke %s", g.epoch, p.what)
}

// membersLocked returns the roster members whose leaves aren't stale, in
// connection order.
func (g *fakeGateway) membersLocked() []*fakeClient {
	var out []*fakeClient
	for _, c := range g.clients {
		if _, member := g.roster[c.id]; member && !c.stale {
			out = append(out, c)
		}
	}

	return out
}

func (g *fakeGateway) othersLocked(c *fakeClient) []*fakeClient {
	return slices.DeleteFunc(slices.Clone(g.clients), func(o *fakeClient) bool { return o == c })
}

func (g *fakeGateway) clientLocked(id godave.UserID) *fakeClient {
	for _, c := range g.clients {
		if c.id == id {
			return c
		}
	}

	return nil
}

func (g *fakeGateway) client(id godave.UserID) *fakeClient {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.clientLocked(id)
	if c == nil {
		g.t.Fatalf("%s is not on the call", id)
	}

	return c
}

// send queues what a client's session sent. A Session holds its send lock
// while its callbacks run, so this only queues and never calls a Session.
func (g *fakeGateway) send(id godave.UserID, m clientMessage) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c := g.clientLocked(id); c != nil {
		c.outbox = append(c.outbox, m)
	}
}

// eventf records what happened, for the history a failure prints. Must be
// called with g.mu held.
func (g *fakeGateway) eventf(format string, args ...any) {
	g.events = append(g.events, fmt.Sprintf(format, args...))
}

// failf fails the test from code that holds g.mu, where Fatalf would leave the
// lock held for the cleanup that prints the history.
func (g *fakeGateway) failf(format string, args ...any) {
	g.eventf("FAIL: "+format, args...)
	g.t.Errorf(format, args...)
}

// gatewayConn is the Callbacks a client's Session sends through.
type gatewayConn struct {
	gw *fakeGateway
	id godave.UserID
}

func (c gatewayConn) SendMLSKeyPackage(kp []byte) error {
	c.gw.send(c.id, clientMessage{op: opKeyPackage, payload: bytes.Clone(kp)})

	return nil
}

func (c gatewayConn) SendMLSCommitWelcome(commitWelcome []byte) error {
	c.gw.send(c.id, clientMessage{op: opCommitWelcome, payload: bytes.Clone(commitWelcome)})

	return nil
}

func (c gatewayConn) SendReadyForTransition(transitionID uint16) error {
	c.gw.send(c.id, clientMessage{op: opReadyForTransition, transitionID: transitionID})

	return nil
}

func (c gatewayConn) SendInvalidCommitWelcome(transitionID uint16) error {
	c.gw.send(c.id, clientMessage{op: opInvalidCommitWelcome, transitionID: transitionID})

	return nil
}

func selectProtocolAck(version uint16) serverMessage {
	return serverMessage{
		what:  fmt.Sprintf("op 4 version %d", version),
		apply: func(s *Session) { s.OnSelectProtocolAck(version) },
	}
}

func clientsConnect(users []godave.UserID) serverMessage {
	return serverMessage{
		what: fmt.Sprintf("op 11 %v", users),
		apply: func(s *Session) {
			for _, u := range users {
				s.AddUser(u)
			}
		},
	}
}

func clientDisconnect(user godave.UserID) serverMessage {
	return serverMessage{what: "op 13 " + string(user), apply: func(s *Session) { s.RemoveUser(user) }}
}

func prepareTransition(id, version uint16) serverMessage {
	return serverMessage{
		what:  fmt.Sprintf("op 21 transition %d version %d", id, version),
		apply: func(s *Session) { s.OnDavePrepareTransition(id, version) },
	}
}

func executeTransition(id uint16) serverMessage {
	return serverMessage{what: fmt.Sprintf("op 22 transition %d", id), apply: func(s *Session) { s.OnDaveExecuteTransition(id) }}
}

func externalSenderPackage(pkg []byte) serverMessage {
	return serverMessage{what: "op 25", apply: func(s *Session) { s.OnDaveMLSExternalSenderPackage(pkg) }}
}

func proposalsMessage(batch []byte, what string) serverMessage {
	return serverMessage{what: "op 27 " + what, apply: func(s *Session) { s.OnDaveMLSProposals(batch) }, proposals: true}
}

func announceCommit(id uint16, commit []byte) serverMessage {
	return serverMessage{
		what:  fmt.Sprintf("op 29 transition %d", id),
		apply: func(s *Session) { s.OnDaveMLSPrepareCommitTransition(id, commit) },
	}
}

func welcome(id uint16, w []byte) serverMessage {
	return serverMessage{what: fmt.Sprintf("op 30 transition %d", id), apply: func(s *Session) { s.OnDaveMLSWelcome(id, w) }}
}

var errUnsplittableCommitWelcome = errors.New("no commit, or commit and Welcome, in op 28 payload")

// splitCommitWelcome splits an op 28 payload into the commit, byte for byte as
// op 29 re-broadcasts it, and the bare Welcome op 30 forwards. mls-go reads
// neither a commit with bytes after it nor a Welcome's length from a prefix,
// so it looks for where a Welcome, which starts with the cipher suite (0x0002
// for DAVE), parses to the end.
func splitCommitWelcome(payload []byte) (commit, welcome []byte, err error) {
	if m, merr := framing.UnmarshalMLSMessage(payload); merr == nil && bytes.Equal(m.Marshal(), payload) {
		return payload, nil, nil
	}
	for k := 4; k+2 <= len(payload); k++ {
		if payload[k] != 0x00 || payload[k+1] != 0x02 {
			continue
		}
		w, werr := group.UnmarshalWelcome(payload[k:])
		if werr != nil || !bytes.Equal(w.Marshal(), payload[k:]) {
			continue
		}
		if m, merr := framing.UnmarshalMLSMessage(payload[:k]); merr == nil && bytes.Equal(m.Marshal(), payload[:k]) {
			return payload[:k], payload[k:], nil
		}
	}

	return nil, nil, errUnsplittableCommitWelcome
}

// parseCommit reads the group, epoch and proposal references the gateway
// inspects in a public commit.
func parseCommit(from godave.UserID, payload []byte) (commitInfo, error) {
	commit, w, err := splitCommitWelcome(payload)
	if err != nil {
		return commitInfo{}, err
	}
	msg, err := framing.UnmarshalMLSMessage(commit)
	if err != nil {
		return commitInfo{}, fmt.Errorf("parse commit: %w", err)
	}
	pub, ok := msg.AsPublic()
	if !ok || pub == nil {
		return commitInfo{}, errors.New("commit is not a public message")
	}
	data, ok := pub.Content.CommitData()
	if !ok {
		return commitInfo{}, errors.New("op 28 message is not a commit")
	}
	c, err := group.UnmarshalCommit(data)
	if err != nil {
		return commitInfo{}, fmt.Errorf("parse commit body: %w", err)
	}
	info := commitInfo{from: from, groupID: pub.Content.GroupID, epoch: pub.Content.Epoch, commit: commit, welcome: w}
	for _, por := range c.Proposals {
		if por.Proposal != nil {
			info.inline = true

			continue
		}
		info.refs = append(info.refs, por.ProposalRef)
	}

	return info, nil
}

// nextRoster applies a winning commit to base the way MLS does. Every remove
// blanks its leaf, then each add, in commit order, takes the lowest free leaf
// (RFC 9420 §12.3; mls-go sortProposalsByRFCOrder and RatchetTree.AddLeaf).
func nextRoster(base map[godave.UserID]uint32, cited []gatewayProposal) map[godave.UserID]uint32 {
	next := maps.Clone(base)
	for _, p := range cited {
		if !p.remove {
			continue
		}
		maps.DeleteFunc(next, func(_ godave.UserID, leaf uint32) bool { return leaf == p.removes })
	}
	for _, p := range cited {
		if p.adds == "" {
			continue
		}
		used := map[uint32]bool{}
		for _, leaf := range next {
			used[leaf] = true
		}
		var leaf uint32
		for used[leaf] {
			leaf++
		}
		next[p.adds] = leaf
	}

	return next
}

func sameRefs(a, b [][]byte) bool {
	key := func(refs [][]byte) []string {
		out := make([]string, 0, len(refs))
		for _, r := range refs {
			out = append(out, hex.EncodeToString(r))
		}
		slices.Sort(out)

		return out
	}

	return slices.Equal(key(a), key(b))
}

func formatRoster(roster map[godave.UserID]uint32) string {
	parts := make([]string, 0, len(roster))
	for id, leaf := range roster {
		parts = append(parts, fmt.Sprintf("%s@%d", id, leaf))
	}
	slices.Sort(parts)

	return "{" + strings.Join(parts, " ") + "}"
}

func ids(clients []*fakeClient) []godave.UserID {
	out := make([]godave.UserID, 0, len(clients))
	for _, c := range clients {
		out = append(out, c.id)
	}

	return out
}

// checkExecuted requires, for each transition executed since the last call,
// every member that got op 22 to be encrypting at the transition's epoch with
// keys the others hold. This catches a session that ends a transition with
// keys nobody else has even if a later restart heals the call.
func (g *fakeGateway) checkExecuted() {
	g.t.Helper()
	g.mu.Lock()
	var todo []executedTransition
	for i := range g.executed {
		if !g.executed[i].checked {
			g.executed[i].checked = true
			todo = append(todo, g.executed[i])
		}
	}
	g.mu.Unlock()
	for _, x := range todo {
		for _, id := range x.members {
			if st := g.client(id).s.State(); !st.Ready || st.EpochID != x.epoch {
				g.t.Errorf("after transition %d to epoch %d, %s is ready=%v at epoch %d", x.id, x.epoch, id, st.Ready, st.EpochID)
			}
		}
		g.requireKeysInStep(x.members)
	}
}

// requireKeysInStep has each of users encrypt a fresh frame on its own SSRC
// and every other one decrypt it back to the plaintext.
func (g *fakeGateway) requireKeysInStep(users []godave.UserID) {
	g.t.Helper()
	for _, from := range users {
		sender := g.client(from)
		g.mu.Lock()
		g.frames++
		plaintext := fmt.Appendf(nil, "frame %06d from %s", g.frames, from)
		g.mu.Unlock()
		out := make([]byte, sender.s.MaxEncryptedFrameSize(len(plaintext)))
		n, err := sender.s.Encrypt(sender.ssrc, plaintext, out)
		if err != nil {
			g.t.Errorf("%s cannot encrypt: %v", from, err)

			continue
		}
		if !frame.LooksLikeDAVEFrame(out[:n]) {
			g.t.Errorf("%s sent its frame in passthrough", from)

			continue
		}
		for _, to := range users {
			if to == from {
				continue
			}
			got := make([]byte, n)
			m, err := g.client(to).s.Decrypt(from, out[:n], got)
			if err != nil || !bytes.Equal(got[:m], plaintext) {
				g.t.Errorf("%s cannot decrypt a frame from %s: %v", to, from, err)
			}
		}
	}
}

// requireConverged stops the media pumps and requires the call to have
// settled into one group: no transition pending, every client in the roster
// with no key package waiting and no stale leaf, every session ready on
// protocol version 1 at the gateway's epoch with the same epoch
// authenticator, and every frame one encrypts decrypting at all the others.
func (g *fakeGateway) requireConverged() {
	g.t.Helper()
	g.media.halt()
	g.mu.Lock()
	epoch, users := g.epoch, ids(g.clients)
	var problems []string
	if g.transition != nil {
		problems = append(problems, fmt.Sprintf("transition %d still waits for %v", g.transition.id, slices.Sorted(maps.Keys(g.transition.waiting))))
	}
	for _, c := range g.clients {
		if _, member := g.roster[c.id]; !member || c.stale || c.kp != nil {
			problems = append(problems, fmt.Sprintf("%s is not a settled member (stale=%v, key package waiting=%v)", c.id, c.stale, c.kp != nil))
		}
	}
	g.mu.Unlock()
	for _, p := range problems {
		g.t.Error(p)
	}

	var authenticator []byte
	for i, id := range users {
		s := g.client(id).s
		st := s.State()
		if !st.Ready || st.ProtocolVersion != 1 || st.EpochID != epoch {
			g.t.Errorf("%s: ready=%v protocol=%d epoch=%d, want ready on protocol 1 at epoch %d", id, st.Ready, st.ProtocolVersion, st.EpochID, epoch)
		}
		a, err := s.EpochAuthenticator(g.t.Context())
		if err != nil {
			g.t.Errorf("%s epoch authenticator: %v", id, err)

			continue
		}
		if i == 0 {
			authenticator = a
		} else if !bytes.Equal(a, authenticator) {
			g.t.Errorf("%s has another epoch authenticator than %s", id, users[0])
		}
	}
	g.requireKeysInStep(users)
}

// requireWinner requires that the commit announced for epoch came from from
// and won by the selection rule, not by forceWinner.
func (g *fakeGateway) requireWinner(epoch uint64, from godave.UserID) {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, a := range g.announced {
		if a.epoch == epoch {
			if a.from != from || a.forced {
				g.t.Errorf("epoch %d: the winner is %s's commit %d (forced=%v), want %s's", epoch, a.from, a.nth, a.forced, from)
			}

			return
		}
	}
	g.t.Errorf("no commit for epoch %d won, want %s's", epoch, from)
}

// requireAnnounced requires that from's commit was forced to win epoch and
// that the selection rule would have refused it.
func (g *fakeGateway) requireAnnounced(epoch uint64, from godave.UserID) {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, a := range g.announced {
		if a.epoch == epoch {
			if a.from != from || !a.forced || !a.stale {
				g.t.Errorf("epoch %d: announced %s's commit %d (forced=%v, stale=%v), want a stale commit of %s's forced through",
					epoch, a.from, a.nth, a.forced, a.stale, from)
			}

			return
		}
	}
	g.t.Errorf("no commit for epoch %d was announced", epoch)
}

// requireRestartsOnly requires that only users sent op 31.
func (g *fakeGateway) requireRestartsOnly(users ...godave.UserID) {
	g.t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, id := range g.restarts {
		if !slices.Contains(users, id) {
			g.t.Errorf("%s started DAVE over with op 31", id)
		}
	}
}

// requireNoRestart requires that no session sent op 31.
func (g *fakeGateway) requireNoRestart() {
	g.t.Helper()
	g.requireRestartsOnly()
}

// requireReady requires id's session to be encrypting.
func (g *fakeGateway) requireReady(id godave.UserID) {
	g.t.Helper()
	if !g.client(id).s.State().Ready {
		g.t.Fatalf("%s is not encrypting", id)
	}
}

// mediaPumps run each client's audio while the handshake goes on. One
// goroutine per client encrypts a frame every mediaInterval and hands it to
// every other client, and another decrypts what it is handed, as disgo's send
// and UDP read loops call Encrypt and Decrypt next to the gateway read loop.
// The pumps ignore the results, since frames fail during a handshake by
// design.
type mediaPumps struct {
	wg      sync.WaitGroup
	mu      sync.Mutex
	in      map[godave.UserID]chan mediaFrame // buffered; a full channel drops the frame
	stopped map[godave.UserID]chan struct{}
}

type mediaFrame struct {
	from godave.UserID
	data []byte
}

func newMediaPumps() *mediaPumps {
	return &mediaPumps{in: map[godave.UserID]chan mediaFrame{}, stopped: map[godave.UserID]chan struct{}{}}
}

func (m *mediaPumps) start(id godave.UserID, ssrc uint32, s *Session) {
	in := make(chan mediaFrame, 64)
	stop := make(chan struct{})
	m.mu.Lock()
	m.in[id], m.stopped[id] = in, stop
	m.mu.Unlock()
	m.wg.Go(func() {
		tick := time.NewTicker(mediaInterval)
		defer tick.Stop()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			plaintext := fmt.Appendf(nil, "media %08d from %s", n, id)
			out := make([]byte, s.MaxEncryptedFrameSize(len(plaintext)))
			if k, err := s.Encrypt(ssrc, plaintext, out); err == nil {
				m.broadcast(id, out[:k])
			}
		}
	})
	m.wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			case f := <-in:
				out := make([]byte, s.MaxDecryptedFrameSize(f.from, len(f.data)))
				_, _ = s.Decrypt(f.from, f.data, out)
				_, _, _ = s.State(), s.Ready(), s.ShouldHoldFrames()
			}
		}
	})
}

func (m *mediaPumps) broadcast(from godave.UserID, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, in := range m.in {
		if id == from {
			continue
		}
		select {
		case in <- mediaFrame{from: from, data: bytes.Clone(data)}:
		default:
		}
	}
}

// stop stops id's pumps.
func (m *mediaPumps) stop(id godave.UserID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if stop, ok := m.stopped[id]; ok {
		close(stop)
		delete(m.stopped, id)
		delete(m.in, id)
	}
}

// halt stops every pump and waits for them.
func (m *mediaPumps) halt() {
	m.mu.Lock()
	for id, stop := range m.stopped {
		close(stop)
		delete(m.stopped, id)
		delete(m.in, id)
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// lockedBuffer collects every session's log lines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}
