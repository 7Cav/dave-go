package session

import (
	"testing"
	"time"

	"github.com/disgoorg/godave"
)

// TestCommitRace_BatchWhileOwnCommitWaits sends a proposal batch to members
// whose commits for the previous batch are still on the wire, so only a
// commit over both batches can win.
func TestCommitRace_BatchWhileOwnCommitWaits(t *testing.T) {
	tests := []struct {
		name        string
		established bool
		order       []godave.UserID // order the gateway takes the held commits
		winner      godave.UserID
	}{
		{name: "first setup, our new commit wins", order: []godave.UserID{recorder, speaker}, winner: recorder},
		{name: "first setup, a peer's commit over both batches wins", order: []godave.UserID{speaker, recorder}, winner: speaker},
		{name: "established, our new commit wins", established: true, order: []godave.UserID{recorder, speaker}, winner: recorder},
		{name: "established, a peer's commit over both batches wins", established: true, order: []godave.UserID{speaker, recorder}, winner: speaker},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newFakeGateway(t)
			var epoch uint64
			late := joiner1
			if tt.established {
				gw.establish(recorder, speaker)
				epoch, late = 1, joiner2
			}
			gw.holdCommits()
			if tt.established {
				gw.connect(joiner1) // add(joiner1) reaches recorder and speaker
			} else {
				gw.connect(recorder) // add(speaker) reaches recorder, add(recorder) reaches speaker
				gw.connect(speaker)
			}
			gw.settle() // recorder and speaker commit; the commits stay on the wire
			gw.connect(late)
			gw.settle() // the late add reaches both while their commits wait
			gw.receiveCommits(tt.order...)
			gw.releaseCommits()
			gw.settle()

			gw.requireWinner(epoch, tt.winner)
			gw.requireNoRestart()
			gw.requireConverged()
		})
	}
}

// TestCommitRace_StaleOwnCommitAnnounced has the gateway announce the commit
// recorder sent before it committed again over a late batch. The protocol
// rules this out. Starting over with op 31 is acceptable; ending a transition
// with keys the others don't hold is not.
func TestCommitRace_StaleOwnCommitAnnounced(t *testing.T) {
	for _, tt := range []struct {
		name        string
		established bool
	}{
		{name: "first setup"},
		{name: "established", established: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gw := newFakeGateway(t)
			var epoch uint64
			late := joiner1
			if tt.established {
				gw.establish(recorder, speaker)
				epoch, late = 1, joiner2
			}
			gw.holdCommits()
			if tt.established {
				gw.connect(joiner1)
			} else {
				gw.connect(recorder)
				gw.connect(speaker)
			}
			gw.settle()
			gw.connect(late)
			gw.settle()
			gw.forceWinner(func(c commitInfo) bool { return c.from == recorder && c.nth == 1 })
			gw.receiveCommits(recorder)
			gw.releaseCommits()
			gw.settle()

			gw.requireAnnounced(epoch, recorder)
			gw.requireRestartsOnly(recorder)
			gw.requireConverged()
		})
	}
}

// TestCommitRace_BatchesQueuedBehindTransition sends two batches while every
// member's pending epoch waits for op 22. Recorder's comes from its confirmed
// commit, speaker's from a peer's commit and joiner1's from a Welcome. Once
// the epoch executes, the next commit has to cover both batches.
func TestCommitRace_BatchesQueuedBehindTransition(t *testing.T) {
	gw := newFakeGateway(t, proposeDuringTransition())
	gw.establish(recorder, speaker)
	gw.holdCommits()
	gw.connect(joiner1)
	gw.settle()                 // recorder and speaker commit over add(joiner1)
	gw.receiveCommits(recorder) // recorder's wins; the transition is pending
	gw.releaseCommits()
	gw.connect(joiner2)
	gw.connect(joiner3)
	gw.deliver()                 // op 29 and op 30 handled; joiner2 and joiner3 send key packages
	gw.receive(joiner2, joiner3) // two adds at epoch 2 reach recorder, speaker and joiner1 before op 22
	gw.settle()

	gw.requireWinner(2, recorder)
	gw.requireNoRestart()
	gw.requireConverged()
}

// TestCommitRace_RevokeWhileOwnCommitWaits revokes a proposal the waiting
// commits cover. Members must commit again over the proposals left, and
// commit nothing when none are left. A commit nobody can accept would restart
// DAVE when its watchdog fires.
func TestCommitRace_RevokeWhileOwnCommitWaits(t *testing.T) {
	t.Run("a proposal is left", func(t *testing.T) {
		gw := newFakeGateway(t)
		gw.establish(recorder, speaker)
		gw.holdCommits()
		gw.connect(joiner1)
		gw.settle() // recorder and speaker commit over add(joiner1)
		gw.connect(joiner2)
		gw.settle() // and again over add(joiner2)
		gw.disconnect(joiner1)
		gw.settle() // the gateway revokes add(joiner1), leaving add(joiner2)
		gw.releaseCommits()
		gw.settle()

		gw.requireWinner(1, recorder)
		gw.requireNoRestart()
		gw.requireConverged()
	})
	t.Run("nothing is left", func(t *testing.T) {
		const recoveryTimeout = 500 * time.Millisecond
		gw := newFakeGateway(t, sessionRecoveryTimeout(recoveryTimeout))
		gw.establish(recorder, speaker)
		gw.holdCommits()
		gw.connect(joiner1)
		gw.settle()
		gw.disconnect(joiner1)
		gw.settle()
		gw.releaseCommits()
		gw.settle() // the commits over the revoked add arrive and lose
		time.Sleep(2 * recoveryTimeout)
		gw.settle()
		gw.requireNoRestart()
		gw.connect(joiner2)
		gw.settle()

		gw.requireWinner(1, recorder)
		gw.requireNoRestart()
		gw.requireConverged()
	})
}

// TestCommitRace_RevokeRevivesEarlierOwnCommit revokes the batch that made the
// members commit again before the gateway takes their first commits off the
// wire. The first commit then cites every unrevoked proposal, so it wins by
// the protocol's rule, and the session that sent it has to take up the group
// state it produced. Processing its own commit would fail and restart DAVE.
func TestCommitRace_RevokeRevivesEarlierOwnCommit(t *testing.T) {
	gw := newFakeGateway(t)
	gw.establish(recorder, speaker)
	gw.holdCommits()
	gw.connect(joiner1)
	gw.settle() // recorder and speaker commit over add(joiner1)
	gw.connect(joiner2)
	gw.settle() // and again over add(joiner2)
	gw.disconnect(joiner2)
	gw.settle() // and again over add(joiner1) alone
	gw.releaseCommits()
	gw.settle() // recorder's first commit arrives first and is valid again

	gw.requireWinner(1, recorder)
	gw.requireNoRestart()
	gw.requireConverged()
}

// TestCommitRace_RefusedBatchWhileOwnCommitWaits sends, while the members'
// commits wait, a batch every member refuses, then revokes it. The rollback
// for the refused batch brings back the proposals of the waiting commit, so
// a commit over them has to stay in flight for the revoke to let one win.
func TestCommitRace_RefusedBatchWhileOwnCommitWaits(t *testing.T) {
	gw := newFakeGateway(t)
	gw.establish(recorder, speaker)
	gw.holdCommits()
	gw.connect(joiner1)
	gw.settle() // recorder and speaker commit over add(joiner1)
	gw.proposeRefused()
	gw.settle()
	gw.receiveCommits(recorder, speaker) // none covers the refused proposal, so none wins
	gw.revokeRefused()
	gw.releaseCommits()
	gw.settle()

	gw.requireWinner(1, recorder)
	gw.requireNoRestart()
	gw.requireConverged()
}
