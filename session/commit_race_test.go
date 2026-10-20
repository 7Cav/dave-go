package session

import (
	"testing"
	"time"

	"github.com/disgoorg/godave"
)

// proposalFraming is how the fake gateway puts the append proposals it queues
// for a member into op 27s. Every commit race test runs under each.
type proposalFraming struct {
	name    string
	batched bool
}

func proposalFramings() []proposalFraming {
	return []proposalFraming{
		{name: "an op 27 per proposal"},
		{name: "queued proposals in one op 27", batched: true},
	}
}

// gateway starts a fake gateway that frames proposals this way.
func (f proposalFraming) gateway(t *testing.T, opts ...gatewayOption) *fakeGateway {
	t.Helper()
	if f.batched {
		opts = append(opts, batchProposals())
	}

	return newFakeGateway(t, opts...)
}

// TestCommitRace_BatchWhileOwnCommitWaits sends a proposal batch to members
// whose commits for the previous batch are still on the wire, so only a
// commit over both batches can win.
func TestCommitRace_BatchWhileOwnCommitWaits(t *testing.T) {
	tests := []struct {
		name        string
		established bool
		order       []godave.UserID // order the gateway takes the held commits
		winner      godave.UserID
		// batchTo gets two proposals in one op 27 when the gateway batches.
		// Empty when the scenario never queues two for one member.
		batchTo godave.UserID
	}{
		{name: "first setup, our new commit wins", order: []godave.UserID{recorder, speaker}, winner: recorder, batchTo: joiner1},
		{name: "first setup, a peer's commit over both batches wins", order: []godave.UserID{speaker, recorder}, winner: speaker, batchTo: joiner1},
		{name: "established, our new commit wins", established: true, order: []godave.UserID{recorder, speaker}, winner: recorder},
		{name: "established, a peer's commit over both batches wins", established: true, order: []godave.UserID{speaker, recorder}, winner: speaker},
	}
	for _, f := range proposalFramings() {
		t.Run(f.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					gw := f.gateway(t)
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
					if f.batched && tt.batchTo != "" {
						gw.requireBatchOf(tt.batchTo, 2)
					}
				})
			}
		})
	}
}

// TestCommitRace_StaleOwnCommitAnnounced has the gateway announce the commit
// recorder sent before it committed again over a late batch. The protocol
// rules this out. Starting over with op 31 is acceptable; ending a transition
// with keys the others don't hold is not.
func TestCommitRace_StaleOwnCommitAnnounced(t *testing.T) {
	tests := []struct {
		name        string
		established bool
		batchTo     godave.UserID // as in TestCommitRace_BatchWhileOwnCommitWaits
	}{
		{name: "first setup", batchTo: joiner1},
		{name: "established", established: true},
	}
	for _, f := range proposalFramings() {
		t.Run(f.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					gw := f.gateway(t)
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
					if f.batched && tt.batchTo != "" {
						gw.requireBatchOf(tt.batchTo, 2)
					}
				})
			}
		})
	}
}

// TestCommitRace_BatchesQueuedBehindTransition sends two adds while every
// member's pending epoch waits for op 22, in two batches or in one.
// Recorder's pending epoch comes from its confirmed commit, speaker's from a
// peer's commit and joiner1's from a Welcome. Once the epoch executes, the
// next commit has to cover both adds.
func TestCommitRace_BatchesQueuedBehindTransition(t *testing.T) {
	for _, f := range proposalFramings() {
		t.Run(f.name, func(t *testing.T) {
			gw := f.gateway(t, proposeDuringTransition())
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
			if f.batched {
				gw.requireBatchOf(recorder, 2)
			}
		})
	}
}

// TestCommitRace_JoinRushDuringTransition has several members join an
// established call while a transition waits for op 23, as at the start of an
// op night. The gateway holds back their adds until the transition executes
// and then proposes all of them at once. Whichever commit over them wins, every
// member has to end at the next epoch with the same keys.
func TestCommitRace_JoinRushDuringTransition(t *testing.T) {
	rush := []godave.UserID{joiner2, joiner3, joiner4}
	tests := []struct {
		name   string
		order  []godave.UserID // order the gateway takes the held commits over the rush
		winner godave.UserID
	}{
		{name: "our commit wins", order: []godave.UserID{recorder, speaker, joiner1}, winner: recorder},
		{name: "a peer's commit wins", order: []godave.UserID{speaker, recorder, joiner1}, winner: speaker},
	}
	for _, f := range proposalFramings() {
		t.Run(f.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					gw := f.gateway(t)
					gw.establish(recorder, speaker)
					gw.connect(joiner1)
					gw.deliver() // joiner1 sends a key package
					gw.receive() // add(joiner1) goes out
					gw.deliver() // recorder and speaker commit over it
					gw.receive() // recorder's commit wins; the transition to epoch 2 waits for op 23
					for _, id := range rush {
						gw.connect(id)
					}
					gw.deliver()        // op 29 and op 30 handled; the rush sends key packages
					gw.receive(rush...) // the key packages arrive while the transition waits
					gw.holdCommits()
					gw.settle() // op 23s execute the transition, and the rush's adds go out
					gw.receiveCommits(tt.order...)
					gw.releaseCommits()
					gw.settle()

					gw.requireWinner(2, tt.winner)
					gw.requireNoRestart()
					gw.requireConverged()
					if f.batched {
						gw.requireBatchOf(recorder, len(rush))
					}
				})
			}
		})
	}
}

// TestCommitRace_RevokeWhileOwnCommitWaits revokes a proposal the waiting
// commits cover. Members must commit again over the proposals left, and
// commit nothing when none are left. A commit nobody can accept would restart
// DAVE when its watchdog fires. No member ever has two proposals queued at
// once, so batching changes nothing here.
func TestCommitRace_RevokeWhileOwnCommitWaits(t *testing.T) {
	for _, f := range proposalFramings() {
		t.Run(f.name, func(t *testing.T) {
			t.Run("a proposal is left", func(t *testing.T) {
				gw := f.gateway(t)
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
				gw := f.gateway(t, sessionRecoveryTimeout(recoveryTimeout))
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
				gw.resetRecoveryTimeout()
				gw.connect(joiner2)
				gw.settle()

				gw.requireWinner(1, recorder)
				gw.requireNoRestart()
				gw.requireConverged()
			})
		})
	}
}

// TestCommitRace_RevokeRevivesEarlierOwnCommit has the gateway revoke the add
// in the last batch that made the members commit again, before it takes their
// commits off the wire. Recorder's commit from just before that batch then
// cites every unrevoked proposal and wins by the protocol's rule. Recorder has
// to take up the group state that commit produced, since processing its own
// commit would fail and restart DAVE. Each add goes out on its own, so
// batching changes nothing here.
func TestCommitRace_RevokeRevivesEarlierOwnCommit(t *testing.T) {
	tests := []struct {
		name  string
		later []godave.UserID // connected one at a time after joiner1; the last one's add is revoked
	}{
		{name: "the first commit wins", later: []godave.UserID{joiner2}},
		{name: "a middle commit wins", later: []godave.UserID{joiner2, joiner3}},
	}
	for _, f := range proposalFramings() {
		t.Run(f.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					gw := f.gateway(t)
					gw.establish(recorder, speaker)
					gw.holdCommits()
					gw.connect(joiner1)
					gw.settle() // recorder and speaker commit over add(joiner1)
					for _, id := range tt.later {
						gw.connect(id)
						gw.settle() // and again over every add so far
					}
					gw.disconnect(tt.later[len(tt.later)-1])
					gw.settle() // and again without the revoked add
					gw.releaseCommits()
					gw.settle() // recorder's commit from before the revoked add arrives first and is valid again

					gw.requireWinner(1, recorder)
					gw.requireNoRestart()
					gw.requireConverged()
				})
			}
		})
	}
}

// TestCommitRace_RefusedBatchWhileOwnCommitWaits sends, while the members'
// commits wait, a batch every member refuses, then revokes it. The rollback
// for the refused batch brings back the waiting commit's proposals. They stay
// cached, so a commit over them wins once the gateway revokes the refused
// proposal. The refused proposal goes out on its own, so batching changes
// nothing here.
func TestCommitRace_RefusedBatchWhileOwnCommitWaits(t *testing.T) {
	for _, f := range proposalFramings() {
		t.Run(f.name, func(t *testing.T) {
			gw := f.gateway(t)
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
		})
	}
}

// TestCommitRace_RefusedProposalBetweenAdds puts a proposal DAVE refuses
// between two adds. Every member skips the refused one, takes in both adds
// and commits over them. Once the gateway revokes the refused proposal, a
// commit over the two adds wins, and every member has to resolve its refs.
func TestCommitRace_RefusedProposalBetweenAdds(t *testing.T) {
	tests := []struct {
		name   string
		order  []godave.UserID // order the gateway takes the held commits
		winner godave.UserID
	}{
		{name: "our commit wins", order: []godave.UserID{recorder, speaker}, winner: recorder},
		{name: "a peer's commit wins", order: []godave.UserID{speaker, recorder}, winner: speaker},
	}
	for _, f := range proposalFramings() {
		t.Run(f.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					gw := f.gateway(t)
					gw.establish(recorder, speaker)
					gw.holdCommits()
					gw.connect(joiner1)
					gw.connect(joiner2)
					gw.deliver()        // joiner1 and joiner2 send key packages
					gw.receive(joiner1) // add(joiner1) goes out
					gw.proposeRefused() // then a proposal every member refuses
					gw.receive(joiner2) // then add(joiner2)
					gw.settle()         // recorder and speaker commit over the two adds; the commits stay on the wire
					gw.revokeRefused()
					gw.receiveCommits(tt.order...)
					gw.releaseCommits()
					gw.settle()

					gw.requireWinner(1, tt.winner)
					gw.requireNoRestart()
					gw.requireConverged()
					if f.batched {
						gw.requireBatchOf(recorder, 3)
					}
				})
			}
		})
	}
}

// TestCommitRace_NextEpochBatchOvertakesAnnounce hands recorder the next
// epoch's first proposals ahead of the op 29 that confirms recorder's commit.
// A gateway that delivers in order can't do this. The proposals belong to the
// epoch that commit starts, so recorder holds them until op 22 and then
// commits over them.
func TestCommitRace_NextEpochBatchOvertakesAnnounce(t *testing.T) {
	tests := []struct {
		name string
		next []godave.UserID // their adds, at epoch 2, overtake op 29
	}{
		{name: "one add overtakes", next: []godave.UserID{joiner2}},
		{name: "two adds overtake", next: []godave.UserID{joiner2, joiner3}},
	}
	for _, f := range proposalFramings() {
		t.Run(f.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					gw := f.gateway(t, proposeDuringTransition())
					gw.establish(recorder, speaker)
					gw.holdCommits()
					gw.connect(joiner1)
					gw.settle() // recorder and speaker commit over add(joiner1)
					for _, id := range tt.next {
						gw.connect(id)
					}
					gw.deliver()                // the newcomers send key packages
					gw.receiveCommits(recorder) // recorder's commit wins; op 29 is queued
					gw.releaseCommits()
					gw.receive(tt.next...) // their adds at epoch 2, queued behind op 29
					gw.proposalsOvertake(recorder)
					gw.settle()

					gw.requireWinner(2, recorder)
					gw.requireNoRestart()
					gw.requireConverged()
					if f.batched && len(tt.next) > 1 {
						gw.requireBatchOf(recorder, len(tt.next))
					}
				})
			}
		})
	}
}
