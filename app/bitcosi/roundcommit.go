package main

import (
	"github.com/dedis/cothority/lib/coconet"
	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/sign"
)

/*
Implements a Stamper and a Cosi-round
*/

const RoundCommitType = "commit"

type RoundCommit struct {
	*conode.StampListener
	*conode.RoundStamper
	ClientQueue []ReplyMessage
}

type ReplyMessage struct {
	Val   []byte
	To    string
	ReqNo byte
}

func init() {
	sign.RegisterRoundFactory(RoundCommitType,
		func(node *sign.Node) sign.Round {
			return NewRoundCommit(node)
		})
}

func NewRoundCommit(node *sign.Node) *RoundCommit {
	dbg.Lvlf3("Making new roundcosistamper %+v", node)
	round := &RoundCommit{}
	//round.StampListener = conode.NewStampListener(node.Name())
	round.RoundStamper = conode.NewRoundStamper(node)
	round.Type = RoundCommitType
	return round
}

// Announcement is already defined in RoundStamper

func (round *RoundCommit) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if round.IsRoot {

		round.Mux.Lock()
		// messages read will now be processed
		round.Queue[conode.READING], round.Queue[conode.PROCESSING] = round.Queue[conode.PROCESSING], round.Queue[conode.READING]
		round.Queue[conode.READING] = round.Queue[conode.READING][:0]
		round.ClientQueue = make([]ReplyMessage, len(round.Queue[conode.PROCESSING]))

		queue := make([][]byte, len(round.Queue[conode.PROCESSING]))
		for i, q := range round.Queue[conode.PROCESSING] {
			queue[i] = q.Tsm.Sreq.Val
			round.ClientQueue[i] = ReplyMessage{
				Val:   q.Tsm.Sreq.Val,
				To:    q.To,
				ReqNo: byte(q.Tsm.ReqNo),
			}
		}
		// get data from s once to avoid refetching from structure
		round.RoundStamper.QueueSet(queue)
		round.Mux.Unlock()

	}
	round.RoundStamper.Commitment(in, out)

	return nil

}

func (round *RoundCommit) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {

	round.RoundStamper.Challenge(in, out)
	return nil
}

func (round *RoundCommit) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	round.RoundStamper.Response(in, out)
	return nil
}

func (round *RoundCommit) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.RoundStamper.SignatureBroadcast(in, out)
	for i, msg := range round.ClientQueue {
		respMessg := &conode.TimeStampMessage{
			Type:  conode.StampSignatureType,
			ReqNo: conode.SeqNo(msg.ReqNo),
			Srep: &conode.StampSignature{
				SuiteStr:   round.Suite.String(),
				Timestamp:  round.Timestamp,
				MerkleRoot: round.MTRoot,
				Prf:        round.RoundStamper.CombProofs[i],
				Response:   in.SBm.R0_hat,
				Challenge:  in.SBm.C,
				AggCommit:  in.SBm.V0_hat,
				AggPublic:  in.SBm.X0_hat,
			}}
		round.PutToClient(msg.To, respMessg)
		dbg.Lvl2("Sent signature response back to client", msg.To)
	}
	return nil
}

// Send message to client given by name
func (round *RoundCommit) PutToClient(name string, data coconet.BinaryMarshaler) {
	err := round.Clients[name].PutData(data)
	if err == coconet.ErrClosed {
		round.Clients[name].Close()
		return
	}
	if err != nil && err != coconet.ErrNotEstablished {
		dbg.Lvl1("%p error putting to client: %v", round, err)
	}
}
