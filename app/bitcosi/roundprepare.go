package main

import (
	"errors"
	"github.com/dedis/cothority/lib/bitcosi"
	"github.com/dedis/cothority/lib/coconet"
	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/sign"
)

/*
Implements a Stamper and a Cosi-round
*/

const RoundPrepareType = "prepare"

type RoundPrepare struct {
	*StampListener
	*conode.RoundStamper
	ClientQueue []ReplyMessage
}

func getblock(round *RoundPrepare, n int) (_ BitCoSi.TrBlock, _ error) {
	if len(round.transaction_pool) > 0 {

		trlist := BitCoSi.NewTransactionList(round.transaction_pool, n)
		header := BitCoSi.NewHeader(trlist, round.Last_Block, round.IP, round.PublicKey)
		trblock := BitCoSi.NewTrBlock(trlist, header)
		round.transaction_pool = round.transaction_pool[trblock.TransactionList.TxCnt:]
		round.Last_Block = trblock.HeaderHash
		return trblock, nil
	} else {
		return *new(BitCoSi.TrBlock), errors.New("no transaction available")
	}

}

func init() {
	sign.RegisterRoundFactory(RoundPrepareType,
		func(node *sign.Node) sign.Round {
			return NewRoundPrepare(node)
		})
}

func NewRoundPrepare(node *sign.Node) *RoundPrepare {
	dbg.Lvlf3("Making new roundcosistamper %+v", node)
	round := &RoundPrepare{}
	round.StampListener = NewStampListener(node.Name())
	round.RoundStamper = conode.NewRoundStamper(node)
	round.Type = RoundPrepareType
	return round
}

// Announcement is already defined in RoundStamper

func (round *RoundPrepare) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if round.IsRoot {

		round.trmux.Lock()
		trblock, err := getblock(round, 10)
		round.trmux.Unlock()
		if err != nil {
			return nil
		}
		round.bmux.Lock()
		round.blocks = append(round.blocks, trblock)
		round.bmux.Unlock()
		// get data from s once to avoid refetching from structure
		var q [][]byte = make([][]byte, 1)
		q[0] = []byte(trblock.HeaderHash)
		round.RoundStamper.QueueSet(q)
		round.Mux.Unlock()

	}
	round.RoundStamper.Commitment(in, out)
	return nil
}

func (round *RoundPrepare) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {

	round.RoundStamper.Challenge(in, out)
	return nil
}

func (round *RoundPrepare) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	round.RoundStamper.Response(in, out)
	return nil
}

func (round *RoundPrepare) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
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
func (round *RoundPrepare) PutToClient(name string, data coconet.BinaryMarshaler) {
	err := round.Clients[name].PutData(data)
	if err == coconet.ErrClosed {
		round.Clients[name].Close()
		return
	}
	if err != nil && err != coconet.ErrNotEstablished {
		dbg.Lvl1("%p error putting to client: %v", round, err)
	}
}
