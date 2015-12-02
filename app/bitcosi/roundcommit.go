package main

import (
	//	"errors"
	"github.com/dedis/cothority/lib/bitcosi"
	"github.com/dedis/cothority/lib/coconet"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/sign"
)

/*
Implements a BitCoSI Prepare and a Cosi-round
*/

const RoundCommitType = "commit"

type RoundCommit struct {
	*StampListener
	*sign.RoundCosi
	ClientQueue []MustReplyMessage
}

func init() {
	sign.RegisterRoundFactory(RoundCommitType,
		func(node *sign.Node) sign.Round {
			return NewRoundCommit(node)
		})
}

func NewRoundCommit(node *sign.Node) *RoundCommit {
	dbg.Lvlf3("Making new roundcommit %+v", node)
	round := &RoundCommit{}
	round.StampListener = NewStampListener(node.Name())
	round.RoundCosi = sign.NewRoundCosi(node)
	round.Type = RoundCommitType
	return round
}

func (round *RoundCommit) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {

	if round.IsRoot {

		//TODO count exceptions and check signatures if everything is ok prepare for release else ????
		round.Mux.Lock()
		// messages read will now be processed
		round.Queue[READING], round.Queue[PROCESSING] = round.Queue[PROCESSING], round.Queue[READING]
		round.Queue[READING] = round.Queue[READING][:0]
		round.ClientQueue = make([]MustReplyMessage, len(round.Queue[PROCESSING]))

		// get data from s once to avoid refetching from structure
		round.Mux.Unlock()

		dbg.LLvl1("ROUND COMMIT! commit?")

		for i, q := range round.Queue[PROCESSING] {
			//queue[i] = q.Tsm.Treq.Val
			round.ClientQueue[i] = q
			dbg.LLvl1(q)

			round.ClientQueue[i].Block = round.TempBlock
		}

		round.bmux.Lock()
		round.blocks = append(round.blocks, round.TempBlock)
		round.bmux.Unlock()

		out.Com.MTRoot = hashid.HashId([]byte(round.TempBlock.HeaderHash))
		//trblock.Print()

	}

	round.RoundCosi.Commitment(in, out)
	return nil
}

func (round *RoundCommit) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {

	dbg.LLvlf1(round.TempBlock.HeaderHash)
	dbg.LLvlf1(round.Last_Block)

	//should sent the proof of acceptance of the temp_block and peers should recieve it
	/*if round.IsRoot {
		round.bmux.Lock()
		if len(round.blocks) > 0 {
			for _, o := range out {
				var err error
				o.Chm.Message, err = json.Marshal(round.blocks[len(round.blocks)-1])
				if err != nil {

					dbg.Fatal("Problem sending TrBlock")
				}
			}
		}
		round.bmux.Unlock()

		//root starts roundcommit

	} else {
		if len(in.Chm.Message) > 0 { //can i poll this?
			if err := json.Unmarshal(in.Chm.Message, &round.TempBlock); err != nil {

				dbg.Fatal("Problem parsing TrBlock")
			}
			dbg.Lvl1("peer got the block")
			//block.Print()
		}
	}*/
	round.RoundCosi.Challenge(in, out)
	return nil
}

func (round *RoundCommit) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	dbg.LLvl1("response in commit?")
	//fix so that it does note enter when there is no new block
	//check the proof of acceptance and sign.

	if !round.IsRoot {
		/*if round.verify_and_store(round.TempBlock) {
			round.Last_Block = round.TempBlock.HeaderHash //this should be done in round commit challenge phase
			dbg.LLvlf3("Block Accepted %+v", round.TempBlock.HeaderHash)
			round.RoundCosi.Response(in, out)

		} else {

			dbg.LLvlf3("Block Rejected %+v", round.TempBlock.HeaderHash)
			round.Cosi.R_hat = round.Suite.Secret().Zero()
			round.RoundCosi.Response(in, out)
			dbg.LLvl3(out.Rm.ExceptionX_hat)
			out.Rm.ExceptionX_hat.Add(out.Rm.ExceptionX_hat, round.Cosi.PubKey)
			out.Rm.ExceptionV_hat.Add(out.Rm.ExceptionV_hat, round.Cosi.Log.V_hat)
		}*/
		round.RoundCosi.Response(in, out) //delete
		round.Last_Block = round.TempBlock.HeaderHash
	} else {
		round.RoundCosi.Response(in, out)
		round.Last_Block = round.TempBlock.HeaderHash
	}

	//roots puts aggregated signature respose in a hash table in the stamplistener. The listener pools tha hash table in the round_commit challenge phase before continuing/// how can i make the other nodes to w8 in the challenge??

	return nil
}

func (round *RoundCommit) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.RoundCosi.SignatureBroadcast(in, out)

	for _, msg := range round.ClientQueue {
		round.bmux.Lock()
		dbg.LLvl1(msg.Block.HeaderHash)
		respMessg := &BitCoSi.BitCoSiMessage{
			Type:  BitCoSi.BlockReplyType,
			ReqNo: msg.Tsm.ReqNo,
			Brep: &BitCoSi.BlockReply{
				SuiteStr:   suite.String(),
				Block:      msg.Block,
				MerkleRoot: round.RoundCosi.Cosi.MTRoot,
				Prf:        round.RoundCosi.Cosi.Proof,
				Response:   in.SBm.R0_hat,
				Challenge:  in.SBm.C,
				AggCommit:  in.SBm.V0_hat,
				AggPublic:  in.SBm.X0_hat}}
		round.PutToClient(msg.To, respMessg)
		dbg.Lvlf1("Sent signature response back to %+v", respMessg.Brep)
		round.bmux.Unlock()
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

func (round *RoundCommit) verify_and_store(block BitCoSi.TrBlock) bool {

	//return block.Header.Parent == round.Last_Block && block.Header.MerkleRoot == block.Calculate_root(block.TransactionList) && block.HeaderHash == block.Hash(block.Header)
	return false
}
