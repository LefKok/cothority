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
	round.StampListener = NewStampListener(node.Name(), true)
	round.RoundCosi = sign.NewRoundCosi(node)
	round.Type = RoundCommitType
	return round
}

func (round *RoundCommit) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {

	if round.IsRoot {

		out.Com.MTRoot = hashid.HashId([]byte(round.TempBlock.HeaderHash))
		//trblock.Print()

	}

	round.RoundCosi.Commitment(in, out)
	return nil
}

func (round *RoundCommit) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {

	dbg.LLvlf1(round.TempBlock.HeaderHash)
	dbg.LLvlf1(round.Last_Block)

	round.Tempflag.Lock()

	//if round.proof_of_signing.SBm.verify??

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
		round.Last_Block = round.TempBlock.HeaderHash

		round.RoundCosi.Response(in, out) //delete
	} else {
		round.Last_Block = round.TempBlock.HeaderHash

		round.RoundCosi.Response(in, out)
	}

	//roots puts aggregated signature respose in a hash table in the stamplistener. The listener pools tha hash table in the round_commit challenge phase before continuing/// how can i make the other nodes to w8 in the challenge??

	return nil
}

func (round *RoundCommit) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {

	//round.proof_of_signing.SBm.verify??

	round.Mux.Lock()
	// messages read will now be processed
	round.Queue[MICRO][READING], round.Queue[MICRO][PROCESSING] = round.Queue[MICRO][PROCESSING], round.Queue[MICRO][READING]
	round.Queue[MICRO][READING] = round.Queue[MICRO][READING][:0]
	round.ClientQueue = make([]MustReplyMessage, len(round.Queue[MICRO][PROCESSING]))

	// get data from s once to avoid refetching from structure
	round.Mux.Unlock()

	for i, q := range round.Queue[MICRO][PROCESSING] {
		//queue[i] = q.Tsm.Treq.Val
		round.ClientQueue[i] = q

		round.ClientQueue[i].Block = round.TempBlock.Block
	}

	round.bmux.Lock()
	round.blocks = append(round.blocks, round.TempBlock)
	round.bmux.Unlock()
	//trblock.Print()

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
		//dbg.Lvlf1("Sent signature response back to %+v", respMessg.Brep)
		round.bmux.Unlock()
	}
	round.Tempflag.Unlock()

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
	dbg.LLvl1("block parent is", block.Header.Parent)
	dbg.LLvl1("round parent is", round.Last_Block)
	dbg.LLvl1("block key parent is", block.Header.ParentKey)
	dbg.LLvl1("round parent key is", round.Last_Key_Block)
	dbg.LLvl1("block merkle is", block.Header.MerkleRoot)
	dbg.LLvl1("calculated merkle is", block.Calculate_root(block.TransactionList))
	dbg.LLvl1("block hash is", block.HeaderHash)
	dbg.LLvl1("calculated hash is", block.Hash(block.Header))

	return block.Header.Parent == round.Last_Block && block.Header.ParentKey == round.Last_Key_Block && block.Header.MerkleRoot == block.Calculate_root(block.TransactionList) && block.HeaderHash == block.Hash(block.Header)
	//return false
}
