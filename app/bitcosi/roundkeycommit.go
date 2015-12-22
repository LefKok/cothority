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

const RoundKeyCommitType = "keycommit"

type RoundKeyCommit struct {
	*StampListener
	*sign.RoundCosi
	ClientQueue []MustReplyMessage
}

func init() {
	sign.RegisterRoundFactory(RoundKeyCommitType,
		func(node *sign.Node) sign.Round {
			return NewRoundKeyCommit(node)
		})
}

func NewRoundKeyCommit(node *sign.Node) *RoundKeyCommit {
	dbg.Lvlf3("Making new roundcommit %+v", node)
	round := &RoundKeyCommit{}
	round.StampListener = NewStampListener(node.Name(), true)
	round.RoundCosi = sign.NewRoundCosi(node)
	round.Type = RoundKeyCommitType
	return round
}

func (round *RoundKeyCommit) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {

	if round.IsRoot {

		//TODO count exceptions and check signatures if everything is ok prepare for release else ????
		round.Mux.Lock()
		// messages read will now be processed
		round.Queue[KEY][READING], round.Queue[KEY][PROCESSING] = round.Queue[KEY][PROCESSING], round.Queue[KEY][READING]
		round.Queue[KEY][READING] = round.Queue[KEY][READING][:0]
		round.ClientQueue = make([]MustReplyMessage, len(round.Queue[KEY][PROCESSING]))

		// get data from s once to avoid refetching from structure
		round.Mux.Unlock()

		for i, q := range round.Queue[KEY][PROCESSING] {
			//queue[i] = q.Tsm.Treq.Val
			round.ClientQueue[i] = q
			dbg.LLvl1(q)

			round.ClientQueue[i].Block = round.TempKeyBlock.Block
		}

		round.bmux.Lock()
		round.keyblocks = append(round.keyblocks, round.TempKeyBlock)
		round.bmux.Unlock()

		out.Com.MTRoot = hashid.HashId([]byte(round.TempKeyBlock.HeaderHash))
		//trblock.Print()

	}

	round.RoundCosi.Commitment(in, out)
	return nil
}

func (round *RoundKeyCommit) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {

	dbg.LLvlf1(round.TempKeyBlock.HeaderHash)
	dbg.LLvlf1(round.Last_Key_Block)

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

func (round *RoundKeyCommit) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
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
		round.Last_Key_Block = round.TempKeyBlock.HeaderHash
	} else {
		round.RoundCosi.Response(in, out)
		round.Last_Key_Block = round.TempKeyBlock.HeaderHash
	}

	//roots puts aggregated signature respose in a hash table in the stamplistener. The listener pools tha hash table in the round_commit challenge phase before continuing/// how can i make the other nodes to w8 in the challenge??

	return nil
}

func (round *RoundKeyCommit) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
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
func (round *RoundKeyCommit) PutToClient(name string, data coconet.BinaryMarshaler) {
	err := round.Clients[name].PutData(data)
	if err == coconet.ErrClosed {
		round.Clients[name].Close()
		return
	}
	if err != nil && err != coconet.ErrNotEstablished {
		dbg.Lvl1("%p error putting to client: %v", round, err)
	}
}

func (round *RoundKeyCommit) verify_and_store(block BitCoSi.TrBlock) bool {
	dbg.LLvl1("block key parent is %+v", block.Header.ParentKey)
	dbg.LLvl1(block.Header.ParentKey)
	dbg.LLvl1("round parent key is %+v", round.Last_Key_Block)
	dbg.LLvl1("block merkle is %+v", block.Header.MerkleRoot)
	dbg.LLvl1("calculated merkle is %+v", block.Calculate_root(block.TransactionList))
	dbg.LLvl1("block hash is %+v", block.HeaderHash)
	dbg.LLvl1("calculated hash is  %+v", block.Hash(block.Header))

	return block.Header.ParentKey == round.Last_Key_Block && block.Header.MerkleRoot == block.Calculate_root(block.TransactionList) && block.HeaderHash == block.Hash(block.Header)
	//return false
}