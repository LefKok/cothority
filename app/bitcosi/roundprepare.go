package main

import (
	"encoding/json"
	"errors"
	"github.com/dedis/cothority/lib/bitcosi"
	"github.com/dedis/cothority/lib/coconet"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/sign"
)

/*
Implements a BitCoSI Prepare and a Cosi-round
*/

const RoundPrepareType = "prepare"

type RoundPrepare struct {
	*StampListener
	*sign.RoundCosi
	ClientQueue   []MustReplyMessage
	TempBlock     BitCoSi.TrBlock
	LastBlockHash string
}

func (round *RoundPrepare) getblock(n int) (trb BitCoSi.TrBlock, _ error) {
	if len(round.transaction_pool) > 0 {
		trlist := BitCoSi.NewTransactionList(round.transaction_pool, n)
		header := trb.NewHeader(trlist, round.Last_Block, round.IP, round.PublicKey)
		trblock := trb.NewTrBlock(trlist, header)
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
	round.RoundCosi = sign.NewRoundCosi(node)
	round.Type = RoundPrepareType
	round.TempBlock = BitCoSi.TrBlock{}
	round.Last_Block = "0"
	return round
}

// Announcement is already defined in RoundCoSi

func (round *RoundPrepare) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if round.IsRoot {

		round.Mux.Lock()
		// messages read will now be processed
		round.Queue[READING], round.Queue[PROCESSING] = round.Queue[PROCESSING], round.Queue[READING]
		round.Queue[READING] = round.Queue[READING][:0]
		round.ClientQueue = make([]MustReplyMessage, len(round.Queue[PROCESSING]))

		// get data from s once to avoid refetching from structure
		round.Mux.Unlock()

		round.trmux.Lock()
		dbg.LLvl1("commit?")

		trblock, err := round.getblock(10)
		round.trmux.Unlock()
		if err != nil {
			dbg.LLvl1(err)
			return nil
		}

		trblock.Print()

		for i, q := range round.Queue[PROCESSING] {
			//queue[i] = q.Tsm.Treq.Val
			round.ClientQueue[i] = q
			round.ClientQueue[i].Block = trblock
		}

		round.bmux.Lock()
		round.blocks = append(round.blocks, trblock)
		round.bmux.Unlock()

		out.Com.MTRoot = hashid.HashId([]byte(trblock.HeaderHash))
		//trblock.Print()

	}

	round.RoundCosi.Commitment(in, out)
	return nil
}

func (round *RoundPrepare) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	if round.IsRoot {
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
	}

	round.RoundCosi.Challenge(in, out)
	return nil
}

func (round *RoundPrepare) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	dbg.LLvl1("response?")
	//fix so that it does note enter when there is no new block

	if !round.IsRoot {
		if round.verify_and_store(round.TempBlock) {
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
		}

	} else {
		round.RoundCosi.Response(in, out)
	}

	//roots puts aggregated signature respose in a hash table in the stamplistener. The listener pools tha hash table in the round_commit challenge phase before continuing/// how can i make the other nodes to w8 in the challenge??

	return nil
}

//should go to round_commit

func (round *RoundPrepare) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.RoundCosi.SignatureBroadcast(in, out)

	for _, msg := range round.ClientQueue {
		round.bmux.Lock()
		msg.Block.Print()

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

func (round *RoundPrepare) verify_and_store(block BitCoSi.TrBlock) bool {

	//return block.Header.Parent == round.Last_Block && block.Header.MerkleRoot == block.Calculate_root(block.TransactionList) && block.HeaderHash == block.Hash(block.Header)
	return false
}
