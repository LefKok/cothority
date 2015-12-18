package main

import (
	//"github.com/dedis/cothority/lib/coconet"
	"encoding/json"
	"errors"
	"github.com/dedis/cothority/lib/bitcosi"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/sign"
)

/*
Implements a BitCoSI Prepare and a Cosi-round
*/

const RoundKeyPrepareType = "keyprepare"

type RoundKeyPrepare struct {
	*StampListener
	*sign.RoundException
}

func (round *RoundKeyPrepare) getblock(n int) (trb BitCoSi.KeyBlock, _ error) {
	if len(round.transaction_pool) > 0 {
		trlist := BitCoSi.NewTransactionList(round.transaction_pool, n)
		header := trb.NewHeader(trlist, round.Last_Key_Block, round.IP, round.PublicKey)
		trblock := trb.NewKeyBlock(trlist, header)
		round.transaction_pool = round.transaction_pool[trblock.TransactionList.TxCnt:]
		return trblock, nil
	} else {
		return *new(BitCoSi.KeyBlock), errors.New("no transaction available")
	}

}

func init() {
	sign.RegisterRoundFactory(RoundKeyPrepareType,
		func(node *sign.Node) sign.Round {
			return NewRoundKeyPrepare(node)
		})
}

func NewRoundKeyPrepare(node *sign.Node) *RoundKeyPrepare {
	dbg.Lvlf3("Making new roundprepare")
	round := &RoundKeyPrepare{}
	round.StampListener = NewStampListener(node.Name(), true)
	round.RoundException = sign.NewRoundException(node)
	round.Type = RoundKeyPrepareType
	return round
}

// Announcement is alrGeady defined in RoundCoSi

func (round *RoundKeyPrepare) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if round.IsRoot {

		round.trmux.Lock()
		//dbg.LLvl1("commit?")

		trblock, err := round.getblock(1)

		round.trmux.Unlock()

		if err != nil {
			dbg.LLvl1(err)
			return nil
		}
		round.TempKeyBlock = trblock

		//dbg.LLvl1("block is for root", trblock.HeaderHash)

		out.Com.MTRoot = hashid.HashId([]byte(trblock.MerkleRoot))
		//trblock.Print()

	}
	dbg.Lvl3("Commit roundprepare ")

	round.RoundException.Commitment(in, out)
	return nil
}

func (round *RoundKeyPrepare) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	if round.IsRoot {
		round.bmux.Lock()

		for _, o := range out {
			var err error
			o.Chm.Message, err = json.Marshal(round.TempKeyBlock)
			if err != nil {

				dbg.Fatal("Problem sending TrBlock")
			}
		}

		round.bmux.Unlock()

		//root starts roundcommit

	} else {
		if len(in.Chm.Message) > 0 { //can i poll this?
			if err := json.Unmarshal(in.Chm.Message, &round.TempKeyBlock); err != nil {

				dbg.Fatal("Problem parsing TrBlock")
			} else {

				//dbg.Lvl1("peer got the block", round.TempKeyBlock.HeaderHash)

			}

		}
	}

	round.RoundException.Challenge(in, out)
	return nil
}

func (round *RoundKeyPrepare) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	//fix so that it does note enter when there is no new block

	if !round.IsRoot {
		if round.verify_and_store(round.TempKeyBlock) {
			//round.Last_Block = round.TempBlock.HeaderHash //this should be done in round commit challenge phase
			dbg.LLvlf3("Block Accepted ")

		} else {
			dbg.LLvlf3("Block Rejected ", round.TempKeyBlock.HeaderHash)
			round.RoundException.RaiseException()
		}

	}
	round.RoundException.Response(in, out)

	//round.Tempflag = true
	//roots puts aggregated signature respose in a hash table in the stamplistener. The listener pools tha hash table in the round_commit challenge phase before continuing/// how can i make the other nodes to w8 in the challenge??

	return nil
}

func (round *RoundKeyPrepare) verify_and_store(block BitCoSi.KeyBlock) bool {

	return block.Header.ParentKey == round.Last_Key_Block && block.Header.MerkleRoot == block.Calculate_root(block.TransactionList) && block.HeaderHash == block.HeaderHash
}
func (round *RoundKeyPrepare) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {

	return nil
}
