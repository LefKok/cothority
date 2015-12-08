package main

import (
	//"github.com/dedis/cothority/lib/coconet"
	"encoding/json"
	"errors"
	"github.com/dedis/cothority/lib/bitcosi"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/sign"
	"time"
)

/*
Implements a BitCoSI Prepare and a Cosi-round
*/

const RoundPrepareType = "prepare"

type RoundPrepare struct {
	*StampListener
	*sign.RoundException
}

func (round *RoundPrepare) getblock(n int) (trb BitCoSi.TrBlock, _ error) {
	if len(round.transaction_pool) > 0 {
		trlist := BitCoSi.NewTransactionList(round.transaction_pool, n)
		header := trb.NewHeader(trlist, round.Last_Block, round.Last_Key_Block, round.IP, round.PublicKey)
		trblock := trb.NewTrBlock(trlist, header)
		round.transaction_pool = round.transaction_pool[trblock.TransactionList.TxCnt:]
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
	dbg.Lvlf3("Making new roundprepare")
	round := &RoundPrepare{}
	round.StampListener = NewStampListener(node.Name(), true)
	round.RoundException = sign.NewRoundException(node)
	round.Type = RoundPrepareType
	return round
}

// Announcement is alrGeady defined in RoundCoSi

func (round *RoundPrepare) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if round.IsRoot {

		round.trmux.Lock()
		//dbg.LLvl1("commit?")

		trblock, err := round.getblock(10000)

		round.trmux.Unlock()

		if err != nil {
			dbg.LLvl1(err)
			return nil
		}
		round.TempBlock = trblock

		dbg.LLvl1("block has transactions", trblock.TransactionList.TxCnt)

		out.Com.MTRoot = hashid.HashId([]byte(trblock.MerkleRoot))
		//trblock.Print()

	}
	dbg.Lvlf3("Commit roundprepare ")

	round.RoundException.Commitment(in, out)
	return nil
}

func (round *RoundPrepare) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.Tempflag.Lock()
	if round.IsRoot {
		round.bmux.Lock()

		for _, o := range out {
			var err error
			o.Chm.Message, err = json.Marshal(round.TempBlock)
			if err != nil {

				dbg.Fatal("Problem sending TrBlock")
			}
		}

		round.bmux.Unlock()

		//root starts roundcommit

	} else {
		if len(in.Chm.Message) > 0 { //can i poll this?
			if err := json.Unmarshal(in.Chm.Message, &round.TempBlock); err != nil {

				dbg.Fatal("Problem parsing TrBlock")
			} else {

				dbg.Lvl1("peer got the block", round.TempBlock.HeaderHash)

			}

		}
	}
	dbg.Lvlf3("Challenge roundprepare ")

	round.RoundException.Challenge(in, out)
	return nil
}

func (round *RoundPrepare) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	dbg.LLvl1("response?")
	//fix so that it does note enter when there is no new block

	if !round.IsRoot {
		var n time.Duration
		n = time.Duration(round.TempBlock.TransactionList.TxCnt) //n is in nsec sould be converted to microsec
		dbg.LLvl1(n * 100000)
		time.Sleep(n * 100000) //verification time od 100 microsec per transaction emulated
		//round.TempBlock.Print()
		if round.verify_and_store(round.TempBlock) {
			//round.Last_Block = round.TempBlock.HeaderHash //this should be done in round commit challenge phase
			dbg.LLvlf3("Block Accepted ")

		} else {
			dbg.LLvlf3("Block Rejected ", round.TempBlock.HeaderHash)
			round.RoundException.RaiseException()
		}

	}
	round.RoundException.Response(in, out)

	//round.Tempflag = true
	//roots puts aggregated signature respose in a hash table in the stamplistener. The listener pools tha hash table in the round_commit challenge phase before continuing/// how can i make the other nodes to w8 in the challenge??

	return nil
}

func (round *RoundPrepare) verify_and_store(block BitCoSi.TrBlock) bool {

	return block.Header.Parent == round.Last_Block && block.Header.ParentKey == round.Last_Key_Block && block.Header.MerkleRoot == block.Calculate_root(block.TransactionList) && block.HeaderHash == block.HeaderHash
}

func (round *RoundPrepare) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.RoundException.SignatureBroadcast(in, out)
	//round.proof_of_signing.SBm = in.SBm
	round.Tempflag.Unlock()
	return nil
}
