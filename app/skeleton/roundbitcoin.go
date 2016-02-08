package main

import (
	//"github.com/dedis/cothority/lib/coconet"
	"encoding/json"
	"errors"
	"github.com/dedis/cothority/lib/bitcosi"
	"github.com/dedis/cothority/lib/dbg"
	//"github.com/dedis/cothority/lib/hashid"
	"fmt"
	"github.com/dedis/cothority/lib/monitor"
	"github.com/dedis/cothority/lib/sign"
	"sync"
	"time"
)

/*
Implements a BitCoSI Prepare and a Cosi-round
*/

const RoundBitcoinType = "bitcoin"

type RoundBitcoin struct {
	*StampListener
	verified          bool
	verification_lock sync.Mutex
	measure           *monitor.Measure
	*sign.RoundStruct
	Cosi       *sign.CosiStruct
	SaveViewNo int
}

func (round *RoundBitcoin) getblock(n int) (trb BitCoSi.TrBlock, _ error) {
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
	sign.RegisterRoundFactory(RoundBitcoinType,
		func(node *sign.Node) sign.Round {
			return NewRoundBitcoin(node)
		})
}

func NewRoundBitcoin(node *sign.Node) *RoundBitcoin {
	dbg.Lvl3("Making new roundprepare")
	round := &RoundBitcoin{}
	round.RoundStruct = sign.NewRoundStruct(node, sign.RoundCosiType)
	round.StampListener = NewStampListener(node.Name(), true)
	round.Type = RoundBitcoinType
	round.verified = false
	round.verification_lock = sync.Mutex{}
	return round
}

func (round *RoundBitcoin) CheckChildren() {
	c := round.Node.Children(round.Node.ViewNo)
	if len(c) != len(round.Cosi.Children) {
		dbg.Print("Children in cosi and node are different")
		dbg.Printf("round.Cosi: %+v", round.Cosi)
		dbg.Printf("Node.Children: %+v", round.Node.Children(round.Node.ViewNo))
		dbg.Print("viewNbr:", round.SaveViewNo, "Node.ViewNo:", round.Node.ViewNo)
		//	dbg.PrintStack()
	}
}

func (round *RoundBitcoin) Announcement(viewNbr, roundNbr int, in *sign.SigningMessage, out []*sign.SigningMessage) error {
	if round.IsRoot {
		round.measure = monitor.NewMeasure("roundprop")
	}
	if err := round.Node.TryFailure(round.Node.ViewNo, roundNbr); err != nil {
		return err
	}

	round.Cosi = sign.NewCosi(round.Node, viewNbr, roundNbr, in.Am)
	round.SaveViewNo = round.Node.ViewNo
	round.CheckChildren()

	round.Cosi.Msg = in.Am.Message
	// Inform all children of announcement - just copy the one that came in
	for i := range out {
		*out[i].Am = *in.Am
	}
	return nil
}

func (round *RoundBitcoin) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if round.IsRoot {

		round.trmux.Lock()

		trblock, err := round.getblock(2200)
		//round.StampListener.time = time.Now()

		round.trmux.Unlock()

		if err != nil {
			dbg.LLvl1(err)
			return nil
		}
		round.TempBlock = trblock

		dbg.Lvl4("block has transactions", trblock.TransactionList.TxCnt)
		//MRoot signed as proof-fo-acceptance
		//out.Com.MTRoot = hashid.HashId([]byte(trblock.MerkleRoot))
		//trblock.Print()

	}
	dbg.Lvl3("Commit roundprepare ")

	cosi := round.Cosi
	cosi.Commits = in

	return nil
}

func (round *RoundBitcoin) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {

	cosi := round.Cosi

	round.Tempflag.Lock()
	if round.IsRoot {
		round.bmux.Lock()

		for _, o := range out {
			var err error
			o.Chm.Message, err = json.Marshal(round.TempBlock)
			dbg.Lvl5(len(o.Chm.Message))
			if err != nil {

				dbg.Fatal("Problem sending TrBlock")
			}
		}

		round.bmux.Unlock()

		//root starts roundcommit

	} else {
		if len(in.Chm.Message) > 0 {
			if err := json.Unmarshal(in.Chm.Message, &round.TempBlock); err != nil {

				dbg.Fatal("Problem parsing TrBlock")
			} else {

				dbg.Lvl3("peer got the block", round.TempBlock.HeaderHash)

			}

			//round.verification_lock.Lock()
			//start concurrent verification of the block
			round.verify_and_store(round.TempBlock, len(in.Chm.Message))
			round.bmux.Lock()
			//the other threads forwards the message down he tree
			for _, o := range out {
				var err error
				o.Chm.Message, err = json.Marshal(round.TempBlock)
				if err != nil {

					dbg.Fatal("Problem sending TrBlock")
				}
			}

			round.bmux.Unlock()

		}
	}
	dbg.Lvl3("Challenge roundprepare ")
	round.CheckChildren()
	if len(cosi.Children) != len(out) {
		return fmt.Errorf("Children (%d) and output (%d) are of different length. Should be %d / %d",
			len(cosi.Children), len(out), len(round.Node.Children(round.Node.ViewNo)),
			round.Node.ViewNo)
	}
	var i = 0
	for name, _ := range cosi.Children {
		out[i].Chm.C = in.Chm.C
		out[i].To = name
		i++
	}

	return nil
}

func (round *RoundBitcoin) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	//dbg.Lvl1("got in response", round.NameL)

	if !round.IsRoot {
		//wait for verification thread to finish
		//round.verification_lock.Lock()

		if round.verified {
			round.Last_Block = round.TempBlock.HeaderHash

			//dbg.LLvl1("Block Accepted ")

		} else {
			dbg.LLvlf3("Block Rejected ", round.TempBlock.HeaderHash)
			//add yourself into the exception list because you vote no
		}
		//round.verification_lock.Unlock()

	}

	//round.Tempflag = true
	//roots puts aggregated signature respose in a hash table in the stamplistener. The listener pools tha hash table in the round_commit challenge phase before continuing/// how can i make the other nodes to w8 in the challenge??
	if round.IsRoot {
		round.Last_Block = round.TempBlock.HeaderHash
		round.measure.Measure()
		dbg.Lvl1("finished  - took", round.measure.WallTime)
	}
	return nil
}

func (round *RoundBitcoin) verify_and_store(block BitCoSi.TrBlock, s int) error {
	//We measure the average block verification delays is 174ms for an average block of 500kB.
	//To simulate the verification cost of bigger blocks we multipley 174ms times the size/500*1024
	var n time.Duration
	n = time.Duration(s / (500 * 1024))
	time.Sleep(150 * time.Millisecond * n) //verification of 174ms per 500KB simulated
	//round.TempBlock.Print()
	//rerun actual verification for the block header
	round.verified = block.Header.Parent == round.Last_Block && block.Header.MerkleRoot == block.Calculate_root(block.TransactionList) && block.HeaderHash == block.Hash(block.Header)
	//round.verification_lock.Unlock()
	return nil
}

func (round *RoundBitcoin) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.proof_of_signing.SBm = in.SBm
	for i := range out {
		*out[i].SBm = *in.SBm
	}
	round.Tempflag.Unlock()
	return nil
}
