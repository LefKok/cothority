package main

import (
	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/sign"
)

/*
Implements a Stamper and a Cosi-round
*/

const RoundKeyType = "key"

type RoundKey struct {
	*sign.RoundCosi
	*sign.RoundStruct
	*conode.RoundStamper
	peer *conode.Peer
}

func RegisterRoundKey(peer *conode.Peer) {
	sign.RegisterRoundFactory(RoundKeyType,
		func(node *sign.Node) sign.Round {
			return NewRoundKey(peer)
		})
}

func NewRoundKey(peer *conode.Peer) sign.Round {
	dbg.Print("Making new roundkey", peer)
	round := &RoundKey{}
	round.RoundStamper = conode.NewRoundStamper(peer)
	round.RoundCosi = sign.NewRoundCosi(peer.Node)
	round.RoundStruct = sign.NewRoundStruct(peer.Node)
	round.peer = peer
	return round
}

func (round *RoundKey) Announcement(viewNbr, roundNbr int, in *sign.SigningMessage,
	out []*sign.SigningMessage) error {
	dbg.LLvl3("Starting new announcement")
	round.RoundStamper.Announcement(viewNbr, roundNbr, in, out)
	round.RoundCosi.Announcement(viewNbr, roundNbr, in, out)
	round.RoundStruct.SetRoundType(RoundKeyType, out)
	return nil
}

func (round *RoundKey) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	round.peer.Mux.Lock()
	// get data from s once to avoid refetching from structure
	round.RoundStamper.QueueSet(round.peer.Queue)
	round.peer.Mux.Unlock()

	round.RoundStamper.Commitment(in, out)
	round.RoundCosi.Commitment(in, out)
	return nil
}

func (round *RoundKey) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.RoundStamper.Challenge(in, out)
	round.RoundCosi.Challenge(in, out)
	return nil
}

func (round *RoundKey) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	round.RoundStamper.Response(in, out)
	round.RoundCosi.Response(in, out)
	return nil
}

func (round *RoundKey) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.RoundCosi.SignatureBroadcast(in, out)
	round.RoundStamper.Proof = round.RoundCosi.Cosi.Proof
	round.RoundStamper.MTRoot = round.RoundCosi.Cosi.MTRoot
	round.RoundStamper.SignatureBroadcast(in, out)
	return nil
}
