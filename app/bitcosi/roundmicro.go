package main

import (
	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/sign"
)

/*
Implements a Stamper and a Cosi-round
*/

const RoundMicroType = "micro"

type RoundMicro struct {
	*sign.RoundCosi
	*sign.RoundStruct
	Proof  []hashid.HashId
	MTRoot hashid.HashId
	peer   *conode.Peer
}

func RegisterRoundMicro(peer *conode.Peer) {
	sign.RegisterRoundFactory(RoundMicroType,
		func(node *sign.Node) sign.Round {
			return NewRoundMicro(peer)
		})
}

func NewRoundMicro(peer *conode.Peer) sign.Round {
	dbg.Print("Making new roundmicro", peer)
	round := &RoundMicro{}
	round.RoundCosi = sign.NewRoundCosi(peer.Node)
	round.RoundStruct = sign.NewRoundStruct(peer.Node)
	round.peer = peer
	return round
}

func (round *RoundMicro) Announcement(viewNbr, roundNbr int, in *sign.SigningMessage,
	out []*sign.SigningMessage) error {
	dbg.LLvl3("Starting new announcement")
	round.RoundCosi.Announcement(viewNbr, roundNbr, in, out)
	round.RoundStruct.SetRoundType(RoundMicroType, out)
	return nil
}

func (round *RoundMicro) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	//out.Com.MTRoot =
	round.RoundCosi.Commitment(in, out)
	return nil
}

func (round *RoundMicro) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.RoundCosi.Challenge(in, out)
	return nil
}

func (round *RoundMicro) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	round.RoundCosi.Response(in, out)
	return nil
}

func (round *RoundMicro) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	round.RoundCosi.SignatureBroadcast(in, out)
	round.Proof = round.RoundCosi.Cosi.Proof
	round.MTRoot = round.RoundCosi.Cosi.MTRoot
	return nil
}
