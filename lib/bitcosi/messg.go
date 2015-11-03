package BitCoSi

import (
	"bytes"
	"encoding/json"
	"github.com/dedis/cothority/lib/app"
	"github.com/dedis/cothority/lib/bitcosi/blkparser"
	dbg "github.com/dedis/cothority/lib/debug_lvl"
	"github.com/dedis/cothority/lib/proof"
	"github.com/dedis/cothority/proto/sign"
)

// Default port for the conode-setup - the stamping-request port
// is at ```DefaultPort + 1```
var DefaultPort int = 2000

type MessageType int

type SeqNo byte

const (
	Error MessageType = iota
	TransactionAnnouncmentType
	BlockReplyType
	BlockRequestType
	BitCoSiClose
	BitCoSiExit
)

type TransactionAnnouncment struct {
	Val blkparser.Tx // Trasaction to be included in a block
}

// NOT: In order to decoe correctly the Proof, we need to the get the suite
// somehow. We could just simply add it as a field and not (un)marhsal it
// We'd just make sure that the suite is setup before unmarshaling.
type BlockReply struct {
	SuiteStr   string
	Timestamp  int64                          // The timestamp requested for the block to prove its ordering
	BlockLen   int                            // Length of Block
	Block      TrBlock                        // The Block including a number of transactions
	MerkleRoot []byte                         // root of the merkle tree
	PrfLen     int                            // Length of proof
	Prf        proof.Proof                    // Merkle proof of value
	SigBroad   sign.SignatureBroadcastMessage // All other elements necessary
}

type BitCoSiMessage struct {
	ReqNo SeqNo // Request sequence number
	// ErrorReply *ErrorReply // Generic error reply to any request
	Type MessageType
	Treq *TransactionAnnouncment
	Brep *BlockReply
}

func (sr *BlockReply) MarshalJSON() ([]byte, error) {
	type Alias BlockReply
	var b bytes.Buffer
	suite := app.GetSuite(sr.SuiteStr)
	if err := suite.Write(&b, sr.SigBroad); err != nil {
		dbg.Lvl1("encoding stampreply signature broadcast :", err)
		return nil, err
	}

	return json.Marshal(&struct {
		SigBroad []byte
		*Alias
	}{
		SigBroad: b.Bytes(),
		Alias:    (*Alias)(sr),
	})
}

func (sr *BlockReply) UnmarshalJSON(dataJSON []byte) error {
	type Alias BlockReply
	aux := &struct {
		SigBroad []byte
		*Alias
	}{
		Alias: (*Alias)(sr),
	}
	if err := json.Unmarshal(dataJSON, &aux); err != nil {
		return err
	}
	suite := app.GetSuite(sr.SuiteStr)
	sr.SigBroad = sign.SignatureBroadcastMessage{}
	if err := suite.Read(bytes.NewReader(aux.SigBroad), &sr.SigBroad); err != nil {
		dbg.Fatal("decoding signature broadcast : ", err)
		return err
	}
	return nil
}

func (Treq BlockReply) MarshalBinary() ([]byte, error) {
	dbg.Fatal("Don't want to do that")
	return nil, nil
}
func (Treq *BlockReply) UnmarshalBinary(data []byte) error {
	dbg.Fatal("Don't want to do that")
	return nil
}

func (tsm BitCoSiMessage) MarshalBinary() ([]byte, error) {
	dbg.Fatal("Don't want to do that")
	return nil, nil
}

func (sm *BitCoSiMessage) UnmarshalBinary(data []byte) error {
	dbg.Fatal("Don't want to do that")
	return nil
}
