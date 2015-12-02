package BitCoSi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/proof"
	"log"
	"net"
)

type Block struct {
	Magic      [4]byte
	BlockSize  uint32
	HeaderHash string
	Header
	TransactionList
}

type TrBlock struct {
	Block
}

type Header struct {
	LeaderId   net.IP
	PublicKey  string
	MerkleRoot string
	Parent     string
	ParentKey  string
}

func (*TrBlock) NewTrBlock(transactions TransactionList, header Header) (tr TrBlock) {
	trb := new(TrBlock)
	trb.Magic = [4]byte{0xF9, 0xBE, 0xB4, 0xD9}
	trb.HeaderHash = trb.Hash(header)
	trb.TransactionList = transactions
	trb.BlockSize = 0
	trb.Header = header
	return *trb
}

func (t *TrBlock) NewHeader(transactions TransactionList, parent string, parentkey string, IP net.IP, key string) (hd Header) {
	hdr := new(Header)
	hdr.LeaderId = IP
	hdr.PublicKey = key
	hdr.Parent = parent
	hdr.ParentKey = parentkey
	hdr.MerkleRoot = t.Calculate_root(transactions)
	return *hdr
}

func (trb *Block) Calculate_root(transactions TransactionList) (res string) {
	var hashes []hashid.HashId

	for _, t := range transactions.Txs {
		temp, _ := hex.DecodeString(t.Hash)
		hashes = append(hashes, temp)
	}
	out, _ := proof.ProofTree(sha256.New, hashes)
	res = hex.EncodeToString(out)
	return
}

func (trb *Block) Hash(h Header) (res string) {
	//change it to be more portable
	data := fmt.Sprintf("%v", h)
	sha := sha256.New()
	sha.Write([]byte(data))
	hash := sha.Sum(nil)
	res = hex.EncodeToString(hash)
	return

}

func (trb *TrBlock) Print() {
	log.Println("Header:")
	log.Printf("Leader %v", trb.LeaderId)
	//log.Printf("Pkey %v", trb.PublicKey)
	log.Printf("Parent %v", trb.Parent)
	log.Printf("ParentKey %v", trb.ParentKey)
	log.Printf("Merkle %v", trb.MerkleRoot)
	//trb.TransactionList.Print()
	//log.Println("Rest:")
	log.Printf("Hash %v", trb.HeaderHash)

	return
}
