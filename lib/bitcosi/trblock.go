package BitCoSi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/dedis/cothority/lib/bitcosi/blkparser"
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

type Header struct {
	LeaderId   net.IP
	PublicKey  string
	MerkleRoot string
	ParentKey  string
	ParentTr   string
	nonce      uint32
}

type TrBlock struct {
	Block
}

func (*TrBlock) NewBlock(transactions []blkparser.Tx, n int, parent_tr string, parent_key string, IP net.IP, key string) (tr TrBlock) {
	trb := new(TrBlock)
	trb.Magic = [4]byte{0xF9, 0xBE, 0xB4, 0xD9}
	trb.TransactionList = NewTransactionList(transactions, n)
	trb.Header = trb.NewHeader(trb.TransactionList, parent_tr, parent_key, IP, key)
	trb.HeaderHash = trb.hash(fmt.Sprintf("%v", trb.Header))
	trb.BlockSize = 0
	return *trb
}

func (t *TrBlock) NewHeader(transactions TransactionList, parent_tr string, parent_key string, IP net.IP, key string) (hd Header) {
	hdr := new(Header)
	hdr.LeaderId = IP
	hdr.PublicKey = key
	hdr.ParentTr = parent_tr
	hdr.ParentKey = parent_key
	hdr.MerkleRoot = t.calculate_root(transactions)
	return *hdr
}

func (t *Block) calculate_root(transactions TransactionList) (res string) {
	var hashes []hashid.HashId

	for _, t := range transactions.Txs {
		temp, _ := hex.DecodeString(t.Hash)
		hashes = append(hashes, temp)
	}
	out, _ := proof.ProofTree(sha256.New, hashes)
	res = hex.EncodeToString(out)
	return
}

func (t *Block) hash(data string) (res string) {
	//change it to be more portable
	//data := fmt.Sprintf("%v", h)
	sha := sha256.New()
	sha.Write([]byte(data))
	hash := sha.Sum(nil)
	res = hex.EncodeToString(hash)
	return

}

func (trb *TrBlock) Print() {
	log.Println("Header:")
	log.Printf("Leader %v", trb.LeaderId)
	log.Printf("Pkey %v", trb.PublicKey)
	log.Printf("Parent_Tr %v", trb.ParentTr)
	log.Printf("Parent_Key %v", trb.ParentKey)
	log.Printf("Merkle %v", trb.MerkleRoot)
	trb.TransactionList.Print()

	log.Println("Rest:")
	log.Printf("Hash %v", trb.HeaderHash)

	return
}
