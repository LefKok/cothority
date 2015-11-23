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

type KeyBlock struct {
	Magic      [4]byte
	BlockSize  uint32
	HeaderHash string
	KeyHeader
	TransactionList
}

type KeyHeader struct {
	LeaderId   net.IP
	PublicKey  string
	MerkleRoot string
	Parent     string
	nonce      uint32
}

func (*KeyBlock) NewBlock(transactions []blkparser.Tx, n int, parent string, IP net.IP, k string) (keyb KeyBlock) {
	key := new(KeyBlock)
	key.Magic = [4]byte{0xF9, 0xBE, 0xB4, 0xD9}
	key.TransactionList = NewTransactionList(transactions, n)
	key.KeyHeader = key.NewHeader(key.TransactionList, parent, IP, k)
	key.HeaderHash = key.hash(key.KeyHeader)
	key.BlockSize = 0
	return *key
}

func (kb *KeyBlock) NewHeader(transactions TransactionList, parent string, IP net.IP, key string) (hd KeyHeader) {
	hdr := new(KeyHeader)
	hdr.LeaderId = IP
	hdr.PublicKey = key
	hdr.Parent = parent
	hdr.nonce = 3
	hdr.MerkleRoot = kb.calculate_root(transactions)
	return *hdr
}

func (t *KeyBlock) calculate_root(transactions TransactionList) (res string) {
	var hashes []hashid.HashId

	for _, t := range transactions.Txs {
		temp, _ := hex.DecodeString(t.Hash)
		hashes = append(hashes, temp)
	}
	out, _ := proof.ProofTree(sha256.New, hashes)
	res = hex.EncodeToString(out)
	return
}

func (t *KeyBlock) hash(h KeyHeader) (res string) {
	//change it to be more portable
	data := fmt.Sprintf("%v", h)
	sha := sha256.New()
	sha.Write([]byte(data))
	hash := sha.Sum(nil)
	res = hex.EncodeToString(hash)
	return

}

func (trb *KeyBlock) Print() {
	log.Println("Header:")
	log.Printf("Leader %v", trb.LeaderId)
	log.Printf("Pkey %v", trb.PublicKey)
	log.Printf("Parent_Key %v", trb.Parent)
	log.Printf("Merkle %v", trb.MerkleRoot)
	trb.TransactionList.Print()

	log.Println("Rest:")
	log.Printf("Hash %v", trb.HeaderHash)

	return
}
