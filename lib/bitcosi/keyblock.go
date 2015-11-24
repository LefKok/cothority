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
	Block
}

func (*KeyBlock) NewBlock(transactions []blkparser.Tx, n int, parent string, IP net.IP, k string) (keyb KeyBlock) {
	key := new(KeyBlock)
	key.Magic = [4]byte{0xF9, 0xBE, 0xB4, 0xD9}
	key.TransactionList = NewTransactionList(transactions, n)
	key.Header = key.NewHeader(key.TransactionList, parent, IP, k)
	key.HeaderHash = key.hash(fmt.Sprintf("%v", key.Header))
	key.BlockSize = 0
	return *key
}

func (kb *KeyBlock) NewHeader(transactions TransactionList, parent string, IP net.IP, key string) (hd Header) {
	hdr := new(Header)
	hdr.LeaderId = IP
	hdr.PublicKey = key
	hdr.ParentKey = parent
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

func (t *KeyBlock) hash(data string) (res string) {
	//change it to be more portable
	//data := fmt.Sprintf("%v", h)
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
	log.Printf("ParentKey_Key %v", trb.ParentKey)
	log.Printf("Merkle %v", trb.MerkleRoot)
	trb.TransactionList.Print()

	log.Println("Rest:")
	log.Printf("Hash %v", trb.HeaderHash)

	return
}
