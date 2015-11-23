package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/dedis/cothority/lib/bitcosi"
	"github.com/dedis/cothority/lib/bitcosi/blkparser"
	"github.com/dedis/cothority/lib/cliutils"
	"github.com/dedis/cothority/lib/coconet"
	dbg "github.com/dedis/cothority/lib/debug_lvl"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/logutils"
	"github.com/dedis/cothority/lib/proof"
	"github.com/dedis/cothority/proto/sign"
	"github.com/dedis/crypto/abstract"
	"os"
)

// struct to ease keeping track of who requires a reply after
// tsm is processed/ aggregated by the TSServer
type TrRequestMessage struct {
	Tsm   BitCoSi.BitCoSiMessage
	To    string // name of reply destination
	Block BitCoSi.TrBlock
}

type KeyRequestMessage struct {
	Tsm   BitCoSi.BitCoSiMessage
	To    string // name of reply destination
	Block BitCoSi.KeyBlock
}

type Server struct {
	sign.Signer
	name    string
	Clients map[string]coconet.Conn

	// for aggregating micro-blockrequests from clients
	mux        sync.Mutex
	Queue      [][]TrRequestMessage
	READING    int
	PROCESSING int

	// for aggregating key-blockrequests from clients
	Kmux        sync.Mutex
	KQueue      [][]KeyRequestMessage
	KREADING    int
	KPROCESSING int

	//transaction pool
	trmux            sync.Mutex
	transaction_pool []blkparser.Tx
	IP               net.IP
	PublicKey        string
	Last_Tr_Block    string
	Last_Key_Block   string
	bmux             sync.Mutex
	trblocks         []BitCoSi.TrBlock
	keyblocks        []BitCoSi.KeyBlock
	//no need for lock if there is concurrency then there is a problem since two keyblocks cannot be concurrently verified

	// Leaves, Root and Proof for a round
	Leaves []hashid.HashId // can be removed after we verify protocol
	Root   hashid.HashId
	Proofs []proof.Proof
	// Timestamp message for this Round
	Timestamp int64

	rLock     sync.Mutex
	maxRounds int
	closeChan chan bool

	Logger   string
	Hostname string
	App      string
}

func NewServer(signer sign.Signer) *Server {
	s := &Server{}

	s.Clients = make(map[string]coconet.Conn)
	s.Queue = make([][]TrRequestMessage, 2)
	s.READING = 0
	s.PROCESSING = 1

	s.KQueue = make([][]KeyRequestMessage, 2)
	s.KREADING = 0
	s.KPROCESSING = 1

	s.IP = net.IPv4(0, 1, 2, 3)
	s.PublicKey = "my_cool_key"
	s.Last_Tr_Block = "0"
	s.Last_Key_Block = "0"
	s.transaction_pool = make([]blkparser.Tx, 0)
	s.trblocks = make([]BitCoSi.TrBlock, 0)
	s.keyblocks = make([]BitCoSi.KeyBlock, 0)

	s.Signer = signer
	s.Signer.RegisterAnnounceFunc(s.AnnounceFunc())
	s.Signer.RegisterCommitFunc(s.CommitFunc())
	s.Signer.RegisterDoneFunc(s.OnDone())
	s.rLock = sync.Mutex{}

	// listen for client requests at one port higher
	// than the signing node
	h, p, err := net.SplitHostPort(s.Signer.Name())
	if err == nil {
		i, err := strconv.Atoi(p)
		if err != nil {
			log.Fatal(err)
		}
		s.name = net.JoinHostPort(h, strconv.Itoa(i+1))
	}
	s.Queue[s.READING] = make([]TrRequestMessage, 0)
	s.Queue[s.PROCESSING] = make([]TrRequestMessage, 0)
	s.KQueue[s.KREADING] = make([]KeyRequestMessage, 0)
	s.KQueue[s.KPROCESSING] = make([]KeyRequestMessage, 0)
	s.closeChan = make(chan bool, 5)
	return s
}

var clientNumber int = 0

func (s *Server) Close() {
	dbg.Lvl4("closing stampserver: %p", s.name)
	s.closeChan <- true
	s.Signer.Close()
}

// listen for clients connections
// this server needs to be running on a different port
// than the Signer that is beneath it
func (s *Server) Listen() error {
	global, _ := cliutils.GlobalBind(s.name)
	dbg.LLvl3("Listening in server at", global)
	ln, err := net.Listen("tcp4", global)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			dbg.Lvl2("Listening to sign-requests: %p", s)
			conn, err := ln.Accept()
			if err != nil {
				// handle error
				dbg.Lvl3("failed to accept connection")
				continue
			}

			c := coconet.NewTCPConnFromNet(conn)
			dbg.Lvl2("Established connection with client:", c)

			if _, ok := s.Clients[c.Name()]; !ok {
				s.Clients[c.Name()] = c

				go func(co coconet.Conn) {
					for {
						tsm := BitCoSi.BitCoSiMessage{}
						err := co.GetData(&tsm)
						dbg.Lvl2("Got data to sign %+v - %+v", tsm, tsm.Treq)
						if err != nil {
							dbg.Lvlf1("%p Failed to get from child: %s", s, err)
							co.Close()
							return
						}
						switch tsm.Type {
						default:
							dbg.Lvlf1("Message of unknown type: %v\n", tsm.Type)
						case BitCoSi.TrBlockRequestType:
							s.mux.Lock()
							dbg.Lvlf1("BlockRequest: %v\n", tsm.Type)
							READING := s.READING
							s.Queue[READING] = append(s.Queue[READING],
								TrRequestMessage{Tsm: tsm, To: co.Name()})
							s.mux.Unlock()
						case BitCoSi.KeyBlockRequestType: //TOD
							s.Kmux.Lock()
							dbg.Lvlf1("BlockRequest: %v\n", tsm.Type)
							KREADING := s.KREADING
							s.KQueue[KREADING] = append(s.KQueue[KREADING],
								KeyRequestMessage{Tsm: tsm, To: co.Name()})
							s.Kmux.Unlock()

						case BitCoSi.TransactionAnnouncmentType:
							s.trmux.Lock()
							s.transaction_pool = append(s.transaction_pool, tsm.Treq.Val)
							s.trmux.Unlock()

						case BitCoSi.BitCoSiClose:
							dbg.Lvl2("Closing connection")
							co.Close()
							return
						case BitCoSi.BitCoSiExit:
							dbg.Lvl1("Exiting server upon request")
							os.Exit(-1)
						}
					}
				}(c)
			}
		}
	}()

	return nil
}

func (s *Server) ConnectToLogger() {
	return
	if s.Logger == "" || s.Hostname == "" || s.App == "" {
		dbg.Lvl4("skipping connect to logger")
		return
	}
	dbg.Lvl4("Connecting to Logger")
	lh, _ := logutils.NewLoggerHook(s.Logger, s.Hostname, s.App)
	dbg.Lvl4("Connected to Logger")
	log.AddHook(lh)
}

func (s *Server) LogReRun(nextRole string, curRole string) {
	if nextRole == "root" {
		var messg = s.Name() + " became root"
		if curRole == "root" {
			messg = s.Name() + " remained root"
		}

		go s.ConnectToLogger()

		log.WithFields(log.Fields{
			"file": logutils.File(),
			"type": "role_change",
		}).Infoln(messg)
		// dbg.Lvl4("role change: %p", s)

	} else {
		var messg = s.Name() + " remained regular"
		if curRole == "root" {
			messg = s.Name() + " became regular"
		}

		if curRole == "root" {
			log.WithFields(log.Fields{
				"file": logutils.File(),
				"type": "role_change",
			}).Infoln(messg)
			dbg.Lvl4("role change: %p", s)
		}

	}

}

func GetTrBlock(s *Server, n int) (t BitCoSi.TrBlock, _ error) {
	if len(s.transaction_pool) > 0 {
		trblock := t.NewBlock(s.transaction_pool, n, s.Last_Tr_Block, s.Last_Key_Block, s.IP, s.PublicKey)
		s.transaction_pool = s.transaction_pool[trblock.TransactionList.TxCnt:]
		s.Last_Tr_Block = trblock.HeaderHash //this should be done afeter verification
		return trblock, nil
	} else {
		return *new(BitCoSi.TrBlock), errors.New("no transaction available")
	}

}

func GetKeyBlock(s *Server, n int) (t BitCoSi.KeyBlock, _ error) {
	if len(s.transaction_pool) > 0 {
		keyblock := t.NewBlock(s.transaction_pool, 1, s.Last_Key_Block, s.IP, s.PublicKey)
		s.transaction_pool = s.transaction_pool[keyblock.TransactionList.TxCnt:]
		s.Last_Key_Block = keyblock.HeaderHash //this should be done afeter verification
		return keyblock, nil
	} else {
		return *new(BitCoSi.KeyBlock), errors.New("no transaction available")
	}

}

var flag_key bool

func (s *Server) runAsRoot(nRounds int) string {
	// every 5 seconds start a new round
	ticker := time.Tick(2 * ROUND_TIME)
	tacker := time.Tick(5 * ROUND_TIME)

	if s.LastRound()+1 > nRounds && nRounds >= 0 {
		dbg.Lvl1(s.Name(), "runAsRoot called with too large round number")
		return "close"
	}

	dbg.Lvl3(s.Name(), "running as root", s.LastRound(), int64(nRounds))
	for {
		select {
		case nextRole := <-s.ViewChangeCh():
			dbg.Lvl4(s.Name(), "assuming next role")
			return nextRole
		// s.reRunWith(nextRole, nRounds, true)

		case <-tacker:
			flag_key = true

			dbg.Lvl4(s.Name(), "Keyblock time server in round", s.LastRound()+1, "of", nRounds)

			var err error
			if s.App == "vote" {
				vote := &sign.Vote{
					Type: sign.AddVT,
					Av: &sign.AddVote{
						Parent: s.Name(),
						Name:   "test-add-node"}}
				err = s.StartVotingRound(vote)
			} else {
				//signingNode = s.Signer.(sign.Node)
				//signingNode.BroadcastBLock(block)
				//signingNode.ReceiveACKBlock()

				s.trmux.Lock()
				keyblock, err := GetKeyBlock(s, 1)
				s.trmux.Unlock()

				if err != nil {
					//dbg.Lvl3(err)
					time.Sleep(1 * time.Second)
					break
				}

				s.keyblocks = append(s.keyblocks, keyblock)
				//s.trblocks[0].Print()

				err = s.StartSigningRound()
			}
			if err == sign.ChangingViewError {
				// report change in view, and continue with the select
				log.WithFields(log.Fields{
					"file": logutils.File(),
					"type": "view_change",
				}).Info("Tried to stary signing round on " + s.Name() + " but it reports view change in progress")
				// skip # of failed round
				time.Sleep(1 * time.Second)
				break
			} else if err != nil {
				dbg.Lvl3(err)
				time.Sleep(1 * time.Second)
				break
			}

			if s.LastRound()+1 >= nRounds && nRounds >= 0 {
				log.Infoln(s.Name(), "reports exceeded the max round: terminating", s.LastRound()+1, ">=", nRounds)
				return "close"
			}

		case <-ticker:
			flag_key = false

			dbg.Lvl4(s.Name(), "Stamp server in round", s.LastRound()+1, "of", nRounds)

			var err error
			if s.App == "vote" {
				vote := &sign.Vote{
					Type: sign.AddVT,
					Av: &sign.AddVote{
						Parent: s.Name(),
						Name:   "test-add-node"}}
				err = s.StartVotingRound(vote)
			} else {
				//signingNode = s.Signer.(sign.Node)
				//signingNode.BroadcastBLock(block)
				//signingNode.ReceiveACKBlock()

				s.trmux.Lock()
				trblock, err := GetTrBlock(s, 10)
				s.trmux.Unlock()

				if err != nil {
					//dbg.Lvl3(err)
					time.Sleep(1 * time.Second)
					break
				}

				s.bmux.Lock()
				s.trblocks = append(s.trblocks, trblock)
				s.bmux.Unlock()
				//s.trblocks[0].Print()

				err = s.StartSigningRound()
			}
			if err == sign.ChangingViewError {
				// report change in view, and continue with the select
				log.WithFields(log.Fields{
					"file": logutils.File(),
					"type": "view_change",
				}).Info("Tried to stary signing round on " + s.Name() + " but it reports view change in progress")
				// skip # of failed round
				time.Sleep(1 * time.Second)
				break
			} else if err != nil {
				dbg.Lvl3(err)
				time.Sleep(1 * time.Second)
				break
			}

			if s.LastRound()+1 >= nRounds && nRounds >= 0 {
				log.Infoln(s.Name(), "reports exceeded the max round: terminating", s.LastRound()+1, ">=", nRounds)
				return "close"
			}
		}
	}
}

func (s *Server) runAsRegular() string {
	select {
	case <-s.closeChan:
		dbg.Lvl3("server", s.Name(), "has closed the connection")
		return ""

	case nextRole := <-s.ViewChangeCh():
		return nextRole
	}
}

// Listen on client connections. If role is root also send annoucement
// for all of the nRounds
func (s *Server) Run(role string) {
	// defer func() {
	// 	log.Infoln(s.Name(), "CLOSE AFTER RUN")
	// 	s.Close()
	// }()

	dbg.Lvl3("Stamp-server", s.name, "starting with ", role)
	closed := make(chan bool, 1)

	go func() { err := s.Signer.Listen(); closed <- true; s.Close(); log.Error(err) }()
	s.rLock.Lock()

	// TO/DO: remove this hack
	s.maxRounds = -1
	s.rLock.Unlock()

	var nextRole string // next role when view changes
	for {
		switch role {

		case "root":
			dbg.Lvl4("running as root")
			nextRole = s.runAsRoot(s.maxRounds)
		case "regular":
			dbg.Lvl4("running as regular")
			nextRole = s.runAsRegular()
		default:
			dbg.Fatal("Unable to run as anything")
			return
		}

		// dbg.Lvl4(s.Name(), "nextRole: ", nextRole)
		if nextRole == "close" {
			s.Close()
			return
		}
		if nextRole == "" {
			return
		}
		s.LogReRun(nextRole, role)
		role = nextRole
	}

}

// AnnounceFunc will keep the timestamp generated for this round
func (s *Server) AnnounceFunc() sign.AnnounceFunc {
	return func(am *sign.AnnouncementMessage) {
		dbg.Lvl1("Anounce")

		var t int64
		if err := binary.Read(bytes.NewBuffer(am.Message), binary.LittleEndian, &t); err != nil {
			dbg.Lvl1("Unmashaling timestamp has failed")
		}
		s.Timestamp = t
	}
}

/*
func (s *Server) RoundMessageFunc() sign.RoundMessageFunc {
	return func(view int) []byte {
		hash(s.trblocks())
	}
}
*/

func (s *Server) CommitFunc() sign.CommitFunc {
	return func(view int) []byte {
		dbg.Lvl4("Aggregating Commits")
		return s.AggregateCommits(view)
	}
}

func (s *Server) OnDone() sign.DoneFunc {

	if flag_key == false {
		return func(view int, SNRoot hashid.HashId, LogHash hashid.HashId, p proof.Proof,
			sb *sign.SignatureBroadcastMessage, suite abstract.Suite) {
			s.mux.Lock()
			for _, msg := range s.Queue[s.PROCESSING] {
				dbg.Lvlf5("%+v", msg)
				// proof to get from s.Root to big root
				combProof := make(proof.Proof, len(p))
				copy(combProof, p)

				// add my proof to get from a leaf message to my root s.Root
				combProof = append(combProof, s.Proofs[0]...)

				// proof that I can get from a leaf message to the big root
				if proof.CheckProof(s.Signer.(*sign.Node).Suite().Hash, SNRoot, s.Leaves[0], combProof) {
					dbg.Lvl2("Proof is OK")
				} else {
					dbg.Lvl2("Inclusion-proof failed")
				}

				s.bmux.Lock()

				respMessg := &BitCoSi.BitCoSiMessage{
					Type:  BitCoSi.BlockReplyType,
					ReqNo: msg.Tsm.ReqNo,
					Brep:  &BitCoSi.BlockReply{SuiteStr: suite.String(), Timestamp: s.Timestamp, TrBlock: s.trblocks[0], MerkleRoot: SNRoot, Prf: combProof, SigBroad: *sb}}
				s.PutToClient(msg.To, respMessg)
				dbg.Lvl1("Sent signature response back to client")
				s.bmux.Unlock()

			}
			s.bmux.Lock()

			if len(s.trblocks) > 0 {
				s.trblocks = s.trblocks[1:]
			}
			s.bmux.Unlock()

			s.mux.Unlock()
			s.Timestamp = 0
		}
	} else {
		return func(view int, SNRoot hashid.HashId, LogHash hashid.HashId, p proof.Proof,
			sb *sign.SignatureBroadcastMessage, suite abstract.Suite) {
			s.Kmux.Lock()
			for _, msg := range s.KQueue[s.KPROCESSING] {
				dbg.Lvlf5("%+v", msg)
				// proof to get from s.Root to big root
				combProof := make(proof.Proof, len(p))
				copy(combProof, p)

				// add my proof to get from a leaf message to my root s.Root
				combProof = append(combProof, s.Proofs[0]...)

				// proof that I can get from a leaf message to the big root
				if proof.CheckProof(s.Signer.(*sign.Node).Suite().Hash, SNRoot, s.Leaves[0], combProof) {
					dbg.Lvl2("Proof is OK")
				} else {
					dbg.Lvl2("Inclusion-proof failed")
				}

				respMessg := &BitCoSi.BitCoSiMessage{
					Type:  BitCoSi.BlockReplyType,
					ReqNo: msg.Tsm.ReqNo,
					Brep:  &BitCoSi.BlockReply{SuiteStr: suite.String(), Timestamp: s.Timestamp, KeyBlock: s.keyblocks[0], MerkleRoot: SNRoot, Prf: combProof, SigBroad: *sb}}
				s.PutToClient(msg.To, respMessg)
				dbg.Lvl1("Sent signature response back to client")

			}

			if len(s.keyblocks) > 0 {
				s.keyblocks = s.keyblocks[1:]
			}

			s.Kmux.Unlock()
			s.Timestamp = 0
		}
	}

}

func (s *Server) AggregateCommits(view int) []byte {
	dbg.Lvl4(s.Name(), "calling AggregateCommits")
	if flag_key == false {

		s.mux.Lock()
		// get data from s once to avoid refetching from structure
		Queue := s.Queue
		READING := s.READING
		PROCESSING := s.PROCESSING
		// messages read will now be processed
		READING, PROCESSING = PROCESSING, READING
		s.READING, s.PROCESSING = s.PROCESSING, s.READING
		s.Queue[READING] = s.Queue[READING][:0]

		// give up if nothing to process
		if len(Queue[PROCESSING]) == 0 {
			s.mux.Unlock()
			s.Root = make([]byte, hashid.Size)
			s.Proofs = make([]proof.Proof, 1)
			return s.Root
		}

		// pull out to be Merkle Tree leaves
		s.Leaves = make([]hashid.HashId, 0)
		s.bmux.Lock()
		for _, msg := range Queue[PROCESSING] {
			msg.Block = s.trblocks[0]
		}
		s.Leaves = append(s.Leaves, hashid.HashId(s.trblocks[0].HeaderHash))
		s.bmux.Unlock()
		s.mux.Unlock()

		// non root servers keep track of rounds here
		if !s.IsRoot(view) {
			s.rLock.Lock()
			lsr := s.LastRound()
			mr := s.maxRounds
			s.rLock.Unlock()
			// if this is our last round then close the connections
			if lsr >= mr && mr >= 0 {
				s.closeChan <- true
			}
		}

		// create Merkle tree for this round's messages and check corectness
		s.Root, s.Proofs = proof.ProofTree(s.Suite().Hash, s.Leaves)
		if sign.DEBUG == true {
			if proof.CheckLocalProofs(s.Suite().Hash, s.Root, s.Leaves, s.Proofs) == true {
				dbg.Lvl4("Local Proofs of", s.Name(), "successful for round "+strconv.Itoa(int(s.LastRound())))
			} else {
				panic("Local Proofs" + s.Name() + " unsuccessful for round " + strconv.Itoa(int(s.LastRound())))
			}
		}

		return s.Root
	} else {

		s.mux.Lock()
		// get data from s once to avoid refetching from structure
		Queue := s.KQueue
		READING := s.KREADING
		PROCESSING := s.KPROCESSING
		// messages read will now be processed
		READING, PROCESSING = PROCESSING, READING
		s.KREADING, s.KPROCESSING = s.KPROCESSING, s.KREADING
		s.KQueue[READING] = s.KQueue[READING][:0]

		// give up if nothing to process
		if len(Queue[PROCESSING]) == 0 {
			s.mux.Unlock()
			s.Root = make([]byte, hashid.Size)
			s.Proofs = make([]proof.Proof, 1)
			return s.Root
		}

		// pull out to be Merkle Tree leaves
		s.Leaves = make([]hashid.HashId, 0)
		s.bmux.Lock()
		for _, msg := range Queue[PROCESSING] {
			msg.Block = s.keyblocks[0]
		}
		s.Leaves = append(s.Leaves, hashid.HashId(s.keyblocks[0].HeaderHash))
		s.bmux.Unlock()
		s.mux.Unlock()

		// non root servers keep track of rounds here
		if !s.IsRoot(view) {
			s.rLock.Lock()
			lsr := s.LastRound()
			mr := s.maxRounds
			s.rLock.Unlock()
			// if this is our last round then close the connections
			if lsr >= mr && mr >= 0 {
				s.closeChan <- true
			}
		}

		// create Merkle tree for this round's messages and check corectness
		s.Root, s.Proofs = proof.ProofTree(s.Suite().Hash, s.Leaves)
		if sign.DEBUG == true {
			if proof.CheckLocalProofs(s.Suite().Hash, s.Root, s.Leaves, s.Proofs) == true {
				dbg.Lvl4("Local Proofs of", s.Name(), "successful for round "+strconv.Itoa(int(s.LastRound())))
			} else {
				panic("Local Proofs" + s.Name() + " unsuccessful for round " + strconv.Itoa(int(s.LastRound())))
			}
		}

		return s.Root

	}
}

// Send message to client given by name
func (s *Server) PutToClient(name string, data coconet.BinaryMarshaler) {
	err := s.Clients[name].PutData(data)
	if err == coconet.ErrClosed {
		s.Close()
		return
	}
	if err != nil && err != coconet.ErrNotEstablished {
		log.Warnf("%p error putting to client: %v", s, err)
	}
}
