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
type MustReplyMessage struct {
	Tsm   BitCoSi.BitCoSiMessage
	To    string // name of reply destination
	Block BitCoSi.TrBlock
}

type Server struct {
	sign.Signer
	name    string
	Clients map[string]coconet.Conn

	// for aggregating blockrequests from clients
	mux        sync.Mutex
	Queue      [][]MustReplyMessage
	READING    int
	PROCESSING int

	//transaction pool
	trmux            sync.Mutex
	transaction_pool []blkparser.Tx
	IP               net.IP
	PublicKey        string
	Last_Block       string
	bmux             sync.Mutex
	blocks           []BitCoSi.TrBlock

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
	s.Queue = make([][]MustReplyMessage, 2)
	s.READING = 0
	s.PROCESSING = 1

	s.IP = net.IPv4(0, 1, 2, 3)
	s.PublicKey = "my_cool_key"
	s.Last_Block = "0"
	s.transaction_pool = make([]blkparser.Tx, 0)
	s.blocks = make([]BitCoSi.TrBlock, 0)

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
	s.Queue[s.READING] = make([]MustReplyMessage, 0)
	s.Queue[s.PROCESSING] = make([]MustReplyMessage, 0)
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
						case BitCoSi.BlockRequestType:
							s.mux.Lock()
							dbg.Lvlf1("BlockRequest: %v\n", tsm.Type)
							READING := s.READING
							s.Queue[READING] = append(s.Queue[READING],
								MustReplyMessage{Tsm: tsm, To: co.Name()})
							s.mux.Unlock()

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

func getblock(s *Server, n int) (_ BitCoSi.TrBlock, _ error) {
	if len(s.transaction_pool) > 0 {

		trlist := BitCoSi.NewTransactionList(s.transaction_pool, n)
		header := BitCoSi.NewHeader(trlist, s.Last_Block, s.IP, s.PublicKey)
		trblock := BitCoSi.NewTrBlock(trlist, header)
		s.transaction_pool = s.transaction_pool[trblock.TransactionList.TxCnt:]
		s.Last_Block = trblock.HeaderHash
		return trblock, nil
	} else {
		return *new(BitCoSi.TrBlock), errors.New("no transaction available")
	}

}

func (s *Server) runAsRoot(nRounds int) string {
	// every 5 seconds start a new round
	ticker := time.Tick(ROUND_TIME)
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
		case <-ticker:

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
				trblock, err := getblock(s, 10)
				s.trmux.Unlock()

				if err != nil {
					//dbg.Lvl3(err)
					time.Sleep(1 * time.Second)
					break
				}

				s.bmux.Lock()
				s.blocks = append(s.blocks, trblock)
				s.bmux.Unlock()
				//s.blocks[0].Print()

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
		hash(s.blocks())
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
				Brep:  &BitCoSi.BlockReply{SuiteStr: suite.String(), Timestamp: s.Timestamp, Block: s.blocks[0], MerkleRoot: SNRoot, Prf: combProof, SigBroad: *sb}}
			s.PutToClient(msg.To, respMessg)
			dbg.Lvl1("Sent signature response back to client")
			s.bmux.Unlock()

		}
		s.bmux.Lock()

		if len(s.blocks) > 0 {
			s.blocks = s.blocks[1:]
		}
		s.bmux.Unlock()

		s.mux.Unlock()
		s.Timestamp = 0
	}

}

func (s *Server) AggregateCommits(view int) []byte {
	//dbg.Lvl4(s.Name(), "calling AggregateCommits")
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
		msg.Block = s.blocks[0]
	}
	s.Leaves = append(s.Leaves, hashid.HashId(s.blocks[0].HeaderHash))
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
