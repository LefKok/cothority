package conode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/dedis/cothority/lib/app"
	"github.com/dedis/cothority/lib/cliutils"
	"github.com/dedis/cothority/lib/coconet"
	dbg "github.com/dedis/cothority/lib/debug_lvl"
	"github.com/dedis/cothority/lib/graphs"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/proof"
	"github.com/dedis/cothority/proto/sign"
	"github.com/dedis/crypto/abstract"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// This file provides methods to run a server amongst a cothority tree
// And also provides a callback implementation of a timestamper server.

// Make connections and run server.go
func RunServer(address string, conf *app.ConfigConode, cb Callbacks) {
	suite := app.GetSuite(conf.Suite)

	var err error
	// make sure address has a port or insert default one
	address, err = cliutils.VerifyPort(address, DefaultPort)
	if err != nil {
		dbg.Fatal(err)
	}

	// For retro compatibility issues, convert the base64 encoded key into hex
	// encoded keys....
	convertTree(suite, conf.Tree)
	// Add our private key to the tree (compatiblity issues again with graphs/
	// lib)
	addPrivateKey(suite, address, conf)
	// load the configuration
	//dbg.Lvl3("loading configuration")
	var hc *graphs.HostConfig
	opts := graphs.ConfigOptions{ConnType: "tcp", Host: address, Suite: suite}

	hc, err = graphs.LoadConfig(conf.Hosts, conf.Tree, suite, opts)
	if err != nil {
		dbg.Fatal(err)
	}

	// Listen to stamp-requests on port 2001
	stampers, err := runTimestamper(hc, 0, cb, address)
	if err != nil {
		dbg.Fatal(err)
	}

	// Start the cothority-listener on port 2000
	err = hc.Run(true, sign.MerkleTree, address)
	if err != nil {
		dbg.Fatal(err)
	}

	defer func(sn *sign.Node) {
		dbg.Lvl2("Program timestamper has terminated:", address)
		sn.Close()
	}(hc.SNodes[0])

	for _, s := range stampers {
		// only listen if this is the hostname specified
		if s.Name() == address {
			s.Hostname = address
			s.App = "stamp"
			if s.IsRoot(0) {
				dbg.Lvl1("Root timestamper at:", address)
				s.Run("root")

			} else {
				dbg.Lvl1("Running regular timestamper on:", address)
				s.Run("regular")
			}
		}
	}
}

// CallbacksStamper is an implementation fo Callbacks which define a stamper
// server
type CallbacksStamper struct {
	// for aggregating messages from clients
	mux        sync.Mutex
	Queue      [][]MustReplyMessage
	READING    int
	PROCESSING int

	// Leaves, Root and Proof for a round
	Leaves []hashid.HashId // can be removed after we verify protocol
	Root   hashid.HashId
	Proofs []proof.Proof
	// Timestamp message for this Round
	Timestamp int64

	Clients map[string]coconet.Conn
}

func NewCallbacksStamper() *CallbacksStamper {
	cbs := &CallbacksStamper{}
	cbs.Queue = make([][]MustReplyMessage, 2)
	cbs.READING = 0
	cbs.PROCESSING = 1
	cbs.Queue[cbs.READING] = make([]MustReplyMessage, 0)
	cbs.Queue[cbs.PROCESSING] = make([]MustReplyMessage, 0)
	cbs.Clients = make(map[string]coconet.Conn)

	return cbs
}

// StartAnnouncementFunc is the function that will return the current timestamp
// in unix int64 format. This message will be forwarded along the tree so every
// signatures for this round will have this timestamp
func (cs *CallbacksStamper) RoundMessageFunc() sign.RoundMessageFunc {
	return sign.DefaultRoundMessageFunc
}

// AnnounceFunc will keep the timestamp generated for this round
func (cs *CallbacksStamper) OnAnnounceFunc() sign.OnAnnounceFunc {
	return func(am *sign.AnnouncementMessage) {
		var t int64
		if err := binary.Read(bytes.NewBuffer(am.Message), binary.LittleEndian, &t); err != nil {
			dbg.Lvl1("Unmashaling timestamp has failed")
		}
		cs.Timestamp = t
	}
}

func (cs *CallbacksStamper) CommitFunc(p *Peer) sign.CommitFunc {
	return func(view int) []byte {
		//dbg.Lvl4(cs.Name(), "calling AggregateCommits")
		cs.mux.Lock()
		// get data from s once to avoid refetching from structure
		Queue := cs.Queue
		READING := cs.READING
		PROCESSING := cs.PROCESSING
		// messages read will now be processed
		READING, PROCESSING = PROCESSING, READING
		cs.READING, cs.PROCESSING = cs.PROCESSING, cs.READING
		cs.Queue[READING] = cs.Queue[READING][:0]

		// give up if nothing to process
		if len(Queue[PROCESSING]) == 0 {
			cs.mux.Unlock()
			cs.Root = make([]byte, hashid.Size)
			cs.Proofs = make([]proof.Proof, 1)
			return cs.Root
		}

		// pull out to be Merkle Tree leaves
		cs.Leaves = make([]hashid.HashId, 0)
		for _, msg := range Queue[PROCESSING] {
			cs.Leaves = append(cs.Leaves, hashid.HashId(msg.Tsm.Sreq.Val))
		}
		cs.mux.Unlock()

		// non root servers keep track of rounds here
		if !p.IsRoot(view) {
			p.rLock.Lock()
			lsr := p.LastRound()
			mr := p.maxRounds
			p.rLock.Unlock()
			// if this is our last round then close the connections
			if lsr >= mr && mr >= 0 {
				p.closeChan <- true
			}
		}

		// create Merkle tree for this round's messages and check corectness
		cs.Root, cs.Proofs = proof.ProofTree(p.Suite().Hash, cs.Leaves)
		if sign.DEBUG == true {
			if proof.CheckLocalProofs(p.Suite().Hash, cs.Root, cs.Leaves, cs.Proofs) == true {
				dbg.Lvl4("Local Proofs of", p.Name(), "successful for round "+strconv.Itoa(int(p.LastRound())))
			} else {
				panic("Local Proofs" + p.Name() + " unsuccessful for round " + strconv.Itoa(int(p.LastRound())))
			}
		}

		return cs.Root
	}
}

// ValidateFunc returns a alwaays-true function since we did not implement
// validation mode yet.
func (cs *CallbacksStamper) ValidateFunc() sign.ValidateFunc {
	return func(vbm *sign.ValidationBroadcastMessage) bool {
		return true
	}
}
func (cs *CallbacksStamper) OnDone(p *Peer) sign.OnDoneFunc {
	return func(view int, SNRoot hashid.HashId, LogHash hashid.HashId, pr proof.Proof,
		sb *sign.SignatureBroadcastMessage) {
		cs.mux.Lock()
		for i, msg := range cs.Queue[cs.PROCESSING] {
			// proof to get from s.Root to big root
			combProof := make(proof.Proof, len(pr))
			copy(combProof, pr)

			// add my proof to get from a leaf message to my root s.Root
			combProof = append(combProof, cs.Proofs[i]...)

			// proof that I can get from a leaf message to the big root
			if proof.CheckProof(p.Signer.(*sign.Node).Suite().Hash, SNRoot, cs.Leaves[i], combProof) {
				dbg.Lvl2("Proof is OK")
			} else {
				dbg.Lvl2("Inclusion-proof failed")
			}
			reply := &StampSignature{
				AggPublic:  sb.X0_hat,
				AggCommit:  sb.V0_hat,
				Response:   sb.R0_hat,
				Challenge:  sb.C,
				Timestamp:  cs.Timestamp,
				SuiteStr:   p.Suite().String(),
				MerkleRoot: SNRoot,
				Prf:        combProof,
			}
			respMessg := &TimeStampMessage{
				Type:  StampSignatureType,
				ReqNo: msg.Tsm.ReqNo,
				Srep:  reply}

			cs.PutToClient(p, msg.To, respMessg)
			dbg.Lvl1("Sent signature response back to client")
		}
		cs.mux.Unlock()
		cs.Timestamp = 0
	}

}

// Send message to client given by name
func (cs *CallbacksStamper) PutToClient(p *Peer, name string, data coconet.BinaryMarshaler) {
	err := cs.Clients[name].PutData(data)
	if err == coconet.ErrClosed {
		p.Close()
		return
	}
	if err != nil && err != coconet.ErrNotEstablished {
		dbg.Lvl2("%p error putting to client: %v", cs, err)
	}
}

// Setu will start to listen to clients connections for stamping request
func (cs *CallbacksStamper) Setup(p *Peer) error {
	global, _ := cliutils.GlobalBind(p.name)
	dbg.LLvl3("Listening in server at", global)
	ln, err := net.Listen("tcp4", global)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			dbg.Lvl2("Listening to sign-requests: %p", cs)
			conn, err := ln.Accept()
			if err != nil {
				// handle error
				dbg.Lvl3("failed to accept connection")
				continue
			}

			c := coconet.NewTCPConnFromNet(conn)
			dbg.Lvl2("Established connection with client:", c)

			if _, ok := cs.Clients[c.Name()]; !ok {
				cs.Clients[c.Name()] = c

				go func(co coconet.Conn) {
					for {
						tsm := TimeStampMessage{}
						err := co.GetData(&tsm)
						dbg.Lvl2("Got data to sign %+v - %+v", tsm, tsm.Sreq)
						if err != nil {
							dbg.Lvlf1("%p Failed to get from child: %s", p, err)
							co.Close()
							return
						}
						switch tsm.Type {
						default:
							dbg.Lvlf1("Message of unknown type: %v\n", tsm.Type)
						case StampRequestType:
							cs.mux.Lock()
							READING := cs.READING
							cs.Queue[READING] = append(cs.Queue[READING],
								MustReplyMessage{Tsm: tsm, To: co.Name()})
							cs.mux.Unlock()
						case StampClose:
							dbg.Lvl2("Closing connection")
							co.Close()
							return
						case StampExit:
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

// run each host in hostnameSlice with the number of clients given
func runTimestamper(hc *graphs.HostConfig, nclients int, cb Callbacks, hostnameSlice ...string) ([]*Peer, error) {
	dbg.Lvl3("RunTimestamper on", hc.Hosts)
	hostnames := make(map[string]*sign.Node)
	// make a list of hostnames we want to run
	if hostnameSlice == nil {
		hostnames = hc.Hosts
	} else {
		for _, h := range hostnameSlice {
			sn, ok := hc.Hosts[h]
			if !ok {
				return nil, errors.New("hostname given not in config file:" + h)
			}
			hostnames[h] = sn
		}
	}
	// for each client in
	stampers := make([]*Peer, 0, len(hostnames))
	for _, sn := range hc.SNodes {
		if _, ok := hostnames[sn.Name()]; !ok {
			dbg.Lvl1("signing node not in hostnmaes")
			continue
		}
		stampers = append(stampers, NewPeer(sn, cb))
		if hc.Dir == nil {
			dbg.Lvl3(hc.Hosts, "listening for clients")
			stampers[len(stampers)-1].Setup()
		}
	}
	dbg.Lvl3("stampers:", stampers)
	for _, s := range stampers[1:] {

		_, p, err := net.SplitHostPort(s.Name())
		if err != nil {
			dbg.Fatal("RunTimestamper: bad Tcp host")
		}
		pn, err := strconv.Atoi(p)
		if hc.Dir != nil {
			pn = 0
		} else if err != nil {
			dbg.Fatal("port ", pn, "is not valid integer")
		}
		//dbg.Lvl4("client connecting to:", hp)

	}

	return stampers, nil
}

// Simple ephemereal helper for comptability issues
// From base64 => hexadecimal
func convertTree(suite abstract.Suite, t *graphs.Tree) {
	point, err := cliutils.ReadPub64(suite, strings.NewReader(t.PubKey))
	if err != nil {
		dbg.Fatal("Could not decode base64 public key")
	}

	str, err := cliutils.PubHex(suite, point)
	if err != nil {
		dbg.Fatal("Could not encode point to hexadecimal ")
	}
	t.PubKey = str
	for _, c := range t.Children {
		convertTree(suite, c)
	}
}

// Add our own private key in the tree. This function exists because of
// compatilibty issues with the graphs/ lib.
func addPrivateKey(suite abstract.Suite, address string, conf *app.ConfigConode) {
	fn := func(t *graphs.Tree) {
		// this is our node in the tree
		if t.Name == address {
			// convert to hexa
			s, err := cliutils.SecretHex(suite, conf.Secret)
			if err != nil {
				dbg.Fatal("Error converting our secret key to hexadecimal")
			}
			// adds it
			t.PriKey = s
		}
	}
	conf.Tree.TraverseTree(fn)
}
