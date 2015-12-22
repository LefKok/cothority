package main

import (
	"github.com/dedis/cothority/lib/bitcosi"
	"github.com/dedis/cothority/lib/bitcosi/blkparser"
	"github.com/dedis/cothority/lib/cliutils"
	"github.com/dedis/cothority/lib/coconet"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/sign"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	READING = iota
	PROCESSING
	KEY
	MICRO
)

// struct to ease keeping track of who requires a reply after
// tsm is processed/ aggregated by the TSServer
type MustReplyMessage struct {
	Tsm   BitCoSi.BitCoSiMessage
	To    string // name of reply destination
	Block BitCoSi.Block
}

/*
The counterpart to stamp.go - it listens for incoming requests
and passes those to the roundstamper.
*/

func init() {
	SLList = make(map[string]*StampListener)
}

var SLList map[string]*StampListener

type StampListener struct {
	Clients map[string]coconet.Conn

	// for aggregating micro-blockrequests from clients

	Mux            sync.Mutex
	Queue          [][][]MustReplyMessage
	READING        int
	PROCESSING     int
	READING_KEY    int
	PROCESSING_KEY int

	//coordination between rounds
	TempBlock  BitCoSi.TrBlock
	Last_Block string
	Tempflag   sync.Mutex

	Commitround *sign.SignatureBroadcastMessage

	TempKeyBlock   BitCoSi.KeyBlock
	Last_Key_Block string

	//transaction pool
	trmux            sync.Mutex
	transaction_pool []blkparser.Tx
	IP               net.IP
	PublicKey        string
	bmux             sync.Mutex
	blocks           []BitCoSi.TrBlock
	keyblocks        []BitCoSi.KeyBlock
	NameL            string
	// The channel for closing the connection
	waitClose chan string
	// The port we're listening on
	Port  net.Listener
	rLock sync.Mutex

	proof_of_signing sign.SigningMessage
	time             time.Time
}

// Creates a new stamp listener one port above the
// address given in nameP
func NewStampListener(nameP string, fail bool) *StampListener {
	// listen for client requests at one port higher
	// than the signing node
	var nameL string
	h, p, err := net.SplitHostPort(nameP)
	if err == nil {
		i, err := strconv.Atoi(p)
		if err != nil {
			dbg.Fatal(err)
		}
		nameL = net.JoinHostPort(h, strconv.Itoa(i+1))
	} else {
		dbg.Fatal("Couldn't split host into name and port:", err)
	}
	sl, ok := SLList[nameL]
	if !ok {
		sl = &StampListener{}
		dbg.Lvl3("Creating new bitcosi-StampListener for", nameL)
		sl.IP = net.IPv4(0, 1, 2, 3)
		sl.PublicKey = "my_cool_key"
		if fail {

			sl.Last_Block = "1"
			sl.Last_Key_Block = "1"

		}
		sl.Last_Block = "0"
		sl.Last_Key_Block = "0"
		sl.TempBlock = BitCoSi.TrBlock{}
		sl.TempKeyBlock = BitCoSi.KeyBlock{}
		sl.Tempflag = sync.Mutex{}
		sl.transaction_pool = make([]blkparser.Tx, 0)
		sl.blocks = make([]BitCoSi.TrBlock, 0)
		sl.keyblocks = make([]BitCoSi.KeyBlock, 0)
		sl.rLock = sync.Mutex{}
		sl.Queue = make([][][]MustReplyMessage, 4)
		sl.Queue[KEY] = make([][]MustReplyMessage, 2)
		sl.Queue[KEY][READING] = make([]MustReplyMessage, 0)
		sl.Queue[KEY][PROCESSING] = make([]MustReplyMessage, 0)
		sl.Queue[MICRO] = make([][]MustReplyMessage, 2)
		sl.Queue[MICRO][READING] = make([]MustReplyMessage, 0)
		sl.Queue[MICRO][PROCESSING] = make([]MustReplyMessage, 0)
		sl.Clients = make(map[string]coconet.Conn)
		sl.waitClose = make(chan string)
		sl.NameL = nameL
		SLList[sl.NameL] = sl
		sl.ListenRequests()
	} else {
		dbg.Lvl3("Taking cached StampListener")
	}
	return sl
}

// listen for clients connections
func (s *StampListener) ListenRequests() error {
	dbg.Lvl3("Setup StampListener on", s.NameL)
	global, _ := cliutils.GlobalBind(s.NameL)
	var err error
	s.Port, err = net.Listen("tcp4", global)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			//dbg.Lvl2("Listening to sign-requests: %p", s)
			conn, err := s.Port.Accept()
			if err != nil {
				// handle error
				dbg.Lvl3("failed to accept connection")
				select {
				case w := <-s.waitClose:
					dbg.Lvl3("Closing stamplistener:", w)
					return
				default:
					continue
				}
			}

			dbg.Lvl3("Waiting for connection")
			c := coconet.NewTCPConnFromNet(conn)

			if _, ok := s.Clients[c.Name()]; !ok {
				s.Clients[c.Name()] = c

				go func(co coconet.Conn) {
					for {
						tsm := BitCoSi.BitCoSiMessage{}
						err := co.GetData(&tsm)
						//dbg.Lvl2("Got data to sign %+v - %+v", tsm, tsm.Treq)
						if err != nil {
							dbg.Lvlf1("%p Failed to get from child: %s", s, err)
							co.Close()
							return
						}
						switch tsm.Type {
						default:
							dbg.Lvlf1("Message of unknown type: %v\n", tsm.Type)
						case BitCoSi.BlockRequestType:
							s.Mux.Lock()
							dbg.Lvl5("BlockRequest: %v\n", tsm.Type)
							READING := s.READING
							s.Queue[MICRO][READING] = append(s.Queue[MICRO][READING],
								MustReplyMessage{Tsm: tsm, To: co.Name()})
							s.Mux.Unlock()
						case BitCoSi.KeyBlockRequestType:
							s.Mux.Lock()
							//dbg.Lvlf1("KeyBlockRequest: %v\n", tsm.Type)
							READING_KEY := s.READING_KEY
							s.Queue[KEY][READING_KEY] = append(s.Queue[KEY][READING_KEY],
								MustReplyMessage{Tsm: tsm, To: co.Name()})
							s.Mux.Unlock()

						case BitCoSi.TransactionAnnouncmentType:
							s.trmux.Lock()
							dbg.Lvl5("Got a transaction to sign %+v ", tsm.Treq.Val)

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

// Close shuts down the connection
func (s *StampListener) Close() {
	close(s.waitClose)
	s.Port.Close()
	delete(SLList, s.NameL)
	dbg.Lvl3(s.NameL, "Closing stamplistener done - SLList is", SLList)
}

// StampListenersClose closes all open stamplisteners
func StampListenersClose() {
	for _, s := range SLList {
		s.Close()
	}
}
