package main

import (
	"github.com/dedis/cothority/lib/bitcosi"
	"github.com/dedis/cothority/lib/bitcosi/blkparser"
	"github.com/dedis/cothority/lib/cliutils"
	"github.com/dedis/cothority/lib/coconet"
	"github.com/dedis/cothority/lib/dbg"
	"net"
	"os"
	"strconv"
	"sync"
)

const (
	READING = iota
	PROCESSING
)

// struct to ease keeping track of who requires a reply after
// tsm is processed/ aggregated by the TSServer
type MustReplyMessage struct {
	Tsm   BitCoSi.BitCoSiMessage
	To    string // name of reply destination
	Block BitCoSi.TrBlock
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

	Mux        sync.Mutex
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
	NameL            string
	// The channel for closing the connection
	waitClose chan string
	// The port we're listening on
	Port  net.Listener
	rLock sync.Mutex
}

// Creates a new stamp listener one port above the
// address given in nameP
func NewStampListener(nameP string) *StampListener {
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
		sl.Queue = make([][]MustReplyMessage, 2)
		sl.Queue[READING] = make([]MustReplyMessage, 0)
		sl.Queue[PROCESSING] = make([]MustReplyMessage, 0)
		sl.Clients = make(map[string]coconet.Conn)
		sl.waitClose = make(chan string)
		sl.NameL = nameL
		sl.IP = net.IPv4(0, 1, 2, 3)
		sl.PublicKey = "my_cool_key"
		sl.Last_Block = "0"
		sl.transaction_pool = make([]blkparser.Tx, 0)
		sl.blocks = make([]BitCoSi.TrBlock, 0)
		sl.rLock = sync.Mutex{}

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
			dbg.Lvl2("Listening to sign-requests: %p", s)
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
							s.Mux.Lock()
							dbg.Lvlf1("BlockRequest: %v\n", tsm.Type)
							READING := s.READING
							s.Queue[READING] = append(s.Queue[READING],
								MustReplyMessage{Tsm: tsm, To: co.Name()})
							s.Mux.Unlock()

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

// Close shuts down the connection
func (s *StampListener) Close() {
	close(s.waitClose)
	s.Port.Close()
	delete(SLList, s.NameL)
	dbg.Lvl3(s.NameL, "Closing stamplistener done - SLList is", SLList)
}
