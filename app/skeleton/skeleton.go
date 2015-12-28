package main

import (
	"github.com/dedis/cothority/lib/app"
	//"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/monitor"
	//"github.com/dedis/cothority/lib/sign"
	"time"
)

// This file is the first draft to a skeleton app where you have all the
// basics to run your own cothority tree. This include the main where you handle
// the configuration + the "running" part. It also include a basic Round
// structure that does nothing yet (up to you). This round will be executed for
// each round of the cothority tree.
// This skeleton is for use with the deploy/ lib, that can deploy on localhost
// or on deterlab. This is not intented to be used as a standalone app. For this
// check the app/conode folder which contains everything to run a standalone
// app. Here all the configuration of the tree, public keys, deployement, etc is
// automatically done. You can make some measurements with the monitor/ library.
// It will create a .csv file in deploy/test_data with the same name of the
// simulation file you wrote. Take a look at some simulation files to get an
// idea on how it is working. Please note that this a first draft for this
// current version of the API and a lot of changes will be brought along the
// next months, so of course there's a lot of things that are not ideal, we know
// that ;).

// To run this skeleton app, go to deploy:
// go build && ./deploy -debug 2 simulations/skeleton.toml
var peer *Peer

func main() {
	// First, let's read our config
	// YOu should create your own config in lib/app.
	// TOML is a pretty simple and readable format
	// Whatever information needed, supply it in the simulation/.toml file that
	// will be parsed into your ConfigSkeleton struct.
	conf := &app.ConfigSkeleton{}
	app.ReadConfig(conf)

	// we must know who we are
	if app.RunFlags.Hostname == "" {
		dbg.Fatal("Hostname empty: Abort")
	}

	// Do some common setup
	if app.RunFlags.Mode == "client" {
		app.RunFlags.Hostname = app.RunFlags.Name
	}
	hostname := app.RunFlags.Hostname
	// i.e. we are root
	if hostname == conf.Hosts[0] {
		dbg.Lvlf3("Tree is %+v", conf.Tree)
	}
	dbg.Lvl3(hostname, "Starting to run")

	// Connect to the monitor process. This monitor process is run on your
	// machine and accepts connections from any node, usually you only connect
	// with the root for readability and performance reason (don't connect to
	// your machine from 8000 nodes .. !)
	if app.RunFlags.Monitor != "" {
		monitor.ConnectSink(app.RunFlags.Monitor)
	} else {
		dbg.Fatal("No logger specified")
	}

	// Here you create a "Peer",that's the struct that will create a new round
	// each seconds and handle other subtleties for you

	peer = NewPeer(hostname, conf.ConfigConode)
	NewStampListener(peer.Name(), false)
	time.Sleep(1 * time.Second) //give time to load transactions
	// The root waits everyones to be up
	if app.RunFlags.AmRoot {
		err := peer.WaitRoundSetup(len(conf.Hosts), 5, 2)
		if err != nil {
			dbg.Fatal(err)
		}
		dbg.Lvl1("Starting the rounds")
	}
	if peer.IsRoot(0) {
		node := new(Node)
		node.run()
	}
	//lock.Lock()
	peer.LoopRounds(RoundPrepareType, RoundCommitType, 20)

	//dbg.LLvl1("Finish Micro")

	//lock.Unlock()

	// Notify we finished to monitor so that the simulation can be stopped
	monitor.End()
}
