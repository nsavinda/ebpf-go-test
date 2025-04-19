package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}

	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load objects: %v", err)
	}
	defer objs.Close()

	ifname := "enp0s3"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("failed to get interface %s: %v", ifname, err)
	}

	// Attach the counter program to the interface
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("AttachXDP failed:", err)
	}
	defer link.Close()

	log.Printf("Attached XDP program to interface %s", ifname)

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Printf("failed to lookup packet count: %v", err)
				continue
			}
			log.Printf("Packet count: %d", count)
		case <-stop:
			log.Print("Received interrupt signal, exiting...")
			return
		}
	}

}
