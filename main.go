package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type PingEvent struct {
	SrcIP uint32
	RttNs uint64
	Seq   uint16
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ifaceName := "wlp1s0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to find interface %s: %v", ifaceName, err)
	}

	spec, err := ebpf.LoadCollectionSpec("ping.bpf.o")
	if err != nil {
		log.Fatalf("failed to load eBPF bytecode: %v", err)
	}

	var objs struct {
		Prog          *ebpf.Program `ebpf:"monitor_icmp"`
		FlightTracker *ebpf.Map     `ebpf:"flight_tracker"`
		Events        *ebpf.Map     `ebpf:"packet_events"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load maps and programs into kernel: %v", err)
	}
	defer objs.Prog.Close()
	defer objs.FlightTracker.Close()
	defer objs.Events.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("failed to attach XDP program: %v", err)
	}
	defer l.Close()

	fmt.Printf("Successfully attached XDP program to %s. Listening for ICMP events....\n", ifaceName)

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("failed to create perf ring buffer reader: %v", err)
	}
	defer rd.Close()

	go func() {
		var event PingEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("error reading from perf ring buffer: %v", err)
				continue
			}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("failed to parse raw byte stream: %v", err)
				continue
			}

			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, event.SrcIP)
			srcIp := net.IP(ipBytes).String()
			rttMs := float64(event.RttNs) / 1000000.0

			fmt.Printf("[eBPF Trace] Reply from %s: seq=%d time=%.3f ms\n", srcIp, event.Seq, rttMs)
		}
	}()

	<-stopper
	fmt.Println("\nDetaching XDP program and exiting safely.")
}
