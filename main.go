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
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type PingEvent struct {
	SrcIP uint32
	RttNs uint64
	Seq   uint16
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock rlimit: %v", err)
	}
	if len(os.Args) < 2 {
		fmt.Println("USAGE: ping <ip_address>")
		os.Exit(0)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	targetIp, err := net.LookupIP(os.Args[1])
	if err != nil || len(targetIp) == 0 {
		log.Fatalf("Error: Demanded target hostname '%s' could not be resolved: %v", os.Args[1], err)
	}
	dstIP := targetIp[0].To4()
	if dstIP == nil {
		log.Fatalf("Error: eBPF monitoring code currently only supports IPv4 targets.")
	}

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

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		log.Fatalf("Privilege Error: Failed to open raw system network sockets: %v", err)
	}
	defer syscall.Close(fd)

	var dstAddr syscall.SockaddrInet4
	copy(dstAddr.Addr[:], dstIP)

	fmt.Printf("EBPF-PING %s (%s) on %s interface:\n", targetIp[0], dstIP.String(), ifaceName)

	seaqTracker := 1
	for i := 0; i < 4; i++ {
		echoMsg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  seaqTracker,
				Data: []byte("This is a ping request"),
			},
		}

		binBytes, err := echoMsg.Marshal(nil)
		if err != nil {
			log.Printf("Internal error serializing packet layoutL %v", err)
			continue
		}

		if err := syscall.Sendto(fd, binBytes, 0, &dstAddr); err != nil {
			log.Printf("Network Error: Failed to broadcast packet sequence: %v", err)
		}
		seaqTracker++
	}
	<-stopper
	fmt.Println("\nDetaching XDP program and exiting safely.")
}
