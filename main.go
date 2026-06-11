package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type icmp struct {
	icmp_type     uint8
	icmp_code     uint8
	icmp_checksum uint16
	icmp_id       uint16
	icmp_seq      uint16
	icmp_data     []byte
}

type PingStats struct {
	Transmitted int
	Received    int
	TotalTime   time.Duration
}

type InFlightPacket struct {
	TargetIP string
	SentAt   time.Time
}

var (
	flightTracker sync.Map
	globalID      = uint16(os.Getpid() & 0xffff)
	seqCounter    uint32 // Atomic counter
)

func (i *icmp) Seriliaze() []byte {
	// RFC 792
	rawBytes := make([]byte, 8+len(i.icmp_data))

	rawBytes[0] = i.icmp_type
	rawBytes[1] = i.icmp_code
	binary.BigEndian.PutUint16(rawBytes[4:6], i.icmp_id)
	binary.BigEndian.PutUint16(rawBytes[6:8], i.icmp_seq)
	copy(rawBytes[8:], i.icmp_data)

	i.icmp_checksum = i.calculateCheckSum(rawBytes)

	binary.BigEndian.PutUint16(rawBytes[2:4], i.icmp_checksum)

	return rawBytes
}

func (i *icmp) calculateCheckSum(buf []byte) uint16 {

	var sum uint32
	length := len(buf)

	for j := 0; j < length-1; j += 2 {
		word := uint32(buf[j])<<8 | uint32(buf[j+1])
		sum += word
	}

	if length%2 != 0 {
		sum += uint32(buf[length-1]) << 8
	}

	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo go run main.go <target_ip>")
		return
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Printf("Socket creation failed (Are you root?): %v\n", err)
		return
	}
	defer syscall.Close(fd)

	stats := &PingStats{}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)

	go func() {
		<-sigChan

		fmt.Printf("\n--- PING Statistics ---\n")
		fmt.Printf("%d packets transmitted, %d received\n", stats.Transmitted, stats.Received)

		if stats.Transmitted > 0 {
			loss := ((stats.Transmitted - stats.Received) * 100) / stats.Transmitted
			fmt.Printf("%d%% packet loss\n", loss)
		}
		if stats.Received > 0 {
			avg := stats.TotalTime / time.Duration(stats.Received)
			fmt.Printf("Average Round-Trip Time: %v\n", avg)
		}
		os.Exit(0)
	}()

	stats.Transmitted++

	go func() {
		replybuf := make([]byte, 1500)
		for {
			n, from, err := syscall.Recvfrom(fd, replybuf, 0)
			if err != nil {
				fmt.Println("Request timed out or host unreachable.")
				continue
			}

			recvTime := time.Now()
			ipHeaderLength := int(replybuf[0]&0x0F) * 4
			icmpBytes := replybuf[ipHeaderLength:n]

			if len(icmpBytes) < 8 {
				fmt.Println("Malformed ICMP packet received")
				return
			}

			recvID := binary.BigEndian.Uint16(icmpBytes[4:6])
			recvSeq := binary.BigEndian.Uint16(icmpBytes[6:8])

			if recvID != globalID {
				continue
			}

			if val, ok := flightTracker.Load(recvSeq); ok {
				flight := val.(InFlightPacket)
				flightTracker.Delete(recvSeq)
				duration := recvTime.Sub(flight.SentAt)
				stats.Received++
				stats.TotalTime += duration
				payload := icmpBytes[8:]

				var srcIP string
				if sockaddr, ok := from.(*syscall.SockaddrInet4); ok {
					srcIP = fmt.Sprintf("%d.%d.%d.%d", sockaddr.Addr[0], sockaddr.Addr[1], sockaddr.Addr[2], sockaddr.Addr[3])
				}

				fmt.Printf("[REPLY] Found %-15s | rtt=%v data=%s", srcIP, duration, payload)
			}
		}
	}()
}

func pingWorker(id int, fd int, jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for target := range jobs {
		targetIP := net.ParseIP(target).To4()
		if targetIP == nil {
			ips, err := net.LookupIP(target)
			if err != nil {
				fmt.Printf("[Worker %d] Failed to resolve host %s\n", id, target)
				continue
			}
			for _, ip := range ips {
				if ipv4 := ip.To4(); ipv4 != nil {
					targetIP = ipv4
					break
				}
			}
		}
		var addr [4]byte
		copy(addr[:], targetIP)
		sockAddr := &syscall.SockaddrInet4{
			Port: 0,
			Addr: addr,
		}
		seq := uint16(atomic.AddUint32(&seqCounter, 1) & 0xffff)

		packet := &icmp{
			icmp_type: 8,
			icmp_code: 0,
			icmp_id:   globalID,
			icmp_seq:  seq,
			icmp_data: []byte("Mechanical sympathy"),
		}

		rawBytes := packet.Seriliaze()

		flightTracker.Store(seq, InFlightPacket{
			TargetIP: targetIP.String(),
			SentAt:   time.Now(),
		})

		fmt.Printf("PING %s...\n", targetIP.String())
		fmt.Printf("[Worker %d] SEND -> %-15s (seq=%d)\n", id, targetIP.String(), seq)
		err := syscall.Sendto(fd, rawBytes, 0, sockAddr)
		if err != nil {
			fmt.Printf("[Worker %d] Error sending to %s: %v\n", id, target, err)
			flightTracker.Delete(seq)
		}

		time.Sleep(10 * time.Millisecond)
	}
}
