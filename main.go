package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
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

	targetIP := net.ParseIP(os.Args[1]).To4()
	if targetIP == nil {
		fmt.Println("Invalid Ipv4 address")
		return
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Printf("Socket creation failed (Are you root?): %v\n", err)
		return
	}
	defer syscall.Close(fd)

	var addr [4]byte
	copy(addr[:], targetIP)
	sockAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: addr,
	}

	packet := &icmp{
		icmp_type: 8,
		icmp_code: 0,
		icmp_id:   uint16(os.Getpid() & 0xffff),
		icmp_data: []byte("Mechanical sympathy"),
	}
	fmt.Printf("PING %s...\n", targetIP.String())

	for seq := 1; ; seq++ {
		packet.icmp_seq = uint16(seq)
		rawBytes := packet.Seriliaze()

		startTime := time.Now()
		err = syscall.Sendto(fd, rawBytes, 0, sockAddr)
		if err != nil {
			fmt.Printf("failed to send packet: %v\n", err)
			return
		}

		replybuf := make([]byte, 1024)
		n, from, err := syscall.Recvfrom(fd, replybuf, 0)
		if err != nil {
			fmt.Println("Request timed out or host unreachable.")
			return
		}
		duration := time.Since(startTime)

		ipHeaderLength := int(replybuf[0]&0x0F) * 4
		icmpBytes := replybuf[ipHeaderLength:n]

		if len(icmpBytes) < 8 {
			fmt.Println("Malformed ICMP packet received")
			return
		}

		responseType := icmpBytes[0]
		responseCode := icmpBytes[1]
		payload := icmpBytes[8:]

		var srcIP string
		if sockaddr, ok := from.(*syscall.SockaddrInet4); ok {
			srcIP = fmt.Sprintf("%d.%d.%d.%d", sockaddr.Addr[0], sockaddr.Addr[1], sockaddr.Addr[2], sockaddr.Addr[3])
		}

		fmt.Printf("Reply from %s: seq=%d type=%d code=%d time=%d payload=%q\n",
			srcIP, seq, responseType, responseCode, duration, string(payload))
		time.Sleep(1 * time.Second)
	}
}
