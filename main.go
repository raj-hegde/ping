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
	icmp_data     []byte
}

func newICMP(packetType uint8, code uint8, data []byte) []byte {
	pkt := &icmp{
		icmp_type: packetType,
		icmp_code: code,
		icmp_data: data,
	}
	pkt.icmp_checksum = pkt.calculateCheckSum()
	// RFC 792

	rawBytes := make([]byte, 4+len(pkt.icmp_data))
	rawBytes[0] = pkt.icmp_type
	rawBytes[1] = pkt.icmp_code
	binary.BigEndian.PutUint16(rawBytes[2:4], uint16(pkt.icmp_checksum))
	copy(rawBytes[4:], pkt.icmp_data)

	return rawBytes
}

func (i *icmp) calculateCheckSum() uint16 {
	buf := make([]byte, 4+len(i.icmp_data))

	buf[0] = i.icmp_type
	buf[1] = i.icmp_code
	buf[2] = 0
	buf[3] = 0

	copy(buf[4:], i.icmp_data)

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

	packet := newICMP(8, 0, []byte("Mechanical sympathy"))

	var addr [4]byte
	copy(addr[:], targetIP)
	sockAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: addr,
	}

	startTime := time.Now()
	err = syscall.Sendto(fd, packet, 0, sockAddr)
	if err != nil {
		fmt.Printf("failed to send packet: %v\n", err)
		return
	}

	replybuf := make([]byte, 1024)
	n, _, err := syscall.Recvfrom(fd, replybuf, 0)
	if err != nil {
		fmt.Println("Request timed out or host unreachable.")
		return
	}
	duration := time.Since(startTime)
	fmt.Printf("Packet received in %d with length %d\n", duration, n)
	fmt.Println(string(replybuf))

	// ipHeaderLength := int(replybuf[0]&0x0F) * 4
	// icmpPayload := replybuf[ipHeaderLength:n]

	// if len(icmpPayload) < 8 {
	// 	fmt.Println("Malformed ICMP packer received")
	// 	return
	// }

	// responseType := icmpPayload[0]
	// responseCode := icmpPayload[1]

}
