package main

type icmp struct {
	icmp_type     uint8
	icmp_code     uint8
	icmp_checksum uint16
	icmp_data     []byte
}

func newICMP(packetType uint8, code uint8, data []byte) *icmp {
	pkt := &icmp{
		icmp_type: packetType,
		icmp_code: code,
		icmp_data: data,
	}
	pkt.icmp_checksum = pkt.calculateCheckSum()
	// RFC 792
	return pkt
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
	for j := 0; j < length; j += 2 {
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
}
