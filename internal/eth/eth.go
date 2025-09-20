package eth

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrFrameTooShort   = errors.New("ethernet frame too short")
	ErrIPv4Header      = errors.New("invalid ipv4 header")
	ErrUnsupportedType = errors.New("unsupported ether type for length inference")
	ErrUDPPacket       = errors.New("invalid udp segment")
)

// ParseEthernet parses an Ethernet II frame beginning at buf and returns
// metadata about the frame. The returned frameLen is the number of bytes
// comprising the captured frame (excluding any trailing data beyond the
// frame). The parser currently supports Ethernet II frames with optional
// 802.1Q VLAN tagging.
func ParseEthernet(buf []byte) (hasVLAN bool, etherType uint16, l2HdrLen int, payloadOff int, frameLen int, err error) {
	if len(buf) < 14 {
		return false, 0, 0, 0, 0, ErrFrameTooShort
	}
	headerLen := 14
	etherType = binary.BigEndian.Uint16(buf[12:14])
	if etherType == 0x8100 {
		if len(buf) < 18 {
			return false, 0, 0, 0, 0, ErrFrameTooShort
		}
		hasVLAN = true
		headerLen = 18
		etherType = binary.BigEndian.Uint16(buf[16:18])
	}
	payloadOff = headerLen
	l2HdrLen = headerLen

	switch {
	case etherType <= 1500:
		payloadLen := int(etherType)
		frameLen = headerLen + payloadLen
	case etherType == 0x0800:
		if len(buf) < headerLen+20 {
			return hasVLAN, etherType, headerLen, payloadOff, 0, ErrFrameTooShort
		}
		_, totalLen, _, _, _, _, perr := ParseIPv4(buf[headerLen:])
		if perr != nil {
			return hasVLAN, etherType, headerLen, payloadOff, 0, perr
		}
		frameLen = headerLen + totalLen
	default:
		return hasVLAN, etherType, headerLen, payloadOff, 0, fmt.Errorf("%w: 0x%04X", ErrUnsupportedType, etherType)
	}

	if frameLen > len(buf) {
		return hasVLAN, etherType, headerLen, payloadOff, 0, fmt.Errorf("frame length %d exceeds buffer (%d)", frameLen, len(buf))
	}
	return hasVLAN, etherType, headerLen, payloadOff, frameLen, nil
}

// ParseIPv4 parses an IPv4 header from buf and returns the header length, total
// length, transport protocol, source/destination addresses, and the header
// offset (which is always zero for the provided slice).
func ParseIPv4(buf []byte) (ihl int, totalLen int, proto uint8, src, dst [4]byte, hdrOff int, err error) {
	if len(buf) < 20 {
		err = ErrIPv4Header
		return
	}
	version := buf[0] >> 4
	if version != 4 {
		err = ErrIPv4Header
		return
	}
	ihl = int(buf[0]&0x0F) * 4
	if ihl < 20 || len(buf) < ihl {
		err = ErrIPv4Header
		return
	}
	totalLen = int(binary.BigEndian.Uint16(buf[2:4]))
	if totalLen < ihl {
		err = ErrIPv4Header
		return
	}
	proto = buf[9]
	copy(src[:], buf[12:16])
	copy(dst[:], buf[16:20])
	hdrOff = 0
	return
}

// ParseUDP parses a UDP header from buf, where buf should start at the IPv4
// header. The ipOff argument specifies the length of the IPv4 header. The
// returned udpOff is the offset within buf to the UDP header.
func ParseUDP(buf []byte, ipOff int) (srcPort, dstPort, length, checksum uint16, udpOff int, err error) {
	if ipOff < 0 || len(buf) < ipOff+8 {
		err = ErrUDPPacket
		return
	}
	udpOff = ipOff
	if len(buf) < udpOff+8 {
		err = ErrUDPPacket
		return
	}
	srcPort = binary.BigEndian.Uint16(buf[udpOff : udpOff+2])
	dstPort = binary.BigEndian.Uint16(buf[udpOff+2 : udpOff+4])
	length = binary.BigEndian.Uint16(buf[udpOff+4 : udpOff+6])
	checksum = binary.BigEndian.Uint16(buf[udpOff+6 : udpOff+8])
	return
}

// IPv4HeaderChecksum computes the RFC 791 header checksum for the provided
// IPv4 header bytes. The caller must ensure the checksum field within the
// header is zeroed prior to invoking this function.
func IPv4HeaderChecksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		word := binary.BigEndian.Uint16(b[i : i+2])
		sum += uint32(word)
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum & 0xFFFF)
}

// UDPChecksum computes the UDP checksum for an IPv4 packet using the provided
// IPv4 header and UDP header+payload slice. The IPv4 header must contain at
// least 20 bytes and the UDP slice must contain at least the 8-byte header.
func UDPChecksum(ipHdr, udp []byte) uint16 {
	if len(ipHdr) < 20 || len(udp) < 8 {
		return 0
	}
	var sum uint32
	pseudo := []byte{
		ipHdr[12], ipHdr[13], ipHdr[14], ipHdr[15],
		ipHdr[16], ipHdr[17], ipHdr[18], ipHdr[19],
		0, ipHdr[9], byte(len(udp) >> 8), byte(len(udp)),
	}
	for i := 0; i < len(pseudo); i += 2 {
		word := binary.BigEndian.Uint16(pseudo[i : i+2])
		sum += uint32(word)
	}
	for i := 0; i+1 < len(udp); i += 2 {
		word := binary.BigEndian.Uint16(udp[i : i+2])
		sum += uint32(word)
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum & 0xFFFF)
}
