package examples_test

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"example.com/ch10gate/internal/ch10"
)

const primaryHeaderSize = 20

func buildMinimalPacket(t *testing.T, profile string, channel uint16, dataType uint16, seq uint8, flags uint8, secHdr, payload []byte) []byte {
	t.Helper()
	total := primaryHeaderSize + len(secHdr) + len(payload)
	header := make([]byte, primaryHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], 0xEB25)
	binary.BigEndian.PutUint16(header[2:4], channel)
	binary.BigEndian.PutUint32(header[4:8], uint32(total-4))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(secHdr)+len(payload)))
	binary.BigEndian.PutUint16(header[12:14], dataType)
	header[14] = seq
	header[15] = flags
	checksum, err := ch10.ComputeHeaderChecksum(profile, header)
	if err != nil {
		t.Fatalf("ComputeHeaderChecksum: %v", err)
	}
	binary.BigEndian.PutUint16(header[16:18], checksum)
	packet := make([]byte, total)
	copy(packet, header)
	offset := primaryHeaderSize
	if len(secHdr) > 0 {
		copy(packet[offset:], secHdr)
		offset += len(secHdr)
	}
	if len(payload) > 0 {
		copy(packet[offset:], payload)
	}
	return packet
}

func TestSyntheticChapter10Generator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.ch10")

	timePkt, err := ch10.BuildTimePacket("106-15", 1, 0x00, 1_000_000)
	if err != nil {
		t.Fatalf("BuildTimePacket: %v", err)
	}
	dynamic := buildMinimalPacket(t, "106-15", 2, 0x08, 0, 0, nil, []byte{0xAA, 0xBB, 0xCC, 0xDD})
	sec := make([]byte, 12)
	binary.BigEndian.PutUint32(sec[0:4], 500_000)
	binary.BigEndian.PutUint32(sec[4:8], 2)
	withSec := buildMinimalPacket(t, "106-15", 3, 0x08, 1, 0x80, sec, []byte{0x01, 0x02})

	data := append(timePkt, dynamic...)
	data = append(data, withSec...)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	reader, err := ch10.NewReader(path)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer reader.Close()
	var packets []ch10.PacketIndex
	for {
		_, idx, err := reader.Next()
		if err == nil {
			packets = append(packets, idx)
			continue
		}
		if err == io.EOF {
			break
		}
		t.Fatalf("reader.Next: %v", err)
	}
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}
	if !packets[0].IsTimePacket {
		t.Fatalf("first packet should be time, got %+v", packets[0])
	}
	if packets[1].ChannelID != 2 || packets[1].HasSecHdr {
		t.Fatalf("second packet unexpected: %+v", packets[1])
	}
	if !packets[2].HasSecHdr {
		t.Fatalf("third packet missing secondary header: %+v", packets[2])
	}
	index := reader.Index()
	if len(index.Packets) != 3 {
		t.Fatalf("index expected 3 packets, got %d", len(index.Packets))
	}
}
