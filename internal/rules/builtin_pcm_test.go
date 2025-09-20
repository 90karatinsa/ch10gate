package rules

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestFixPCMAlignUpdatesHeaderAndFiller(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pcm.ch10")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	dataLen := 4
	fillerLen := 4
	totalLen := ch10PrimaryHeaderSize + dataLen + fillerLen
	packetLen := uint32(totalLen - 4)

	header := make([]byte, ch10PrimaryHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], 0xEB25)
	binary.BigEndian.PutUint16(header[2:4], 0x0001)
	binary.BigEndian.PutUint32(header[4:8], packetLen)
	binary.BigEndian.PutUint32(header[8:12], uint32(dataLen))
	binary.BigEndian.PutUint16(header[12:14], 0x0008)
	header[14] = 0x00
	header[15] = 0x00
	if _, err := f.Write(header); err != nil {
		t.Fatalf("write header failed: %v", err)
	}

	csdw := uint32(0)
	csdw |= 1 << 31
	csdw |= 1 << 30
	csdw |= 1 << 29
	csdw |= 1 << 28
	csdw |= uint32(3) << 26
	csdw |= uint32(2) << 24
	csdw |= uint32(2) << 22
	csdw |= 1 << 20
	csdw |= 1 << 19
	csdw |= 5

	var csdwBuf [4]byte
	binary.BigEndian.PutUint32(csdwBuf[:], csdw)
	if _, err := f.Write(csdwBuf[:]); err != nil {
		t.Fatalf("write csdw failed: %v", err)
	}

	filler := []byte{0x12, 0x34, 0x56, 0x78}
	if _, err := f.Write(filler); err != nil {
		t.Fatalf("write filler failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	ctx := &Context{InputFile: path, Profile: "106-15"}
	rule := Rule{RuleId: "RP-0010", Refs: []string{"ref"}}
	diag, applied, err := FixPCMAlign(ctx, rule)
	if err != nil {
		t.Fatalf("FixPCMAlign returned error: %v", err)
	}
	if !applied {
		t.Fatalf("FixPCMAlign did not apply fix")
	}
	if diag.PacketIndex != 0 {
		t.Fatalf("PacketIndex = %d, want 0", diag.PacketIndex)
	}
	if diag.ChannelId != 1 {
		t.Fatalf("ChannelId = %d, want 1", diag.ChannelId)
	}
	if diag.Offset != "0x0" {
		t.Fatalf("Offset = %s, want 0x0", diag.Offset)
	}
	expectedMsg := "fixed PCM alignment on 1 packet(s) (1 header, 1 filler)"
	if diag.Message != expectedMsg {
		t.Fatalf("message = %q, want %q", diag.Message, expectedMsg)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(data) < totalLen {
		t.Fatalf("file length = %d, want >= %d", len(data), totalLen)
	}
	gotCsdw := binary.BigEndian.Uint32(data[ch10PrimaryHeaderSize : ch10PrimaryHeaderSize+4])
	if gotCsdw != (uint32(1) << 20) {
		t.Fatalf("CSDW = 0x%X, want 0x%X", gotCsdw, uint32(1)<<20)
	}
	for i := 0; i < fillerLen; i++ {
		if data[ch10PrimaryHeaderSize+4+i] != 0x00 {
			t.Fatalf("filler byte %d = 0x%X, want 0x00", i, data[ch10PrimaryHeaderSize+4+i])
		}
	}
}
