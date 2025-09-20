package rules

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"example.com/ch10gate/internal/ch10"
	"example.com/ch10gate/internal/eth"
)

func writePrimaryHeader(t *testing.T, dataType uint16, dataLen int, flags uint8) []byte {
	t.Helper()
	total := ch10PrimaryHeaderSize + dataLen
	hdr := make([]byte, ch10PrimaryHeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], 0xEB25)
	binary.BigEndian.PutUint16(hdr[2:4], 1)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(total-4))
	binary.BigEndian.PutUint32(hdr[8:12], uint32(dataLen))
	binary.BigEndian.PutUint16(hdr[12:14], dataType)
	hdr[14] = 0
	hdr[15] = flags
	chk, err := ch10.ComputeHeaderChecksum("106-15", hdr)
	if err != nil {
		t.Fatalf("checksum: %v", err)
	}
	binary.BigEndian.PutUint16(hdr[16:18], chk)
	return hdr
}

func TestAddEthIPHInsertsMissingHeader(t *testing.T) {
	t.Parallel()
	frame := make([]byte, 0, 64)
	// Ethernet header
	frame = append(frame, []byte{
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
		0x08, 0x00,
	}...)
	// IPv4 header (incorrect checksum will be recomputed later if needed)
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], 32)
	ip[6] = 0
	ip[7] = 0
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 2})
	ip[10] = 0
	ip[11] = 0
	csum := eth.IPv4HeaderChecksum(ip)
	binary.BigEndian.PutUint16(ip[10:12], csum)
	frame = append(frame, ip...)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 0x1111)
	binary.BigEndian.PutUint16(udp[2:4], 0x2222)
	binary.BigEndian.PutUint16(udp[4:6], 12)
	// leave checksum zero
	frame = append(frame, udp...)
	frame = append(frame, []byte{0xDE, 0xAD, 0xBE, 0xEF}...)

	csdw := make([]byte, 4)
	binary.BigEndian.PutUint32(csdw, 0x00000001)
	body := append(csdw, frame...)

	hdr := writePrimaryHeader(t, 0x50, len(body), 0)
	fileData := append(hdr, body...)

	dir := t.TempDir()
	inPath := filepath.Join(dir, "eth_missing.ch10")
	if err := os.WriteFile(inPath, fileData, 0644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	ctx := &Context{InputFile: inPath, Profile: "106-15"}
	rule := Rule{RuleId: "RP-0015"}
	diag, applied, err := AddEthIPH(ctx, rule)
	if err != nil {
		t.Fatalf("AddEthIPH error: %v", err)
	}
	if !applied || !diag.FixApplied {
		t.Fatalf("expected fix applied, diag=%+v", diag)
	}
	outPath := inPath + ".fixed.ch10"
	if diag.FixPatchId != filepath.Base(outPath) {
		t.Fatalf("unexpected FixPatchId %q", diag.FixPatchId)
	}
	out, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read fixed: %v", err)
	}
	if len(out) <= len(fileData) {
		t.Fatalf("expected larger file after insertion")
	}
	newDataLen := binary.BigEndian.Uint32(out[8:12])
	if newDataLen != uint32(len(body)+12) {
		t.Fatalf("unexpected data length %d", newDataLen)
	}
	newPacketLen := binary.BigEndian.Uint32(out[4:8])
	if newPacketLen != uint32(ch10PrimaryHeaderSize+len(body)+12-4) {
		t.Fatalf("unexpected packet length %d", newPacketLen)
	}
	// Verify inserted IPH
	bodyStart := ch10PrimaryHeaderSize
	iph := out[bodyStart+4 : bodyStart+16]
	frameID := binary.BigEndian.Uint32(iph[8:12]) & 0x3FFF
	if int(frameID) != len(frame) {
		t.Fatalf("frame length mismatch: %d vs %d", frameID, len(frame))
	}
	// Ensure checksum updated
	chk, err := ch10.ComputeHeaderChecksum("106-15", out[:ch10PrimaryHeaderSize])
	if err != nil {
		t.Fatalf("checksum compute: %v", err)
	}
	stored := binary.BigEndian.Uint16(out[16:18])
	if chk != stored {
		t.Fatalf("header checksum mismatch: got %04X want %04X", stored, chk)
	}
}

func TestFixA664LensRepairsLengths(t *testing.T) {
	t.Parallel()
	payloadLen := 4
	body := make([]byte, 0, 96)
	csdw := uint32(0x00180001)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, csdw)
	body = append(body, tmp...)
	iph := make([]byte, 24)
	word1 := uint32(payloadLen << 16)
	binary.BigEndian.PutUint32(iph[8:12], word1)
	copy(iph[12:16], []byte{0, 0, 0, 1})
	copy(iph[16:20], []byte{0, 0, 0, 2})
	copy(iph[20:24], []byte{0x12, 0x34, 0x56, 0x78})
	body = append(body, iph...)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 64)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{0, 0, 0, 1})
	copy(ip[16:20], []byte{0, 0, 0, 2})
	ip[10] = 0
	ip[11] = 0
	csum := eth.IPv4HeaderChecksum(ip)
	binary.BigEndian.PutUint16(ip[10:12], csum)
	body = append(body, ip...)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 0x1234)
	binary.BigEndian.PutUint16(udp[2:4], 0x5678)
	binary.BigEndian.PutUint16(udp[4:6], 20)
	binary.BigEndian.PutUint16(udp[6:8], 0xFFFF)
	body = append(body, udp...)
	body = append(body, []byte{0xCA, 0xFE, 0xBA, 0xBE}...)

	hdr := writePrimaryHeader(t, 0x51, len(body), 0)
	data := append(hdr, body...)

	dir := t.TempDir()
	inPath := filepath.Join(dir, "a664_bad.ch10")
	if err := os.WriteFile(inPath, data, 0644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	ctx := &Context{InputFile: inPath, Profile: "106-15"}
	rule := Rule{RuleId: "RP-0016"}
	diag, applied, err := FixA664Lens(ctx, rule)
	if err != nil {
		t.Fatalf("FixA664Lens error: %v", err)
	}
	if !applied || !diag.FixApplied {
		t.Fatalf("expected fix applied, diag=%+v", diag)
	}

	out, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	bodyStart := ch10PrimaryHeaderSize
	// Skip CSDW and IPH
	ipv4Offset := bodyStart + 4 + 24
	udpOffset := ipv4Offset + 20
	totalLen := binary.BigEndian.Uint16(out[ipv4Offset+2 : ipv4Offset+4])
	if totalLen != uint16(20+8+payloadLen) {
		t.Fatalf("unexpected ipv4 total length %d", totalLen)
	}
	udpLen := binary.BigEndian.Uint16(out[udpOffset+4 : udpOffset+6])
	if udpLen != uint16(8+payloadLen) {
		t.Fatalf("unexpected udp length %d", udpLen)
	}
	ipv4Hdr := make([]byte, 20)
	copy(ipv4Hdr, out[ipv4Offset:ipv4Offset+20])
	ipv4Hdr[10] = 0
	ipv4Hdr[11] = 0
	wantIPCS := eth.IPv4HeaderChecksum(ipv4Hdr)
	gotIPCS := binary.BigEndian.Uint16(out[ipv4Offset+10 : ipv4Offset+12])
	if wantIPCS != gotIPCS {
		t.Fatalf("ipv4 checksum mismatch: got %04X want %04X", gotIPCS, wantIPCS)
	}
	udpSeg := make([]byte, 8+payloadLen)
	copy(udpSeg, out[udpOffset:udpOffset+8+payloadLen])
	udpSeg[6] = 0
	udpSeg[7] = 0
	wantUDPCS := eth.UDPChecksum(ipv4Hdr, udpSeg)
	if wantUDPCS == 0 {
		wantUDPCS = 0xFFFF
	}
	gotUDPCS := binary.BigEndian.Uint16(out[udpOffset+6 : udpOffset+8])
	if gotUDPCS != wantUDPCS {
		t.Fatalf("udp checksum mismatch: got %04X want %04X", gotUDPCS, wantUDPCS)
	}
}
