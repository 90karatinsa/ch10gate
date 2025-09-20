package rules

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.com/ch10gate/internal/ch10"
	"example.com/ch10gate/internal/tmats"
)

func TestEnsureTimePacketMissingTime(t *testing.T) {
	dir := t.TempDir()
	ch10Path := filepath.Join(dir, "input.ch10")
	writeChapter10File(t, ch10Path, buildPCMPacket(t, 2, 0))
	tmatsPath := filepath.Join(dir, "input.tmats")
	writeTMATSFile(t, tmatsPath)

	ctx := &Context{InputFile: ch10Path, TMATSFile: tmatsPath, Profile: "106-15"}
	rule := Rule{RuleId: "RP-0009", Refs: []string{"ref"}}
	diag, applied, err := EnsureTimePacket(ctx, rule)
	if err != nil {
		t.Fatalf("EnsureTimePacket returned error: %v", err)
	}
	if !applied {
		t.Fatalf("expected fix to be applied")
	}
	if diag.Severity != INFO {
		t.Fatalf("severity = %s, want INFO", diag.Severity)
	}
	if !strings.Contains(diag.Message, "inserted time reference packet") {
		t.Fatalf("message = %q, want insertion notice", diag.Message)
	}
	if diag.TimestampSource == nil || *diag.TimestampSource != string(ch10.TimestampSourceTimePacket) {
		t.Fatalf("timestamp source = %v, want time_packet", diag.TimestampSource)
	}

	outPath := ch10Path + ".fixed.ch10"
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected fixed Chapter 10 file: %v", err)
	}

	tmatsOut := tmatsPath + ".tmats.fixed"
	if _, err := os.Stat(tmatsOut); err != nil {
		t.Fatalf("expected fixed TMATS file: %v", err)
	}
	doc, err := tmats.Parse(tmatsOut)
	if err != nil {
		t.Fatalf("parse fixed TMATS: %v", err)
	}
	group := inferTMATSRecordGroup(doc)
	if val, ok := doc.Get(fmt.Sprintf("%s\\RI3", group)); !ok || val != "MODIFIED" {
		t.Fatalf("RI3 not updated, got %q", val)
	}
	if val, ok := doc.Get(fmt.Sprintf("%s\\RI6", group)); !ok || !strings.Contains(val, "Inserted time packet") {
		t.Fatalf("RI6 detail missing, got %q", val)
	}
	foundComment := false
	for _, c := range doc.Comments() {
		if strings.Contains(c, rule.RuleId) {
			foundComment = true
			break
		}
	}
	if !foundComment {
		t.Fatalf("expected comment referencing rule id")
	}
}

func TestEnsureTimePacketFixesWhenDynamicBeforeTime(t *testing.T) {
	dir := t.TempDir()
	ch10Path := filepath.Join(dir, "input.ch10")
	dynamic := buildPCMPacket(t, 3, 0)
	timePkt, err := ch10.BuildTimePacket("106-15", 5, 0x00, 1_000_000)
	if err != nil {
		t.Fatalf("build time packet: %v", err)
	}
	writeChapter10File(t, ch10Path, dynamic, timePkt)
	tmatsPath := filepath.Join(dir, "input.tmats")
	writeTMATSFile(t, tmatsPath)

	ctx := &Context{InputFile: ch10Path, TMATSFile: tmatsPath, Profile: "106-15"}
	rule := Rule{RuleId: "RP-0009"}
	diag, applied, err := EnsureTimePacket(ctx, rule)
	if err != nil {
		t.Fatalf("EnsureTimePacket returned error: %v", err)
	}
	if !applied {
		t.Fatalf("expected fix to be applied")
	}
	if diag.PacketIndex != 0 {
		t.Fatalf("PacketIndex = %d, want 0", diag.PacketIndex)
	}
	if diag.ChannelId != 5 {
		t.Fatalf("ChannelId = %d, want 5", diag.ChannelId)
	}
	if diag.TimestampUs == nil || *diag.TimestampUs != 1_000_000 {
		t.Fatalf("timestamp pointer incorrect: %v", diag.TimestampUs)
	}
	if !strings.Contains(diag.Message, "time packet observed after dynamic data") {
		t.Fatalf("message = %q, want reason for late time", diag.Message)
	}

	outPath := ch10Path + ".fixed.ch10"
	reader, err := ch10.NewReader(outPath)
	if err != nil {
		t.Fatalf("open fixed file: %v", err)
	}
	defer reader.Close()
	if _, idx, err := reader.Next(); err != nil {
		t.Fatalf("reader.Next: %v", err)
	} else if !idx.IsTimePacket {
		t.Fatalf("first packet not time after fix: %+v", idx)
	}
}

func TestEnsureTimePacketReportsMissingSecHeader(t *testing.T) {
	timePkt := ch10.PacketIndex{IsTimePacket: true, TimeStampUs: 1_000_000, Source: ch10.TimestampSourceTimePacket}
	badDyn := ch10.PacketIndex{HasSecHdr: true, SecHdrBytes: false, ChannelID: 3, Offset: 0x60}
	ctx := &Context{
		InputFile: "file.ch10",
		Profile:   "106-15",
		Index: &ch10.FileIndex{
			HasTimePacket:         true,
			TimeSeenBeforeDynamic: true,
			Packets:               []ch10.PacketIndex{timePkt, badDyn},
		},
	}
	diag, applied, err := EnsureTimePacket(ctx, Rule{RuleId: "RP-0009"})
	if err != nil {
		t.Fatalf("EnsureTimePacket returned error: %v", err)
	}
	if applied {
		t.Fatalf("EnsureTimePacket applied fix unexpectedly")
	}
	if diag.Severity != ERROR {
		t.Fatalf("severity = %s, want ERROR", diag.Severity)
	}
	if diag.PacketIndex != 1 {
		t.Fatalf("PacketIndex = %d, want 1", diag.PacketIndex)
	}
	if diag.Message != "secondary header flag set but bytes missing" {
		t.Fatalf("message = %q, want missing secondary header message", diag.Message)
	}
}

func TestEnsureTimePacketInfo(t *testing.T) {
	timePkt := ch10.PacketIndex{IsTimePacket: true, TimeStampUs: 1_234_567, Source: ch10.TimestampSourceTimePacket, ChannelID: 1, Offset: 0x100}
	ctx := &Context{
		InputFile: "file.ch10",
		Profile:   "106-15",
		Index: &ch10.FileIndex{
			HasTimePacket:         true,
			TimeSeenBeforeDynamic: true,
			Packets:               []ch10.PacketIndex{timePkt},
		},
	}
	diag, applied, err := EnsureTimePacket(ctx, Rule{RuleId: "RP-0009"})
	if err != nil {
		t.Fatalf("EnsureTimePacket returned error: %v", err)
	}
	if applied {
		t.Fatalf("EnsureTimePacket applied fix unexpectedly")
	}
	if diag.Severity != INFO {
		t.Fatalf("severity = %s, want INFO", diag.Severity)
	}
	if diag.Message != "time packet present before first dynamic packet" {
		t.Fatalf("message = %q, want success message", diag.Message)
	}
	if diag.TimestampUs == nil || *diag.TimestampUs != timePkt.TimeStampUs {
		t.Fatalf("timestamp pointer incorrect: %v", diag.TimestampUs)
	}
	if diag.TimestampSource == nil || *diag.TimestampSource != string(timePkt.Source) {
		t.Fatalf("timestamp source incorrect: %v", diag.TimestampSource)
	}
}

func TestSyncSecondaryTimeFmtCases(t *testing.T) {
	ctxEmpty := &Context{InputFile: "file.ch10", Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{}}}}
	diag, _, err := SyncSecondaryTimeFmt(ctxEmpty, Rule{RuleId: "RP-0019"})
	if err != nil {
		t.Fatalf("SyncSecondaryTimeFmt returned error: %v", err)
	}
	if diag.Severity != INFO || diag.Message != "no packets with secondary header timestamps" {
		t.Fatalf("unexpected diag for empty index: %+v", diag)
	}

	pkt1 := ch10.PacketIndex{HasSecHdr: true, SecHdrBytes: true, SecHdrValid: true, TimeFormat: 0x00, TimeStampUs: 1_000_000, Source: ch10.TimestampSourceSecondaryHeader, ChannelID: 1, Offset: 0x20}
	pkt2 := ch10.PacketIndex{HasSecHdr: true, SecHdrBytes: true, SecHdrValid: true, TimeFormat: 0x00, TimeStampUs: 1_000_100, Source: ch10.TimestampSourceSecondaryHeader, ChannelID: 2, Offset: 0x40}
	ctxConsistent := &Context{InputFile: "file.ch10", Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{pkt1, pkt2}}}
	diag, _, err = SyncSecondaryTimeFmt(ctxConsistent, Rule{RuleId: "RP-0019"})
	if err != nil {
		t.Fatalf("SyncSecondaryTimeFmt consistent returned error: %v", err)
	}
	if diag.Severity != INFO {
		t.Fatalf("severity = %s, want INFO", diag.Severity)
	}
	if diag.Message != "secondary header time format consistent (0x0)" {
		t.Fatalf("message = %q, want consistent message", diag.Message)
	}
	if diag.TimestampUs == nil || *diag.TimestampUs != pkt1.TimeStampUs {
		t.Fatalf("timestamp pointer incorrect: %v", diag.TimestampUs)
	}

	pkt3 := ch10.PacketIndex{HasSecHdr: true, SecHdrBytes: true, SecHdrValid: true, TimeFormat: 0x04, TimeStampUs: 2_000_000, Source: ch10.TimestampSourceSecondaryHeader, ChannelID: 3, Offset: 0x60}
	ctxMismatch := &Context{InputFile: "file.ch10", Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{pkt1, pkt3}}}
	diag, _, err = SyncSecondaryTimeFmt(ctxMismatch, Rule{RuleId: "RP-0019"})
	if err != nil {
		t.Fatalf("SyncSecondaryTimeFmt mismatch returned error: %v", err)
	}
	if diag.Severity != WARN {
		t.Fatalf("severity = %s, want WARN", diag.Severity)
	}
	if diag.PacketIndex != 1 {
		t.Fatalf("PacketIndex = %d, want 1", diag.PacketIndex)
	}
	wantMsg := "secondary header time formats inconsistent: 0x4 vs 0x0"
	if diag.Message != wantMsg {
		t.Fatalf("message = %q, want %q", diag.Message, wantMsg)
	}
}

func buildPCMPacket(t *testing.T, channel uint16, seq uint8) []byte {
	t.Helper()
	header := make([]byte, ch10PrimaryHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], 0xEB25)
	binary.BigEndian.PutUint16(header[2:4], channel)
	payloadLen := 12
	binary.BigEndian.PutUint32(header[4:8], uint32(ch10PrimaryHeaderSize+payloadLen-4))
	binary.BigEndian.PutUint32(header[8:12], uint32(payloadLen))
	binary.BigEndian.PutUint16(header[12:14], 0x08)
	header[14] = seq
	header[15] = 0
	header[16] = 0
	header[17] = 0
	chk, err := ch10.ComputeHeaderChecksum("106-15", header)
	if err != nil {
		t.Fatalf("ComputeHeaderChecksum: %v", err)
	}
	binary.BigEndian.PutUint16(header[16:18], chk)
	payload := make([]byte, payloadLen)
	packet := make([]byte, len(header)+len(payload))
	copy(packet, header)
	copy(packet[len(header):], payload)
	return packet
}

func writeChapter10File(t *testing.T, path string, packets ...[]byte) {
	t.Helper()
	var buf []byte
	for _, pkt := range packets {
		buf = append(buf, pkt...)
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatalf("write Chapter 10 file: %v", err)
	}
}

func writeTMATSFile(t *testing.T, path string) {
	t.Helper()
	content := "# Test TMATS\nR-1\\CHE-1:1;\nR-1\\CDT-1:PCM;\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write TMATS: %v", err)
	}
}
