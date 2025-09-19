package rules

import (
	"testing"

	"example.com/ch10gate/internal/ch10"
)

func TestEnsureTimePacketMissingTime(t *testing.T) {
	ctx := &Context{InputFile: "file.ch10", Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{}}}}
	rule := Rule{RuleId: "RP-0009", Refs: []string{"ref"}}
	diag, applied, err := EnsureTimePacket(ctx, rule)
	if err != nil {
		t.Fatalf("EnsureTimePacket returned error: %v", err)
	}
	if applied {
		t.Fatalf("EnsureTimePacket applied fix unexpectedly")
	}
	if diag.Severity != ERROR {
		t.Fatalf("severity = %s, want ERROR", diag.Severity)
	}
	if diag.Message != "no time packets detected" {
		t.Fatalf("message = %q, want 'no time packets detected'", diag.Message)
	}
	if diag.TimestampUs != nil || diag.TimestampSource != nil {
		t.Fatalf("expected nil timestamp fields, got %v/%v", diag.TimestampUs, diag.TimestampSource)
	}
}

func TestEnsureTimePacketWarnsWhenDynamicBeforeTime(t *testing.T) {
	timePkt := ch10.PacketIndex{IsTimePacket: true, TimeStampUs: 1_000_000, Source: ch10.TimestampSourceTimePacket, ChannelID: 10, Offset: 0x40}
	dynPkt := ch10.PacketIndex{HasSecHdr: true, SecHdrBytes: true, SecHdrValid: true, TimeStampUs: 500_000, Source: ch10.TimestampSourceSecondaryHeader, ChannelID: 2, Offset: 0x20}
	ctx := &Context{
		InputFile: "file.ch10",
		Index: &ch10.FileIndex{
			HasTimePacket:         true,
			TimeSeenBeforeDynamic: false,
			Packets:               []ch10.PacketIndex{dynPkt, timePkt},
		},
	}
	rule := Rule{RuleId: "RP-0009"}
	diag, applied, err := EnsureTimePacket(ctx, rule)
	if err != nil {
		t.Fatalf("EnsureTimePacket returned error: %v", err)
	}
	if applied {
		t.Fatalf("EnsureTimePacket applied fix unexpectedly")
	}
	if diag.Severity != WARN {
		t.Fatalf("severity = %s, want WARN", diag.Severity)
	}
	if diag.PacketIndex != 0 {
		t.Fatalf("PacketIndex = %d, want 0", diag.PacketIndex)
	}
	if diag.ChannelId != int(dynPkt.ChannelID) {
		t.Fatalf("ChannelId = %d, want %d", diag.ChannelId, dynPkt.ChannelID)
	}
	if diag.TimestampUs == nil || *diag.TimestampUs != timePkt.TimeStampUs {
		t.Fatalf("timestamp pointer incorrect: %v", diag.TimestampUs)
	}
	if diag.TimestampSource == nil || *diag.TimestampSource != string(timePkt.Source) {
		t.Fatalf("timestamp source incorrect: %v", diag.TimestampSource)
	}
}

func TestEnsureTimePacketReportsMissingSecHeader(t *testing.T) {
	timePkt := ch10.PacketIndex{IsTimePacket: true, TimeStampUs: 1_000_000, Source: ch10.TimestampSourceTimePacket}
	badDyn := ch10.PacketIndex{HasSecHdr: true, SecHdrBytes: false, ChannelID: 3, Offset: 0x60}
	ctx := &Context{
		InputFile: "file.ch10",
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
