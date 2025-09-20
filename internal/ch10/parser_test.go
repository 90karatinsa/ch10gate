package ch10

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
)

func TestParseSecHdrFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   uint8
		hasSec  bool
		timeFmt uint8
	}{
		{name: "no secondary header", flags: 0x00, hasSec: false, timeFmt: 0x00},
		{name: "irig format", flags: packetFlagSecondaryHdr | timeFormatIRIG106, hasSec: true, timeFmt: timeFormatIRIG106},
		{name: "reserved format", flags: packetFlagSecondaryHdr | 0x08, hasSec: true, timeFmt: 0x08},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hdr := PacketHeader{Flags: tc.flags}
			has, tf := parseSecHdrFlags(&hdr)
			if has != tc.hasSec {
				t.Fatalf("HasSecHdr = %v, want %v", has, tc.hasSec)
			}
			if tf != tc.timeFmt {
				t.Fatalf("TimeFormat = 0x%X, want 0x%X", tf, tc.timeFmt)
			}
		})
	}
}

func TestDecodeIPTSToMicros(t *testing.T) {
	tests := []struct {
		name     string
		tf       uint8
		raw      []byte
		wantUs   int64
		wantErr  error
		wantSecs uint32
		wantSub  uint32
	}{
		{
			name:     "ch4 binary",
			tf:       timeFormatIRIG106,
			raw:      []byte{0x00, 0x00, 0x00, 0x7b, 0x11, 0xd7, 0x00, 0x00},
			wantUs:   1_234_567,
			wantSecs: 1,
			wantSub:  234_567,
		},
		{
			name:     "ieee1588",
			tf:       timeFormatIEEE1588,
			raw:      []byte{0x1d, 0xcd, 0x65, 0x00, 0x00, 0x00, 0x00, 0x02},
			wantUs:   2_500_000,
			wantSecs: 2,
			wantSub:  500_000_000,
		},
		{
			name:    "unsupported",
			tf:      0x08,
			raw:     make([]byte, 8),
			wantUs:  -1,
			wantErr: ErrUnsupportedTimeFormat,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, secondary, err := decodeIPTSToMicros(tc.tf, tc.raw)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				if got != -1 {
					t.Fatalf("expected -1 timestamp on error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeIPTSToMicros returned error: %v", err)
			}
			if got != tc.wantUs {
				t.Fatalf("timestamp = %d, want %d", got, tc.wantUs)
			}
			if secondary.Seconds != tc.wantSecs {
				t.Fatalf("seconds = %d, want %d", secondary.Seconds, tc.wantSecs)
			}
			if secondary.Subsecond != tc.wantSub {
				t.Fatalf("subsecond = %d, want %d", secondary.Subsecond, tc.wantSub)
			}
			if secondary.TimeStampUs != tc.wantUs {
				t.Fatalf("secondary timestamp = %d, want %d", secondary.TimeStampUs, tc.wantUs)
			}
		})
	}
}

func TestReaderNextTimeStamp(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "ch10-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer tmp.Close()

	writePacket := func(flags uint8, secHdr []byte) {
		totalLen := primaryHeaderSize + len(secHdr)
		packetLen := uint32(totalLen - 4)
		header := make([]byte, primaryHeaderSize)
		binary.BigEndian.PutUint16(header[0:2], syncPattern)
		binary.BigEndian.PutUint16(header[2:4], 0x0001)
		binary.BigEndian.PutUint32(header[4:8], packetLen)
		binary.BigEndian.PutUint32(header[8:12], uint32(len(secHdr)))
		binary.BigEndian.PutUint16(header[12:14], 0)
		header[14] = 0
		header[15] = flags
		if _, err := tmp.Write(header); err != nil {
			t.Fatalf("write header failed: %v", err)
		}
		if len(secHdr) > 0 {
			if len(secHdr) < secondaryHeaderSize {
				padded := make([]byte, secondaryHeaderSize)
				copy(padded, secHdr)
				secHdr = padded
			}
			if _, err := tmp.Write(secHdr); err != nil {
				t.Fatalf("write secondary header failed: %v", err)
			}
		}
	}

	irigSec := make([]byte, secondaryHeaderSize)
	binary.BigEndian.PutUint16(irigSec[0:2], 0)
	binary.BigEndian.PutUint16(irigSec[2:4], 0x007b)
	binary.BigEndian.PutUint16(irigSec[4:6], 0x11d7)

	ieeeSec := make([]byte, secondaryHeaderSize)
	binary.BigEndian.PutUint32(ieeeSec[0:4], 500_000_000)
	binary.BigEndian.PutUint32(ieeeSec[4:8], 3)

	writePacket(packetFlagSecondaryHdr|timeFormatIRIG106, irigSec)
	writePacket(0, nil)
	writePacket(packetFlagSecondaryHdr|0x08, ieeeSec)

	if err := tmp.Sync(); err != nil {
		t.Fatalf("sync temp file failed: %v", err)
	}

	reader, err := NewReader(tmp.Name())
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}
	defer reader.Close()

	expected := []struct {
		hasSec   bool
		secBytes bool
		secValid bool
		ts       int64
		source   TimestampSource
		isTime   bool
	}{
		{hasSec: true, secBytes: true, secValid: true, ts: 1_234_567, source: TimestampSourceTimePacket, isTime: true},
		{hasSec: false, secBytes: false, secValid: false, ts: -1, source: TimestampSourceUnknown, isTime: true},
		{hasSec: true, secBytes: true, secValid: false, ts: -1, source: TimestampSourceUnknown, isTime: true},
	}

	for i, want := range expected {
		_, idx, err := reader.Next()
		if err != nil {
			t.Fatalf("Next %d failed: %v", i, err)
		}
		if idx.HasSecHdr != want.hasSec {
			t.Fatalf("packet %d HasSecHdr = %v, want %v", i, idx.HasSecHdr, want.hasSec)
		}
		if idx.SecHdrBytes != want.secBytes {
			t.Fatalf("packet %d SecHdrBytes = %v, want %v", i, idx.SecHdrBytes, want.secBytes)
		}
		if idx.SecHdrValid != want.secValid {
			t.Fatalf("packet %d SecHdrValid = %v, want %v", i, idx.SecHdrValid, want.secValid)
		}
		if idx.TimeStampUs != want.ts {
			t.Fatalf("packet %d TimeStampUs = %d, want %d", i, idx.TimeStampUs, want.ts)
		}
		if idx.Source != want.source {
			t.Fatalf("packet %d Source = %q, want %q", i, idx.Source, want.source)
		}
		if idx.IsTimePacket != want.isTime {
			t.Fatalf("packet %d IsTimePacket = %v, want %v", i, idx.IsTimePacket, want.isTime)
		}
	}

	if _, _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}

	idx := reader.Index()
	if len(idx.Packets) != len(expected) {
		t.Fatalf("index length = %d, want %d", len(idx.Packets), len(expected))
	}
	for i, pkt := range idx.Packets {
		if pkt.TimeStampUs != expected[i].ts {
			t.Fatalf("index packet %d TimeStampUs = %d, want %d", i, pkt.TimeStampUs, expected[i].ts)
		}
		if pkt.Source != expected[i].source {
			t.Fatalf("index packet %d Source = %q, want %q", i, pkt.Source, expected[i].source)
		}
	}
}

func TestReaderTimeRefAndIPTS(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "ch10-ts-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer tmp.Close()

	timeSec := make([]byte, secondaryHeaderSize)
	binary.BigEndian.PutUint16(timeSec[0:2], 0)
	binary.BigEndian.PutUint16(timeSec[2:4], 0x007b)
	binary.BigEndian.PutUint16(timeSec[4:6], 0x11d7)
	writeTestPacket(t, tmp, 0x0000, packetFlagSecondaryHdr|timeFormatIRIG106, timeSec, nil)

	dynSec := make([]byte, secondaryHeaderSize)
	binary.BigEndian.PutUint16(dynSec[0:2], 0)
	binary.BigEndian.PutUint16(dynSec[2:4], 0x007b)
	binary.BigEndian.PutUint16(dynSec[4:6], 0x15bf)
	writeTestPacket(t, tmp, 0x0011, packetFlagSecondaryHdr|timeFormatIRIG106, dynSec, nil)

	iptsPayload := make([]byte, 8)
	binary.BigEndian.PutUint64(iptsPayload, 200)
	writeTestPacket(t, tmp, 0x0011, 0x00, nil, iptsPayload)

	if err := tmp.Sync(); err != nil {
		t.Fatalf("sync temp file failed: %v", err)
	}

	reader, err := NewReader(tmp.Name())
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}
	defer reader.Close()

	_, first, err := reader.Next()
	if err != nil {
		t.Fatalf("first Next failed: %v", err)
	}
	if !first.IsTimePacket || first.Source != TimestampSourceTimePacket {
		t.Fatalf("first packet source = %q, IsTimePacket=%v", first.Source, first.IsTimePacket)
	}
	if first.TimeStampUs != 1_234_567 {
		t.Fatalf("first timestamp = %d, want 1234567", first.TimeStampUs)
	}

	_, second, err := reader.Next()
	if err != nil {
		t.Fatalf("second Next failed: %v", err)
	}
	if second.Source != TimestampSourceSecondaryHeader {
		t.Fatalf("second packet source = %q, want secondary header", second.Source)
	}
	if second.TimeStampUs != 1_235_567 {
		t.Fatalf("second timestamp = %d, want 1235567", second.TimeStampUs)
	}

	_, third, err := reader.Next()
	if err != nil {
		t.Fatalf("third Next failed: %v", err)
	}
	if third.Source != TimestampSourceIPTS {
		t.Fatalf("third packet source = %q, want ipts", third.Source)
	}
	if third.TimeStampUs != 1_234_767 {
		t.Fatalf("third timestamp = %d, want 1234767", third.TimeStampUs)
	}

	idx := reader.Index()
	if !idx.TimeSeenBeforeDynamic {
		t.Fatalf("TimeSeenBeforeDynamic = false, want true")
	}
	if !idx.HasTimePacket {
		t.Fatalf("HasTimePacket = false, want true")
	}
	if len(idx.Packets) != 3 {
		t.Fatalf("index packets = %d, want 3", len(idx.Packets))
	}
	if idx.Packets[2].Source != TimestampSourceIPTS {
		t.Fatalf("index third source = %q, want ipts", idx.Packets[2].Source)
	}
}

func TestReaderTimeSeenBeforeDynamic(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "ch10-order-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer tmp.Close()

	ieeeSec := make([]byte, secondaryHeaderSize)
	binary.BigEndian.PutUint32(ieeeSec[0:4], 500_000_000)
	binary.BigEndian.PutUint32(ieeeSec[4:8], 0)
	writeTestPacket(t, tmp, 0x0011, packetFlagSecondaryHdr|timeFormatIEEE1588, ieeeSec, nil)

	iptsEarly := make([]byte, 8)
	binary.BigEndian.PutUint64(iptsEarly, 100)
	writeTestPacket(t, tmp, 0x0011, 0x00, nil, iptsEarly)

	timeSec := make([]byte, secondaryHeaderSize)
	binary.BigEndian.PutUint16(timeSec[0:2], 0)
	binary.BigEndian.PutUint16(timeSec[2:4], 0x007b)
	binary.BigEndian.PutUint16(timeSec[4:6], 0x11d7)
	writeTestPacket(t, tmp, 0x0000, packetFlagSecondaryHdr|timeFormatIRIG106, timeSec, nil)

	iptsLate := make([]byte, 8)
	binary.BigEndian.PutUint64(iptsLate, 300)
	writeTestPacket(t, tmp, 0x0011, 0x00, nil, iptsLate)

	if err := tmp.Sync(); err != nil {
		t.Fatalf("sync temp file failed: %v", err)
	}

	reader, err := NewReader(tmp.Name())
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}
	defer reader.Close()

	_, first, err := reader.Next()
	if err != nil {
		t.Fatalf("first Next failed: %v", err)
	}
	if first.Source != TimestampSourceSecondaryHeader {
		t.Fatalf("first packet source = %q, want secondary header", first.Source)
	}
	if first.TimeStampUs != 500_000 {
		t.Fatalf("first timestamp = %d, want 500000", first.TimeStampUs)
	}

	_, second, err := reader.Next()
	if err != nil {
		t.Fatalf("second Next failed: %v", err)
	}
	if second.TimeStampUs != -1 {
		t.Fatalf("second timestamp = %d, want -1", second.TimeStampUs)
	}
	if second.Source != TimestampSourceUnknown {
		t.Fatalf("second source = %q, want unknown", second.Source)
	}

	_, third, err := reader.Next()
	if err != nil {
		t.Fatalf("third Next failed: %v", err)
	}
	if third.Source != TimestampSourceTimePacket {
		t.Fatalf("third source = %q, want time packet", third.Source)
	}

	_, fourth, err := reader.Next()
	if err != nil {
		t.Fatalf("fourth Next failed: %v", err)
	}
	if fourth.Source != TimestampSourceIPTS {
		t.Fatalf("fourth source = %q, want ipts", fourth.Source)
	}
	if fourth.TimeStampUs != 1_234_867 {
		t.Fatalf("fourth timestamp = %d, want 1234867", fourth.TimeStampUs)
	}

	idx := reader.Index()
	if idx.TimeSeenBeforeDynamic {
		t.Fatalf("TimeSeenBeforeDynamic = true, want false")
	}
	if !idx.HasTimePacket {
		t.Fatalf("HasTimePacket = false, want true")
	}
	if len(idx.Packets) != 4 {
		t.Fatalf("index packets = %d, want 4", len(idx.Packets))
	}
	if idx.Packets[1].TimeStampUs != -1 {
		t.Fatalf("index second timestamp = %d, want -1", idx.Packets[1].TimeStampUs)
	}
	if idx.Packets[3].Source != TimestampSourceIPTS {
		t.Fatalf("index fourth source = %q, want ipts", idx.Packets[3].Source)
	}
}

func writeTestPacket(t *testing.T, f *os.File, dataType uint16, flags uint8, secHdr, payload []byte) {
	t.Helper()
	totalLen := primaryHeaderSize + len(secHdr) + len(payload)
	packetLen := uint32(totalLen - 4)
	header := make([]byte, primaryHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], syncPattern)
	binary.BigEndian.PutUint16(header[2:4], 0x0001)
	binary.BigEndian.PutUint32(header[4:8], packetLen)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(secHdr)+len(payload)))
	binary.BigEndian.PutUint16(header[12:14], dataType)
	header[14] = 0
	header[15] = flags
	if _, err := f.Write(header); err != nil {
		t.Fatalf("write header failed: %v", err)
	}
	if len(secHdr) > 0 {
		if len(secHdr) < secondaryHeaderSize {
			padded := make([]byte, secondaryHeaderSize)
			copy(padded, secHdr)
			secHdr = padded
		}
		if _, err := f.Write(secHdr); err != nil {
			t.Fatalf("write secondary header failed: %v", err)
		}
	}
	if len(payload) > 0 {
		if _, err := f.Write(payload); err != nil {
			t.Fatalf("write payload failed: %v", err)
		}
	}
}

func TestDecodePCMCSDW(t *testing.T) {
	csdw := uint32(0)
	csdw |= 1 << 31
	csdw |= 1 << 30
	csdw |= 1 << 29
	csdw |= 1 << 28
	csdw |= uint32(3) << 26
	csdw |= uint32(2) << 24
	csdw |= uint32(2) << 22
	csdw |= 1 << 21
	csdw |= 1 << 20
	csdw |= 1 << 19
	csdw |= 1 << 18
	csdw |= 0x12345

	info := DecodePCMCSDW(csdw)
	if !info.HasIPH {
		t.Fatalf("HasIPH = false, want true")
	}
	if !info.MajorFrame || !info.MinorFrame {
		t.Fatalf("frame indicators not set: major=%v minor=%v", info.MajorFrame, info.MinorFrame)
	}
	if info.MinorStatus != 3 || info.MajorStatus != 2 {
		t.Fatalf("lock status mismatch: minor=%d major=%d", info.MinorStatus, info.MajorStatus)
	}
	if info.AlignmentBits != 32 {
		t.Fatalf("AlignmentBits = %d, want 32", info.AlignmentBits)
	}
	if !info.Throughput || !info.Packed || !info.Unpacked {
		t.Fatalf("mode bits incorrect: throughput=%v packed=%v unpacked=%v", info.Throughput, info.Packed, info.Unpacked)
	}
	if info.Mode != PCMModeUnknown {
		t.Fatalf("Mode = %v, want PCMModeUnknown", info.Mode)
	}
	if !info.ModeConflict {
		t.Fatalf("ModeConflict = false, want true")
	}
	if !info.ReservedNonZero {
		t.Fatalf("ReservedNonZero = false, want true")
	}
	if info.SyncOffset != 0x12345&pcmMaskSyncOffset {
		t.Fatalf("SyncOffset = 0x%X, want 0x%X", info.SyncOffset, 0x12345&pcmMaskSyncOffset)
	}
}
