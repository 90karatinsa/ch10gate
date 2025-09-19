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
		hasSec bool
		ts     int64
	}{
		{hasSec: true, ts: 1_234_567},
		{hasSec: false, ts: -1},
		{hasSec: true, ts: -1},
	}

	for i, want := range expected {
		_, idx, err := reader.Next()
		if err != nil {
			t.Fatalf("Next %d failed: %v", i, err)
		}
		if idx.HasSecHdr != want.hasSec {
			t.Fatalf("packet %d HasSecHdr = %v, want %v", i, idx.HasSecHdr, want.hasSec)
		}
		if idx.TimeStampUs != want.ts {
			t.Fatalf("packet %d TimeStampUs = %d, want %d", i, idx.TimeStampUs, want.ts)
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
	}
}
