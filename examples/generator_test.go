package examples_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"example.com/ch10gate/examples/internal/samples"
	"example.com/ch10gate/internal/ch10"
)

const sampleChapter10Hex = "eb25000100000018000000080000000014b90000000030391a850000eb25000200000018000000080008010013b0000000000000000009c4eb250003000000200000001000080280121f00000000303c06fd000000003739aa55aa55"

func TestSampleFixturesMatchGenerator(t *testing.T) {
	ch10Data, err := samples.BuildChapter10()
	if err != nil {
		t.Fatalf("BuildChapter10: %v", err)
	}
	tmatsData, err := samples.BuildTMATS()
	if err != nil {
		t.Fatalf("BuildTMATS: %v", err)
	}

	wantCh10, err := hex.DecodeString(sampleChapter10Hex)
	if err != nil {
		t.Fatalf("decode expected Chapter 10 hex: %v", err)
	}
	if !bytes.Equal(wantCh10, ch10Data) {
		t.Fatalf("BuildChapter10 produced unexpected bytes")
	}
	fixtureTMATS := readFixture(t, samples.TMATSFileName)
	if !bytes.Equal(fixtureTMATS, tmatsData) {
		t.Fatalf("sample.tmats does not match generator output")
	}

	tmp := t.TempDir()
	if err := samples.WriteFiles(tmp); err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}
	generatedCh10 := readFile(t, filepath.Join(tmp, samples.Chapter10FileName))
	if !bytes.Equal(generatedCh10, ch10Data) {
		t.Fatalf("WriteFiles produced unexpected Chapter 10 bytes")
	}
	generatedTMATS := readFile(t, filepath.Join(tmp, samples.TMATSFileName))
	if !bytes.Equal(generatedTMATS, tmatsData) {
		t.Fatalf("WriteFiles produced unexpected TMATS bytes")
	}
}

func TestChapter10ReaderParsesSample(t *testing.T) {
	tmp := t.TempDir()
	if err := samples.WriteFiles(tmp); err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}
	reader, err := ch10.NewReader(filepath.Join(tmp, samples.Chapter10FileName))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer reader.Close()

	type expectedPacket struct {
		channel     uint16
		dataType    uint16
		hasSecHdr   bool
		secHdrValid bool
		timeStampUs int64
		source      ch10.TimestampSource
		isTime      bool
	}

	want := []expectedPacket{
		{channel: 1, dataType: 0x0000, hasSecHdr: false, secHdrValid: false, timeStampUs: samples.BaseTimestampUS, source: ch10.TimestampSourceTimePacket, isTime: true},
		{channel: 2, dataType: 0x0008, hasSecHdr: false, secHdrValid: false, timeStampUs: samples.BaseTimestampUS + int64(samples.IPTSOffsetUS), source: ch10.TimestampSourceIPTS, isTime: false},
		{channel: 3, dataType: 0x0008, hasSecHdr: true, secHdrValid: true, timeStampUs: samples.SecondaryTimestampUS, source: ch10.TimestampSourceSecondaryHeader, isTime: false},
	}

	var got []ch10.PacketIndex
	for {
		hdr, idx, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reader.Next: %v", err)
		}
		got = append(got, idx)
		if len(got) > len(want) {
			t.Fatalf("read more packets than expected: %d", len(got))
		}
		exp := want[len(got)-1]
		if hdr.ChannelID != exp.channel {
			t.Fatalf("packet %d channel = %d, want %d", len(got)-1, hdr.ChannelID, exp.channel)
		}
		if hdr.DataType != exp.dataType {
			t.Fatalf("packet %d datatype = 0x%X, want 0x%X", len(got)-1, hdr.DataType, exp.dataType)
		}
		if idx.HasSecHdr != exp.hasSecHdr {
			t.Fatalf("packet %d HasSecHdr = %v, want %v", len(got)-1, idx.HasSecHdr, exp.hasSecHdr)
		}
		if idx.SecHdrValid != exp.secHdrValid {
			t.Fatalf("packet %d SecHdrValid = %v, want %v", len(got)-1, idx.SecHdrValid, exp.secHdrValid)
		}
		if idx.TimeStampUs != exp.timeStampUs {
			t.Fatalf("packet %d timestamp = %d, want %d", len(got)-1, idx.TimeStampUs, exp.timeStampUs)
		}
		if idx.Source != exp.source {
			t.Fatalf("packet %d source = %v, want %v", len(got)-1, idx.Source, exp.source)
		}
		if idx.IsTimePacket != exp.isTime {
			t.Fatalf("packet %d IsTimePacket = %v, want %v", len(got)-1, idx.IsTimePacket, exp.isTime)
		}
	}

	if len(got) != len(want) {
		t.Fatalf("read %d packets, want %d", len(got), len(want))
	}

	index := reader.Index()
	if len(index.Packets) != len(want) {
		t.Fatalf("index length = %d, want %d", len(index.Packets), len(want))
	}
	for i, pkt := range index.Packets {
		if pkt.TimeStampUs != want[i].timeStampUs {
			t.Fatalf("index packet %d timestamp = %d, want %d", i, pkt.TimeStampUs, want[i].timeStampUs)
		}
		if pkt.Source != want[i].source {
			t.Fatalf("index packet %d source = %v, want %v", i, pkt.Source, want[i].source)
		}
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	return readFile(t, name)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	return data
}
