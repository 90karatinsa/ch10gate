package rules

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.com/ch10gate/internal/ch10"
	"example.com/ch10gate/internal/dict"
	"example.com/ch10gate/internal/tmats"
)

const (
	testPrimaryHeaderSize = 20
)

func buildSyntheticPacket(t *testing.T, profile string, channel uint16, dataType uint16, seq uint8, flags uint8, secHdr, payload []byte) []byte {
	t.Helper()
	total := testPrimaryHeaderSize + len(secHdr) + len(payload)
	header := make([]byte, testPrimaryHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], 0xEB25)
	binary.BigEndian.PutUint16(header[2:4], channel)
	binary.BigEndian.PutUint32(header[4:8], uint32(total-4))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(secHdr)+len(payload)))
	binary.BigEndian.PutUint16(header[12:14], dataType)
	header[14] = seq
	header[15] = flags
	header[16] = 0
	header[17] = 0
	chk, err := ch10.ComputeHeaderChecksum(profile, header)
	if err != nil {
		t.Fatalf("ComputeHeaderChecksum: %v", err)
	}
	binary.BigEndian.PutUint16(header[16:18], chk)
	packet := make([]byte, total)
	copy(packet, header)
	offset := testPrimaryHeaderSize
	if len(secHdr) > 0 {
		copy(packet[offset:], secHdr)
		offset += len(secHdr)
	}
	if len(payload) > 0 {
		copy(packet[offset:], payload)
	}
	return packet
}

func writeSyntheticFile(t *testing.T, path string, packets ...[]byte) {
	t.Helper()
	var data []byte
	for _, pkt := range packets {
		data = append(data, pkt...)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("writeSyntheticFile: %v", err)
	}
}

func computeDataChecksum(t *testing.T, profile string, payload []byte) uint16 {
	t.Helper()
	calc, err := ch10.NewDataChecksum(profile)
	if err != nil {
		t.Fatalf("NewDataChecksum: %v", err)
	}
	calc.Write(payload)
	return calc.Sum16()
}

func TestCheckSyncPattern(t *testing.T) {
	rule := Rule{RuleId: "RP-0001"}
	goodCtx := &Context{PrimaryHeader: &ch10.PacketHeader{Sync: 0xEB25}}
	diag, applied, err := CheckSyncPattern(goodCtx, rule)
	if err != nil {
		t.Fatalf("CheckSyncPattern good err: %v", err)
	}
	if applied {
		t.Fatalf("expected no fix applied")
	}
	if diag.Severity != INFO || diag.Message != "sync pattern ok" {
		t.Fatalf("unexpected diag for good sync: %+v", diag)
	}

	badCtx := &Context{PrimaryHeader: &ch10.PacketHeader{Sync: 0x1234}}
	diag, applied, err = CheckSyncPattern(badCtx, rule)
	if err != nil {
		t.Fatalf("CheckSyncPattern bad err: %v", err)
	}
	if diag.Severity != ERROR || !strings.Contains(diag.Message, "sync pattern") {
		t.Fatalf("unexpected diag for bad sync: %+v", diag)
	}
	if applied {
		t.Fatalf("unexpected applied on bad sync")
	}
}

func TestFixHeaderChecksum(t *testing.T) {
	rule := Rule{RuleId: "RP-0002"}

	t.Run("apply", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "header.ch10")
		payload := []byte{0x01, 0x02, 0x03, 0x04}
		packet := buildSyntheticPacket(t, "106-15", 1, 0x08, 0, 0, nil, payload)
		binary.BigEndian.PutUint16(packet[16:18], 0xFFFF)
		writeSyntheticFile(t, path, packet)

		ctx := &Context{InputFile: path, Profile: "106-15"}
		diag, applied, err := FixHeaderChecksum(ctx, rule)
		if err != nil {
			t.Fatalf("FixHeaderChecksum err: %v", err)
		}
		if !applied {
			t.Fatalf("expected checksum fix applied")
		}
		if !strings.Contains(diag.Message, "fixed header checksum") {
			t.Fatalf("unexpected diag message: %+v", diag)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixed file: %v", err)
		}
		want := buildSyntheticPacket(t, "106-15", 1, 0x08, 0, 0, nil, payload)
		got := binary.BigEndian.Uint16(data[16:18])
		if got != binary.BigEndian.Uint16(want[16:18]) {
			t.Fatalf("checksum not corrected: got 0x%04X want 0x%04X", got, binary.BigEndian.Uint16(want[16:18]))
		}
	})

	t.Run("dry-run", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "header.ch10")
		payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}
		packet := buildSyntheticPacket(t, "106-15", 2, 0x08, 0, 0, nil, payload)
		binary.BigEndian.PutUint16(packet[16:18], 0xFFFF)
		writeSyntheticFile(t, path, packet)

		ctx := &Context{InputFile: path, Profile: "106-15", DryRun: true}
		diag, applied, err := FixHeaderChecksum(ctx, rule)
		if err != nil {
			t.Fatalf("FixHeaderChecksum dry-run err: %v", err)
		}
		if applied {
			t.Fatalf("expected no fix applied during dry-run")
		}
		if !diag.FixSuggested {
			t.Fatalf("expected fix suggested during dry-run: %+v", diag)
		}
		if !strings.Contains(diag.Message, "would fix header checksum") {
			t.Fatalf("unexpected dry-run message: %+v", diag)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read original file: %v", err)
		}
		if binary.BigEndian.Uint16(data[16:18]) != 0xFFFF {
			t.Fatalf("checksum should remain unchanged during dry-run")
		}
	})

	if _, _, err := FixHeaderChecksum(&Context{}, rule); err == nil {
		t.Fatalf("expected error when input file missing")
	}
}

func TestFixDataChecksumOrTrailer(t *testing.T) {
	rule := Rule{RuleId: "RP-0003"}

	t.Run("apply", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "data.ch10")
		payload := []byte{0x10, 0x20, 0x30, 0x40}
		packet := buildSyntheticPacket(t, "106-15", 2, 0x08, 0, 0, nil, payload)
		binary.BigEndian.PutUint16(packet[18:20], 0)
		writeSyntheticFile(t, path, packet)

		ctx := &Context{InputFile: path, Profile: "106-15"}
		diag, applied, err := FixDataChecksumOrTrailer(ctx, rule)
		if err != nil {
			t.Fatalf("FixDataChecksumOrTrailer err: %v", err)
		}
		if !applied {
			t.Fatalf("expected checksum fix applied")
		}
		if !strings.Contains(diag.Message, "data checksum") {
			t.Fatalf("unexpected diag message: %+v", diag)
		}
		want := computeDataChecksum(t, "106-15", payload)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixed file: %v", err)
		}
		if binary.BigEndian.Uint16(data[18:20]) != want {
			t.Fatalf("data checksum not corrected")
		}
	})

	t.Run("dry-run", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "data.ch10")
		payload := []byte{0x55, 0x66, 0x77, 0x88}
		packet := buildSyntheticPacket(t, "106-15", 4, 0x08, 0, 0, nil, payload)
		binary.BigEndian.PutUint16(packet[18:20], 0)
		writeSyntheticFile(t, path, packet)

		ctx := &Context{InputFile: path, Profile: "106-15", DryRun: true}
		diag, applied, err := FixDataChecksumOrTrailer(ctx, rule)
		if err != nil {
			t.Fatalf("FixDataChecksumOrTrailer dry-run err: %v", err)
		}
		if applied {
			t.Fatalf("expected no fix applied during dry-run")
		}
		if !diag.FixSuggested {
			t.Fatalf("expected fix suggested during dry-run: %+v", diag)
		}
		if !strings.Contains(diag.Message, "would fix data checksum") {
			t.Fatalf("unexpected dry-run message: %+v", diag)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read original file: %v", err)
		}
		if binary.BigEndian.Uint16(data[18:20]) != 0 {
			t.Fatalf("data checksum should remain unchanged during dry-run")
		}
	})

	if _, _, err := FixDataChecksumOrTrailer(&Context{}, rule); err == nil {
		t.Fatalf("expected error when input file missing")
	}
}

func TestFixLengths(t *testing.T) {
	rule := Rule{RuleId: "RP-0005"}

	t.Run("apply", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lengths.ch10")
		payload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44}
		packet := buildSyntheticPacket(t, "106-15", 3, 0x00, 0, 0, nil, payload)
		binary.BigEndian.PutUint32(packet[8:12], uint32(len(payload)/2))
		binary.BigEndian.PutUint16(packet[18:20], 0)
		writeSyntheticFile(t, path, packet)

		ctx := &Context{InputFile: path, Profile: "106-15"}
		diag, applied, err := FixLengths(ctx, rule)
		if err != nil {
			t.Fatalf("FixLengths err: %v", err)
		}
		if !applied {
			t.Fatalf("expected length fix applied")
		}
		if !strings.Contains(diag.Message, "length") {
			t.Fatalf("unexpected diag message: %+v", diag)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixed file: %v", err)
		}
		if binary.BigEndian.Uint32(data[8:12]) != uint32(len(payload)) {
			t.Fatalf("data length not corrected")
		}
	})

	t.Run("dry-run", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lengths.ch10")
		payload := []byte{0x01, 0x02, 0x03, 0x04}
		packet := buildSyntheticPacket(t, "106-15", 4, 0x00, 0, 0, nil, payload)
		binary.BigEndian.PutUint32(packet[8:12], uint32(len(payload)/2))
		binary.BigEndian.PutUint16(packet[18:20], 0)
		writeSyntheticFile(t, path, packet)

		ctx := &Context{InputFile: path, Profile: "106-15", DryRun: true}
		diag, applied, err := FixLengths(ctx, rule)
		if err != nil {
			t.Fatalf("FixLengths dry-run err: %v", err)
		}
		if applied {
			t.Fatalf("expected no fix applied during dry-run")
		}
		if !diag.FixSuggested {
			t.Fatalf("expected fix suggested during dry-run: %+v", diag)
		}
		if !strings.Contains(diag.Message, "would update length fields") {
			t.Fatalf("unexpected dry-run message: %+v", diag)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read original file: %v", err)
		}
		if binary.BigEndian.Uint32(data[8:12]) == uint32(len(payload)) {
			t.Fatalf("data length should remain incorrect during dry-run")
		}
	})

	if _, _, err := FixLengths(&Context{}, rule); err == nil {
		t.Fatalf("expected error when input file missing")
	}
}

func TestRemapChannelIds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remap.ch10")
	pkt0 := buildSyntheticPacket(t, "106-15", 0, 0x08, 0, 0, nil, []byte{0x01})
	pkt2 := buildSyntheticPacket(t, "106-15", 2, 0x08, 1, 0, nil, []byte{0x02})
	writeSyntheticFile(t, path, pkt0, pkt2)

	ctx := &Context{InputFile: path, Profile: "106-15"}
	rule := Rule{RuleId: "RP-0006"}
	diag, applied, err := RemapChannelIds(ctx, rule)
	if err != nil {
		t.Fatalf("RemapChannelIds err: %v", err)
	}
	if !applied {
		t.Fatalf("expected remap to apply")
	}
	outPath := path + ".fixed.ch10"
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected rewritten file: %v", err)
	}
	out, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read remapped file: %v", err)
	}
	newChannel := binary.BigEndian.Uint16(out[2:4])
	if newChannel == 0 {
		t.Fatalf("channel id still zero")
	}
	if !strings.Contains(diag.Message, "remapped") {
		t.Fatalf("unexpected diag: %+v", diag)
	}

	_, _, err = RemapChannelIds(&Context{InputFile: path}, rule)
	if err == nil {
		t.Fatalf("expected error without profile")
	}
}

func TestRenumberSeq(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seq.ch10")
	pkt0 := buildSyntheticPacket(t, "106-15", 5, 0x08, 0, 0, nil, []byte{0x01})
	pkt2 := buildSyntheticPacket(t, "106-15", 5, 0x08, 2, 0, nil, []byte{0x02})
	pkt3 := buildSyntheticPacket(t, "106-15", 5, 0x08, 3, 0, nil, []byte{0x03})
	writeSyntheticFile(t, path, pkt0, pkt2, pkt3)

	ctx := &Context{InputFile: path, Profile: "106-15"}
	rule := Rule{RuleId: "RP-0007"}
	diag, applied, err := RenumberSeq(ctx, rule)
	if err != nil {
		t.Fatalf("RenumberSeq err: %v", err)
	}
	if !applied {
		t.Fatalf("expected renumber to apply")
	}
	if !strings.Contains(diag.Message, "renumbered") {
		t.Fatalf("unexpected diag: %+v", diag)
	}
	outPath := path + ".fixed.ch10"
	reader, err := ch10.NewReader(outPath)
	if err != nil {
		t.Fatalf("reader open: %v", err)
	}
	defer reader.Close()
	var seqs []uint8
	for {
		_, pkt, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reader next: %v", err)
		}
		seqs = append(seqs, pkt.SeqNum)
	}
	if len(seqs) == 0 {
		t.Fatalf("no packets after renumber")
	}
	if seqs[0] != 0 {
		t.Fatalf("first seq not zero: %d", seqs[0])
	}

	_, _, err = RenumberSeq(&Context{InputFile: path}, rule)
	if err == nil {
		t.Fatalf("expected error without profile")
	}
}

func TestBlockUnknownDataType(t *testing.T) {
	rule := Rule{RuleId: "RP-0008"}
	ctx := &Context{PrimaryHeader: &ch10.PacketHeader{DataType: 0x10}}
	diag, applied, err := BlockUnknownDataType(ctx, rule)
	if err != nil {
		t.Fatalf("BlockUnknownDataType err: %v", err)
	}
	if applied {
		t.Fatalf("unexpected fix applied")
	}
	if diag.Severity != INFO {
		t.Fatalf("expected INFO severity")
	}

	ctx = &Context{PrimaryHeader: &ch10.PacketHeader{DataType: 0x90}}
	diag, applied, err = BlockUnknownDataType(ctx, rule)
	if err != nil {
		t.Fatalf("BlockUnknownDataType err: %v", err)
	}
	if diag.Severity != ERROR {
		t.Fatalf("expected ERROR for unknown data type")
	}
	if applied {
		t.Fatalf("unexpected fix applied for unknown type")
	}
}

func TestCheck1553IpdhLen(t *testing.T) {
	rule := Rule{RuleId: "RP-0011", Message: "IPDH mismatch"}
	good := &Context{
		Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{
			DataType: 0x19,
			MIL1553: &ch10.MIL1553Info{
				Messages: []ch10.MIL1553Message{{IPDHLength: 0x18}},
			},
		}}},
	}
	diag, _, err := Check1553IpdhLen(good, rule)
	if err != nil {
		t.Fatalf("Check1553IpdhLen good err: %v", err)
	}
	if diag.Severity != INFO {
		t.Fatalf("expected INFO diag for good IPDH")
	}

	bad := &Context{
		Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{
			DataType: 0x19,
			MIL1553: &ch10.MIL1553Info{
				Messages: []ch10.MIL1553Message{{IPDHLength: 0x10}},
			},
		}}},
	}
	diag, _, err = Check1553IpdhLen(bad, rule)
	if err != nil {
		t.Fatalf("Check1553IpdhLen bad err: %v", err)
	}
	if diag.Severity != ERROR {
		t.Fatalf("expected ERROR when length mismatch")
	}
	if !strings.Contains(diag.Message, rule.Message) {
		t.Fatalf("message did not include rule message: %q", diag.Message)
	}
}

func TestWarn1553Ttb(t *testing.T) {
	rule := Rule{RuleId: "RP-0012", Message: "TTB out-of-context"}
	info := &Context{
		Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{
			DataType: 0x18,
			MIL1553:  &ch10.MIL1553Info{TTB: 0x00},
		}}},
	}
	diag, _, err := Warn1553Ttb(info, rule)
	if err != nil {
		t.Fatalf("Warn1553Ttb info err: %v", err)
	}
	if diag.Severity != INFO {
		t.Fatalf("expected INFO when TTB normal")
	}

	warn := &Context{
		Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{
			DataType: 0x18,
			MIL1553:  &ch10.MIL1553Info{TTB: 0x03},
		}}},
	}
	diag, _, err = Warn1553Ttb(warn, rule)
	if err != nil {
		t.Fatalf("Warn1553Ttb warn err: %v", err)
	}
	if diag.Severity != WARN {
		t.Fatalf("expected WARN for out-of-context TTB")
	}
	if !strings.Contains(diag.Message, "0x3") {
		t.Fatalf("expected detail about TTB value, got %q", diag.Message)
	}
}

func TestValidateAgainstDictionaries(t *testing.T) {
	store, err := dict.FromJSON(dict.JSONFile{
		A429: []dict.JSONA429Entry{
			{Label: 0x1A, SDI: 0, Name: "Pitch Angle"},
		},
		MIL1553: []dict.JSONMIL1553Entry{
			{RT: 3, SA: 2, WordCount: intPtr(16), Name: "Flight Control"},
			{RT: 4, SA: 31, ModeCode: intPtr(3), Name: "Initiate BIT"},
		},
	})
	if err != nil {
		t.Fatalf("dict.FromJSON: %v", err)
	}

	ctx := &Context{
		InputFile:        "test.ch10",
		Dictionaries:     store,
		DictionaryReport: &DictionaryComplianceReport{},
		Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{
			{
				ChannelID: 1,
				Offset:    0x100,
				MIL1553: &ch10.MIL1553Info{
					MessageCount: 2,
					Messages: []ch10.MIL1553Message{
						{HasCommandWord: true, CommandWord: uint16((3 << 11) | (2 << 5) | 18)},
						{HasCommandWord: true, CommandWord: uint16((4 << 11) | (31 << 5) | 4)},
					},
				},
			},
			{
				ChannelID: 2,
				Offset:    0x200,
				A429: &ch10.A429Info{
					MessageCount: 1,
					Words:        []ch10.A429Word{{Label: 0x2B, SDI: 1}},
				},
			},
		}},
	}

	diag, _, err := ValidateAgainstDictionaries(ctx, Rule{RuleId: "RP-DICT", Refs: []string{"ICD"}})
	if err != nil {
		t.Fatalf("ValidateAgainstDictionaries err: %v", err)
	}
	if diag.Severity != ERROR {
		t.Fatalf("expected severity ERROR, got %s", diag.Severity)
	}
	if len(ctx.DictionaryReport.MIL1553) != 2 {
		t.Fatalf("expected 2 MIL-STD-1553 findings, got %d", len(ctx.DictionaryReport.MIL1553))
	}
	if len(ctx.DictionaryReport.A429) != 1 {
		t.Fatalf("expected 1 ARINC-429 finding, got %d", len(ctx.DictionaryReport.A429))
	}

	var wordCountMismatch, modeMismatch bool
	for _, finding := range ctx.DictionaryReport.MIL1553 {
		if strings.Contains(finding.Issue, "Word count mismatch") {
			wordCountMismatch = finding.ExpectedWordCount != nil
		}
		if strings.Contains(finding.Issue, "Mode code mismatch") {
			modeMismatch = finding.ExpectedModeCode != nil
		}
	}
	if !wordCountMismatch {
		t.Fatalf("expected word count mismatch finding")
	}
	if !modeMismatch {
		t.Fatalf("expected mode code mismatch finding")
	}
	if !strings.Contains(ctx.DictionaryReport.A429[0].Issue, "No dictionary entry") {
		t.Fatalf("unexpected A429 issue: %s", ctx.DictionaryReport.A429[0].Issue)
	}
	if !strings.Contains(diag.Message, "Dictionary mismatches detected") {
		t.Fatalf("unexpected diagnostic message: %s", diag.Message)
	}
}

func TestFixA429Gap(t *testing.T) {
	rule := Rule{RuleId: "RP-0013"}
	ctx := &Context{InputFile: "file.ch10", Profile: "106-15", Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{
		DataType: 0x38,
		A429:     &ch10.A429Info{Words: []ch10.A429Word{{}, {GapTime0p1Us: 100}}},
	}}}}
	diag, applied, err := FixA429Gap(ctx, rule)
	if err != nil {
		t.Fatalf("FixA429Gap no violation err: %v", err)
	}
	if applied {
		t.Fatalf("expected no fix when gaps ok")
	}
	if diag.Message != "ARINC-429 gaps verified" {
		t.Fatalf("unexpected message: %q", diag.Message)
	}

	failCtx := &Context{InputFile: "file.ch10", Profile: "106-15", Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{
		DataType: 0x38,
	}}}}
	diag, applied, err = FixA429Gap(failCtx, rule)
	if err == nil {
		t.Fatalf("expected error when metadata missing")
	}
	if diag.Severity != ERROR {
		t.Fatalf("expected ERROR when metadata missing")
	}
	if applied {
		t.Fatalf("should not apply when metadata missing")
	}
}

func TestWarnA429Parity(t *testing.T) {
	rule := Rule{RuleId: "RP-0014", Message: "Parity warning"}
	ctx := &Context{InputFile: "file.ch10", Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{
		DataType: 0x38,
		A429:     &ch10.A429Info{Words: []ch10.A429Word{{ComputedParity: true}}},
	}}}}
	diag, applied, err := WarnA429Parity(ctx, rule)
	if err != nil {
		t.Fatalf("WarnA429Parity normal err: %v", err)
	}
	if applied {
		t.Fatalf("unexpected fix applied")
	}
	if diag.Severity != INFO {
		t.Fatalf("expected INFO when parity ok")
	}

	warn := &Context{InputFile: "file.ch10", Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{
		DataType: 0x38,
		A429:     &ch10.A429Info{Words: []ch10.A429Word{{ParityErrorFlag: true, Label: 0x1, SDI: 2}}},
	}}}}
	diag, applied, err = WarnA429Parity(warn, rule)
	if err != nil {
		t.Fatalf("WarnA429Parity warn err: %v", err)
	}
	if diag.Severity != WARN {
		t.Fatalf("expected WARN for parity issue")
	}
	if !strings.Contains(diag.Message, "label") {
		t.Fatalf("expected label detail in message: %q", diag.Message)
	}
}

func TestUpdateTMATSDigest(t *testing.T) {
	dir := t.TempDir()
	tmatsPath := filepath.Join(dir, "input.tmats")
	content := "# sample\nR-1\\CHE-1:1;\n"
	if err := os.WriteFile(tmatsPath, []byte(content), 0644); err != nil {
		t.Fatalf("write tmats: %v", err)
	}
	ctx := &Context{TMATSFile: tmatsPath}
	rule := Rule{RuleId: "RP-0017"}
	diag, applied, err := UpdateTMATSDigest(ctx, rule)
	if err != nil {
		t.Fatalf("UpdateTMATSDigest err: %v", err)
	}
	if !applied {
		t.Fatalf("expected digest update to apply")
	}
	if !strings.Contains(diag.Message, "digest updated") {
		t.Fatalf("unexpected message: %q", diag.Message)
	}
	if _, err := os.Stat(tmatsPath + ".fixed"); err != nil {
		t.Fatalf("expected fixed tmats file: %v", err)
	}

	diag, applied, err = UpdateTMATSDigest(&Context{}, rule)
	if err != nil {
		t.Fatalf("unexpected error when TMATS missing")
	}
	if diag.Severity != WARN {
		t.Fatalf("expected WARN when TMATS missing")
	}
	if applied {
		t.Fatalf("should not apply without TMATS")
	}
}

func TestNormalizeTMATSChannelMap(t *testing.T) {
	dir := t.TempDir()
	tmatsPath := filepath.Join(dir, "map.tmats")
	content := "R-1\\CHE-1:9;\nR-1\\CDT-1:PCM;\n"
	if err := os.WriteFile(tmatsPath, []byte(content), 0644); err != nil {
		t.Fatalf("write tmats: %v", err)
	}
	idx := &ch10.FileIndex{Packets: []ch10.PacketIndex{{
		ChannelID: 1,
		DataType:  0x08,
	}, {
		ChannelID:  2,
		DataType:   0x00,
		HasSecHdr:  true,
		TimeFormat: 0x00,
	}}}
	ctx := &Context{TMATSFile: tmatsPath, Index: idx}
	rule := Rule{RuleId: "RP-0018"}
	diag, applied, err := NormalizeTMATSChannelMap(ctx, rule)
	if err != nil {
		t.Fatalf("NormalizeTMATSChannelMap err: %v", err)
	}
	if !applied {
		t.Fatalf("expected TMATS normalization to apply")
	}
	if !strings.Contains(diag.Message, "normalized") {
		t.Fatalf("unexpected diag message: %+v", diag)
	}
	fixedPath := tmatsPath + ".fixed"
	fixed, err := tmats.Parse(fixedPath)
	if err != nil {
		t.Fatalf("parse fixed tmats: %v", err)
	}
	if val, ok := fixed.Get("R-1\\CHE-1"); !ok || val != "1" {
		t.Fatalf("unexpected CHE-1: %q", val)
	}
	if val, ok := fixed.Get("R-1\\NSB"); !ok || val != "2" {
		t.Fatalf("unexpected NSB: %q", val)
	}

	diag, applied, err = NormalizeTMATSChannelMap(&Context{TMATSFile: ""}, rule)
	if err != nil {
		t.Fatalf("unexpected error when TMATS missing")
	}
	if diag.Severity != WARN {
		t.Fatalf("expected WARN when TMATS missing")
	}
	if applied {
		t.Fatalf("should not apply without TMATS")
	}
}

func TestFixFileExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	ctx := &Context{InputFile: path}
	rule := Rule{RuleId: "RP-0020"}
	diag, applied, err := FixFileExtension(ctx, rule)
	if err != nil {
		t.Fatalf("FixFileExtension err: %v", err)
	}
	if !applied {
		t.Fatalf("expected file copy to apply")
	}
	if !strings.Contains(diag.Message, "copied") {
		t.Fatalf("unexpected diag message: %+v", diag)
	}
	if _, err := os.Stat(path + ".ch10"); err != nil {
		t.Fatalf("expected copied file: %v", err)
	}

	ctx = &Context{InputFile: filepath.Join(dir, "missing.bin")}
	if _, _, err := FixFileExtension(ctx, rule); err == nil {
		t.Fatalf("expected error for missing source file")
	}
}

func TestRuleFilterApplyAndMatches(t *testing.T) {
	base := &ch10.FileIndex{Packets: []ch10.PacketIndex{{ChannelID: 1, DataType: 0x08}, {ChannelID: 2, DataType: 0x09}}}
	filter := ruleFilter{channels: []uint16{2}}
	filtered, mapping, ok := filter.apply(base)
	if !ok || len(filtered.Packets) != 1 || mapping[0] != 1 {
		t.Fatalf("unexpected filter result: ok=%v len=%d mapping=%v", ok, len(filtered.Packets), mapping)
	}
	if filter.empty() {
		t.Fatalf("expected filter to be non-empty")
	}
	if !filter.matches(base.Packets[1]) {
		t.Fatalf("expected filter to match second packet")
	}
	if filter.matches(base.Packets[0]) {
		t.Fatalf("filter should not match first packet")
	}
	_, _, ok = ruleFilter{}.apply(nil)
	if ok {
		t.Fatalf("expected empty filter on nil index to be false")
	}
}

func TestBuildChannelFilters(t *testing.T) {
	base := &ch10.FileIndex{Packets: []ch10.PacketIndex{{ChannelID: 1, DataType: 0x08}, {ChannelID: 2, DataType: 0x08}, {ChannelID: 3, DataType: 0x09}}}
	rule := Rule{AppliesTo: AppliesTo{DataTypes: []uint16{0x08}}}
	filters := buildChannelFilters(base, rule)
	if len(filters) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(filters))
	}
	if !filters[0].matches(base.Packets[0]) || !filters[1].matches(base.Packets[1]) {
		t.Fatalf("filters did not match expected packets")
	}
}

func TestChooseBestDiagnostic(t *testing.T) {
	diags := []Diagnostic{{Severity: INFO, PacketIndex: 2}, {Severity: WARN, PacketIndex: 5}, {Severity: WARN, PacketIndex: 1}}
	best := chooseBestDiagnostic(diags)
	if best == nil || best.PacketIndex != 1 {
		t.Fatalf("unexpected best diagnostic: %+v", best)
	}
	if chooseBestDiagnostic(nil) != nil {
		t.Fatalf("expected nil when no diagnostics")
	}
}

func TestCloneContextIndependence(t *testing.T) {
	ctx := &Context{InputFile: "file.ch10", Index: &ch10.FileIndex{Packets: []ch10.PacketIndex{{ChannelID: 1}}}}
	dup := cloneContext(ctx)
	if dup == nil || dup == ctx {
		t.Fatalf("clone failed")
	}
	dup.InputFile = "other.ch10"
	if ctx.InputFile == dup.InputFile {
		t.Fatalf("expected clone to be independent")
	}
}

func TestRunRuleOnceAppliesFilter(t *testing.T) {
	base := &ch10.FileIndex{Packets: []ch10.PacketIndex{{ChannelID: 1}, {ChannelID: 2}}}
	eng := &Engine{}
	rule := Rule{RuleId: "RP-X"}
	fn := func(ctx *Context, r Rule) (Diagnostic, bool, error) {
		if len(ctx.Index.Packets) == 0 {
			return Diagnostic{RuleId: r.RuleId, Severity: ERROR, Message: "no packets"}, false, nil
		}
		return Diagnostic{RuleId: r.RuleId, Severity: INFO, Message: "ok", PacketIndex: 0, ChannelId: int(ctx.Index.Packets[0].ChannelID)}, true, nil
	}
	diag, executed := eng.runRuleOnce(&Context{}, base, rule, fn, ruleFilter{channels: []uint16{2}}, true)
	if !executed {
		t.Fatalf("expected rule to execute")
	}
	if diag.PacketIndex != 1 || diag.ChannelId != 2 || !diag.FixApplied {
		t.Fatalf("unexpected diagnostic: %+v", diag)
	}

	errFn := func(ctx *Context, r Rule) (Diagnostic, bool, error) {
		return Diagnostic{RuleId: r.RuleId, Message: "failed"}, false, errors.New("boom")
	}
	diag, executed = eng.runRuleOnce(&Context{}, base, rule, errFn, ruleFilter{}, false)
	if !executed || diag.Severity != ERROR || !strings.Contains(diag.Message, "boom") {
		t.Fatalf("expected error diagnostic, got %+v", diag)
	}
}
