package rules

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"example.com/ch10gate/internal/ch10"
	"example.com/ch10gate/internal/common"
	"example.com/ch10gate/internal/eth"
	"example.com/ch10gate/internal/tmats"
)

const (
	ch10PrimaryHeaderSize   = 20
	ch10SecondaryHeaderSize = 12
)

const (
	pcmBitIPH         = uint32(1) << 30
	pcmBitMajorFrame  = uint32(1) << 29
	pcmBitMinorFrame  = uint32(1) << 28
	pcmBitAlignment32 = uint32(1) << 21
	pcmBitThroughput  = uint32(1) << 20
	pcmBitPacked      = uint32(1) << 19
	pcmBitUnpacked    = uint32(1) << 18
	pcmMaskSyncOffset = uint32(0x3FFFF)
)

func int64Ptr(v int64) *int64 { return &v }

func intPtr(v int) *int { return &v }

func stringPtr(s string) *string { return &s }

func nextUnusedChannelID(used map[uint16]bool) uint16 {
	var id uint16 = 1
	for {
		if !used[id] {
			used[id] = true
			return id
		}
		id++
		if id == 0 {
			id = 1
		}
	}
}

func formatOffsetRange(offset int64, length int) string {
	if length <= 0 {
		return ""
	}
	if length == 1 {
		return fmt.Sprintf("0x%X", offset)
	}
	end := offset + int64(length) - 1
	return fmt.Sprintf("0x%X-0x%X", offset, end)
}

func appendAuditEntries(ctx *Context, rule Rule, edits []ch10.PatchEdit) error {
	if ctx == nil || ctx.AuditLog == nil || ctx.InputFile == "" {
		return nil
	}
	if len(edits) == 0 {
		return nil
	}
	f, err := os.Open(ctx.InputFile)
	if err != nil {
		return err
	}
	defer f.Close()
	ref := ""
	if len(rule.Refs) > 0 {
		ref = rule.Refs[0]
	}
	for _, edit := range edits {
		if len(edit.Data) == 0 {
			continue
		}
		before := make([]byte, len(edit.Data))
		if _, err := f.ReadAt(before, edit.Offset); err != nil {
			return err
		}
		entry := common.PatchEntry{
			RuleID:    rule.RuleId,
			Ref:       ref,
			Offset:    edit.Offset,
			Range:     formatOffsetRange(edit.Offset, len(edit.Data)),
			BeforeHex: strings.ToUpper(hex.EncodeToString(before)),
			AfterHex:  strings.ToUpper(hex.EncodeToString(edit.Data)),
			Ts:        time.Now().UTC(),
		}
		if err := ctx.AuditLog.Append(entry); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) RegisterBuiltins() {
	e.Register("CheckSyncPattern", CheckSyncPattern)
	e.Register("FixHeaderChecksum", FixHeaderChecksum)
	e.Register("FixDataChecksumOrTrailer", FixDataChecksumOrTrailer)
	e.Register("SyncSecondaryHeaderFlag", SyncSecondaryHeaderFlag)
	e.Register("FixLengths", FixLengths)
	e.Register("RemapChannelIds", RemapChannelIds)
	e.Register("RenumberSeq", RenumberSeq)
	e.Register("BlockUnknownDataType", BlockUnknownDataType)
	e.Register("EnsureTimePacket", EnsureTimePacket)
	e.Register("FixPCMAlign", FixPCMAlign)
	e.Register("Check1553IpdhLen", Check1553IpdhLen)
	e.Register("Warn1553Ttb", Warn1553Ttb)
	e.Register("FixA429Gap", FixA429Gap)
	e.Register("WarnA429Parity", WarnA429Parity)
	e.Register("AddEthIPH", AddEthIPH)
	e.Register("FixA664Lens", FixA664Lens)
	e.Register("UpdateTMATSDigest", UpdateTMATSDigest)
	e.Register("NormalizeTMATSChannelMap", NormalizeTMATSChannelMap)
	e.Register("SyncSecondaryTimeFmt", SyncSecondaryTimeFmt)
	e.Register("ValidateAgainstDictionaries", ValidateAgainstDictionaries)
	e.Register("ValidateOrRebuildDirectory", ValidateOrRebuildDirectory)
	e.Register("FixFileExtension", FixFileExtension)
}

func CheckSyncPattern(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	if err := ctx.EnsureFileIndex(); err != nil {
		return Diagnostic{
			Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR,
			Message: "cannot parse first header", Refs: rule.Refs, FixSuggested: false,
		}, false, err
	}
	if ctx.PrimaryHeader == nil {
		return Diagnostic{
			Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR,
			Message: "no primary header found", Refs: rule.Refs, FixSuggested: false,
		}, false, nil
	}
	hdr := *ctx.PrimaryHeader
	if hdr.Sync != 0xEB25 {
		return Diagnostic{
			Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR,
			Message: "sync pattern not 0xEB25", Refs: rule.Refs, FixSuggested: false,
		}, false, nil
	}
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO,
		Message: "sync pattern ok", Refs: rule.Refs, FixSuggested: false,
	}, false, nil
}

func FixHeaderChecksum(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{
		Ts:       time.Now(),
		File:     ctx.InputFile,
		RuleId:   rule.RuleId,
		Severity: INFO,
		Message:  "header checksum verification skipped",
		Refs:     rule.Refs,
	}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if ctx.Index == nil {
		if err := ctx.EnsureFileIndex(); err != nil {
			diag.Severity = ERROR
			diag.Message = "cannot index file"
			return diag, false, err
		}
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}
	f, err := os.Open(ctx.InputFile)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot open input file"
		return diag, false, err
	}
	defer f.Close()

	header := make([]byte, ch10PrimaryHeaderSize)
	var edits []ch10.PatchEdit
	var mismatched int
	for _, pkt := range ctx.Index.Packets {
		if _, err := f.ReadAt(header, pkt.Offset); err != nil {
			diag.Severity = ERROR
			diag.Message = fmt.Sprintf("read header at offset %d failed", pkt.Offset)
			return diag, false, err
		}
		stored := binary.BigEndian.Uint16(header[16:18])
		computed, err := ch10.ComputeHeaderChecksum(ctx.Profile, header)
		if err != nil {
			diag.Severity = ERROR
			diag.Message = "cannot compute header checksum"
			return diag, false, err
		}
		if stored == computed {
			continue
		}
		mismatched++
		buf := []byte{byte(computed >> 8), byte(computed)}
		edits = append(edits, ch10.PatchEdit{Offset: pkt.Offset + 16, Data: buf})
	}

	if mismatched == 0 {
		diag.Message = "header checksums verified"
		return diag, false, nil
	}
	if err := appendAuditEntries(ctx, rule, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = fmt.Sprintf("failed to record audit trail: %v", err)
		return diag, false, err
	}
	if err := ch10.ApplyPatch(ctx.InputFile, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to update header checksum"
		return diag, false, err
	}
	diag.Message = fmt.Sprintf("fixed header checksum on %d packets", mismatched)
	diag.FixSuggested = true
	return diag, true, nil
}

func FixDataChecksumOrTrailer(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{
		Ts:       time.Now(),
		File:     ctx.InputFile,
		RuleId:   rule.RuleId,
		Severity: INFO,
		Message:  "data checksum verification skipped",
		Refs:     rule.Refs,
	}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if ctx.Index == nil {
		if err := ctx.EnsureFileIndex(); err != nil {
			diag.Severity = ERROR
			diag.Message = "cannot index file"
			return diag, false, err
		}
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}
	f, err := os.Open(ctx.InputFile)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot open input file"
		return diag, false, err
	}
	info, statErr := f.Stat()
	if statErr != nil {
		f.Close()
		diag.Severity = ERROR
		diag.Message = "cannot stat input file"
		return diag, false, statErr
	}
	size := info.Size()
	header := make([]byte, ch10PrimaryHeaderSize)
	buf := make([]byte, 64*1024)
	var edits []ch10.PatchEdit
	var mismatched int

	for _, pkt := range ctx.Index.Packets {
		if _, err := f.ReadAt(header, pkt.Offset); err != nil {
			f.Close()
			diag.Severity = ERROR
			diag.Message = fmt.Sprintf("read header at offset %d failed", pkt.Offset)
			return diag, false, err
		}
		storedChecksum := binary.BigEndian.Uint16(header[18:20])
		pktLen := binary.BigEndian.Uint32(header[4:8])
		totalLen := int64(pktLen) + 4
		if totalLen < ch10PrimaryHeaderSize {
			continue
		}
		dataOffset := pkt.Offset + ch10PrimaryHeaderSize
		if dataOffset >= size {
			continue
		}
		dataLen := totalLen - ch10PrimaryHeaderSize
		maxAvail := size - dataOffset
		if maxAvail < 0 {
			maxAvail = 0
		}
		if dataLen > maxAvail {
			dataLen = maxAvail
		}
		remaining := dataLen
		calc, err := ch10.NewDataChecksum(ctx.Profile)
		if err != nil {
			f.Close()
			diag.Severity = ERROR
			diag.Message = "cannot init data checksum"
			return diag, false, err
		}
		offset := dataOffset
		for remaining > 0 {
			chunk := int64(len(buf))
			if remaining < chunk {
				chunk = remaining
			}
			if chunk <= 0 {
				break
			}
			n, err := f.ReadAt(buf[:int(chunk)], offset)
			if err != nil && err != io.EOF {
				f.Close()
				diag.Severity = ERROR
				diag.Message = fmt.Sprintf("read payload at offset %d failed", offset)
				return diag, false, err
			}
			if n == 0 {
				break
			}
			calc.Write(buf[:n])
			remaining -= int64(n)
			offset += int64(n)
			if int64(n) < chunk {
				break
			}
		}
		computed := calc.Sum16()
		if computed == storedChecksum {
			continue
		}
		mismatched++
		buf2 := []byte{byte(computed >> 8), byte(computed)}
		edits = append(edits, ch10.PatchEdit{Offset: pkt.Offset + 18, Data: buf2})
	}
	f.Close()

	if mismatched == 0 {
		diag.Message = "data checksums verified"
		return diag, false, nil
	}
	if err := appendAuditEntries(ctx, rule, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = fmt.Sprintf("failed to record audit trail: %v", err)
		return diag, false, err
	}
	if err := ch10.ApplyPatch(ctx.InputFile, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to update data checksum"
		return diag, false, err
	}
	diag.Message = fmt.Sprintf("fixed data checksum on %d packets", mismatched)
	diag.FixSuggested = true
	return diag, true, nil
}

func SyncSecondaryHeaderFlag(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO,
		Message: "skipped (implemented in Part 2)", Refs: rule.Refs,
	}, false, nil
}

func FixLengths(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{
		Ts:       time.Now(),
		File:     ctx.InputFile,
		RuleId:   rule.RuleId,
		Severity: INFO,
		Message:  "length verification skipped",
		Refs:     rule.Refs,
	}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if ctx.Index == nil {
		if err := ctx.EnsureFileIndex(); err != nil {
			diag.Severity = ERROR
			diag.Message = "cannot index file"
			return diag, false, err
		}
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}
	f, err := os.Open(ctx.InputFile)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot open input file"
		return diag, false, err
	}
	info, statErr := f.Stat()
	if statErr != nil {
		f.Close()
		diag.Severity = ERROR
		diag.Message = "cannot stat input file"
		return diag, false, statErr
	}
	size := info.Size()
	header := make([]byte, ch10PrimaryHeaderSize)
	buf := make([]byte, 64*1024)

	var edits []ch10.PatchEdit
	var fixed int

	for _, pkt := range ctx.Index.Packets {
		if _, err := f.ReadAt(header, pkt.Offset); err != nil {
			f.Close()
			diag.Severity = ERROR
			diag.Message = fmt.Sprintf("read header at offset %d failed", pkt.Offset)
			return diag, false, err
		}
		storedPacketLen := binary.BigEndian.Uint32(header[4:8])
		storedDataLen := binary.BigEndian.Uint32(header[8:12])
		storedChecksum := binary.BigEndian.Uint16(header[18:20])

		totalLen := int64(storedPacketLen) + 4
		if totalLen < ch10PrimaryHeaderSize {
			continue
		}
		dataOffset := pkt.Offset + ch10PrimaryHeaderSize
		if dataOffset > size {
			continue
		}
		maxAvail := size - dataOffset
		if maxAvail < 0 {
			maxAvail = 0
		}
		dataLenFromPacket := totalLen - ch10PrimaryHeaderSize
		if dataLenFromPacket < 0 {
			dataLenFromPacket = 0
		}
		if dataLenFromPacket > maxAvail {
			dataLenFromPacket = maxAvail
		}

		calcFull, err := ch10.NewDataChecksum(ctx.Profile)
		if err != nil {
			f.Close()
			diag.Severity = ERROR
			diag.Message = "cannot init data checksum"
			return diag, false, err
		}
		var calcStored *ch10.DataChecksum
		remainingStored := int64(storedDataLen)
		storedValid := remainingStored <= dataLenFromPacket
		if storedValid {
			calcStored, err = ch10.NewDataChecksum(ctx.Profile)
			if err != nil {
				f.Close()
				diag.Severity = ERROR
				diag.Message = "cannot init data checksum"
				return diag, false, err
			}
		}

		remainingFull := dataLenFromPacket
		offset := dataOffset
		for remainingFull > 0 {
			chunk := int64(len(buf))
			if remainingFull < chunk {
				chunk = remainingFull
			}
			if chunk <= 0 {
				break
			}
			n, err := f.ReadAt(buf[:int(chunk)], offset)
			if err != nil && err != io.EOF {
				f.Close()
				diag.Severity = ERROR
				diag.Message = fmt.Sprintf("read payload at offset %d failed", offset)
				return diag, false, err
			}
			if n == 0 {
				break
			}
			calcFull.Write(buf[:n])
			if calcStored != nil && remainingStored > 0 {
				portion := n
				if int64(portion) > remainingStored {
					portion = int(remainingStored)
				}
				if portion > 0 {
					calcStored.Write(buf[:portion])
					remainingStored -= int64(portion)
				}
			}
			remainingFull -= int64(n)
			offset += int64(n)
			if int64(n) < chunk {
				break
			}
		}
		if calcStored != nil && remainingStored > 0 {
			storedValid = false
		}

		crcFull := calcFull.Sum16()
		var crcStored uint16
		if calcStored != nil && storedValid {
			crcStored = calcStored.Sum16()
		}

		storedMatches := storedValid && crcStored == storedChecksum
		fullMatches := crcFull == storedChecksum

		targetDataLen := uint32(dataLenFromPacket)
		switch {
		case storedMatches:
			targetDataLen = storedDataLen
		case fullMatches:
			targetDataLen = uint32(dataLenFromPacket)
		default:
			targetDataLen = uint32(dataLenFromPacket)
		}
		targetPacketLen := targetDataLen + uint32(ch10PrimaryHeaderSize) - 4

		packetChanged := false
		if storedDataLen != targetDataLen {
			var out [4]byte
			binary.BigEndian.PutUint32(out[:], targetDataLen)
			edits = append(edits, ch10.PatchEdit{Offset: pkt.Offset + 8, Data: out[:]})
			packetChanged = true
		}
		if storedPacketLen != targetPacketLen {
			var out [4]byte
			binary.BigEndian.PutUint32(out[:], targetPacketLen)
			edits = append(edits, ch10.PatchEdit{Offset: pkt.Offset + 4, Data: out[:]})
			packetChanged = true
		}
		if packetChanged {
			fixed++
		}
	}
	f.Close()

	if len(edits) == 0 {
		diag.Message = "packet/data lengths verified"
		return diag, false, nil
	}
	if err := appendAuditEntries(ctx, rule, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = fmt.Sprintf("failed to record audit trail: %v", err)
		return diag, false, err
	}
	if err := ch10.ApplyPatch(ctx.InputFile, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to update length fields"
		return diag, false, err
	}
	diag.Message = fmt.Sprintf("updated length fields in %d packets", fixed)
	diag.FixSuggested = true
	return diag, true, nil
}

func RemapChannelIds(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "channel id remap inspection", Refs: rule.Refs}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if ctx.Profile == "" {
		diag.Severity = ERROR
		diag.Message = "profile required"
		return diag, false, errors.New("profile required")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	used := make(map[uint16]bool)
	zeroCount := 0
	firstIdx := -1
	var firstPkt *ch10.PacketIndex
	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if pkt.ChannelID == 0 {
			zeroCount++
			if firstIdx < 0 {
				firstIdx = i
				firstPkt = pkt
			}
			continue
		}
		used[pkt.ChannelID] = true
	}

	if zeroCount == 0 {
		diag.Message = "channel ids already non-zero"
		return diag, false, nil
	}

	newID := nextUnusedChannelID(used)
	remap := map[uint16]uint16{0: newID}

	plan := &ch10.StructuralPlan{ChannelRemap: remap}
	outPath := ctx.InputFile + ".fixed.ch10"
	if err := ch10.RewriteWithPlan(ctx.InputFile, outPath, ctx.Profile, ctx.Index, plan); err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to rewrite file with new channel id"
		return diag, false, err
	}

	diag.FixSuggested = true
	diag.FixApplied = true
	diag.FixPatchId = filepath.Base(outPath)
	diag.Message = fmt.Sprintf("remapped %d packet(s) from channel id 0 to %d, wrote %s", zeroCount, newID, filepath.Base(outPath))
	if firstIdx >= 0 && firstPkt != nil {
		diag.PacketIndex = firstIdx
		diag.ChannelId = int(newID)
		diag.Offset = fmt.Sprintf("0x%X", firstPkt.Offset)
		if firstPkt.TimeStampUs >= 0 {
			diag.TimestampUs = int64Ptr(firstPkt.TimeStampUs)
			src := string(firstPkt.Source)
			diag.TimestampSource = stringPtr(src)
		}
	}

	if tmatsPath, err := annotateTMATSModified(ctx, rule, "Channel ID remap"); err != nil {
		diag.Severity = WARN
		diag.Message += fmt.Sprintf(" (TMATS update failed: %v)", err)
	} else if tmatsPath != "" {
		diag.Message += fmt.Sprintf(", updated TMATS %s", filepath.Base(tmatsPath))
	}

	return diag, true, nil
}

func RenumberSeq(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "sequence renumber inspection", Refs: rule.Refs}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if ctx.Profile == "" {
		diag.Severity = ERROR
		diag.Message = "profile required"
		return diag, false, errors.New("profile required")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	type seqState struct {
		next     uint8
		needs    bool
		firstIdx int
		firstPkt *ch10.PacketIndex
	}

	states := make(map[uint16]*seqState)
	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		st := states[pkt.ChannelID]
		if st == nil {
			st = &seqState{next: pkt.SeqNum + 1, firstIdx: i, firstPkt: pkt}
			states[pkt.ChannelID] = st
			continue
		}
		if pkt.SeqNum != st.next {
			st.needs = true
		}
		st.next = pkt.SeqNum + 1
	}

	var channels []uint16
	for ch, st := range states {
		if st.needs {
			channels = append(channels, ch)
		}
	}
	if len(channels) == 0 {
		diag.Message = "channel sequences already continuous"
		return diag, false, nil
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i] < channels[j] })

	plan := &ch10.StructuralPlan{RenumberChannels: make(map[uint16]bool)}
	for _, ch := range channels {
		plan.RenumberChannels[ch] = true
	}

	outPath := ctx.InputFile + ".fixed.ch10"
	if err := ch10.RewriteWithPlan(ctx.InputFile, outPath, ctx.Profile, ctx.Index, plan); err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to renumber channel sequences"
		return diag, false, err
	}

	diag.FixSuggested = true
	diag.FixApplied = true
	diag.FixPatchId = filepath.Base(outPath)
	diag.Message = fmt.Sprintf("renumbered sequences for %d channel(s), wrote %s", len(channels), filepath.Base(outPath))
	firstCh := channels[0]
	if st := states[firstCh]; st != nil && st.firstPkt != nil {
		diag.PacketIndex = st.firstIdx
		diag.ChannelId = int(firstCh)
		diag.Offset = fmt.Sprintf("0x%X", st.firstPkt.Offset)
		if st.firstPkt.TimeStampUs >= 0 {
			diag.TimestampUs = int64Ptr(st.firstPkt.TimeStampUs)
			src := string(st.firstPkt.Source)
			diag.TimestampSource = stringPtr(src)
		}
	}

	if tmatsPath, err := annotateTMATSModified(ctx, rule, "Sequence renumber"); err != nil {
		diag.Severity = WARN
		diag.Message += fmt.Sprintf(" (TMATS update failed: %v)", err)
	} else if tmatsPath != "" {
		diag.Message += fmt.Sprintf(", updated TMATS %s", filepath.Base(tmatsPath))
	}

	return diag, true, nil
}

func BlockUnknownDataType(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	if err := ctx.EnsureFileIndex(); err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR, Message: "cannot parse", Refs: rule.Refs}, false, err
	}
	if ctx.PrimaryHeader == nil {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR, Message: "no primary header", Refs: rule.Refs}, false, nil
	}
	hdr := *ctx.PrimaryHeader
	if hdr.DataType > 0x80 {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR, Message: fmt.Sprintf("unknown data type 0x%X", hdr.DataType), Refs: rule.Refs}, false, nil
	}
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "data type within provisional range", Refs: rule.Refs}, false, nil
}

func annotateTMATSModified(ctx *Context, rule Rule, detail string) (string, error) {
	if ctx == nil || ctx.TMATSFile == "" {
		return "", nil
	}
	doc, err := tmats.Parse(ctx.TMATSFile)
	if err != nil {
		return "", err
	}
	recordGroup := inferTMATSRecordGroup(doc)
	changed := false
	if doc.Set(fmt.Sprintf("%s\\RI3", recordGroup), "MODIFIED") {
		changed = true
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	ri6 := fmt.Sprintf("%s at %s", detail, timestamp)
	if doc.Set(fmt.Sprintf("%s\\RI6", recordGroup), ri6) {
		changed = true
	}
	comment := fmt.Sprintf("Modified recording (%s): %s", rule.RuleId, ri6)
	if doc.EnsureCommentWithTag(rule.RuleId, comment) {
		changed = true
	}
	digest, err := doc.ComputeDigest()
	if err != nil {
		return "", err
	}
	if doc.Set("G\\SHA", digest) {
		changed = true
	}
	if !changed {
		return "", nil
	}
	outPath := ctx.TMATSFile + ".tmats.fixed"
	if err := os.WriteFile(outPath, []byte(doc.String()), 0644); err != nil {
		return "", err
	}
	return outPath, nil
}

func EnsureTimePacket(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "time packet inspection", Refs: rule.Refs}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if ctx.Profile == "" {
		diag.Severity = ERROR
		diag.Message = "profile required"
		return diag, false, errors.New("profile required")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	idx := ctx.Index

	var (
		firstTimeIdx       = -1
		firstDynamicIdx    = -1
		firstTimePacket    *ch10.PacketIndex
		firstDynamicPacket *ch10.PacketIndex
		missingSecHdrIdx   = -1
		unsupportedIdx     = -1
	)

	for i := range idx.Packets {
		pkt := &idx.Packets[i]
		if pkt.IsTimePacket {
			if firstTimeIdx == -1 {
				firstTimeIdx = i
				firstTimePacket = pkt
			}
			continue
		}
		if firstDynamicIdx == -1 {
			firstDynamicIdx = i
			firstDynamicPacket = pkt
		}
		if pkt.HasSecHdr && !pkt.SecHdrBytes {
			missingSecHdrIdx = i
			break
		}
		if pkt.HasSecHdr && pkt.SecHdrBytes && !pkt.SecHdrValid && unsupportedIdx == -1 {
			unsupportedIdx = i
		}
	}

	if firstTimePacket != nil && firstTimePacket.TimeStampUs >= 0 {
		diag.TimestampUs = int64Ptr(firstTimePacket.TimeStampUs)
		src := string(firstTimePacket.Source)
		diag.TimestampSource = stringPtr(src)
	} else if firstDynamicPacket != nil && firstDynamicPacket.TimeStampUs >= 0 {
		diag.TimestampUs = int64Ptr(firstDynamicPacket.TimeStampUs)
		src := string(firstDynamicPacket.Source)
		diag.TimestampSource = stringPtr(src)
	}

	if missingSecHdrIdx >= 0 {
		pkt := idx.Packets[missingSecHdrIdx]
		diag.Severity = ERROR
		diag.PacketIndex = missingSecHdrIdx
		diag.ChannelId = int(pkt.ChannelID)
		diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
		diag.Message = "secondary header flag set but bytes missing"
		return diag, false, nil
	}

	if unsupportedIdx >= 0 {
		pkt := idx.Packets[unsupportedIdx]
		diag.Severity = WARN
		diag.PacketIndex = unsupportedIdx
		diag.ChannelId = int(pkt.ChannelID)
		diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
		diag.Message = "secondary header time format unsupported"
		if diag.TimestampUs == nil && pkt.TimeStampUs >= 0 {
			diag.TimestampUs = int64Ptr(pkt.TimeStampUs)
			src := string(pkt.Source)
			diag.TimestampSource = stringPtr(src)
		}
		return diag, false, nil
	}

	needInsert := false
	if !idx.HasTimePacket {
		needInsert = true
	} else if !idx.TimeSeenBeforeDynamic {
		needInsert = true
	}

	if !needInsert {
		diag.Message = "time packet present before first dynamic packet"
		if firstTimeIdx >= 0 {
			pkt := idx.Packets[firstTimeIdx]
			diag.PacketIndex = firstTimeIdx
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
		}
		return diag, false, nil
	}

	insertBefore := 0
	if firstDynamicIdx >= 0 {
		insertBefore = firstDynamicIdx
	}

	used := make(map[uint16]bool)
	for i := range idx.Packets {
		pkt := idx.Packets[i]
		if pkt.ChannelID != 0 {
			used[pkt.ChannelID] = true
		}
	}

	channelID := uint16(0)
	if firstTimePacket != nil {
		channelID = firstTimePacket.ChannelID
	}
	remap := make(map[uint16]uint16)
	if channelID == 0 {
		channelID = nextUnusedChannelID(used)
		if idx.HasTimePacket {
			remap[0] = channelID
		}
	}
	if channelID == 0 {
		channelID = nextUnusedChannelID(used)
	}

	timeFormat := uint8(0)
	if firstTimePacket != nil && firstTimePacket.HasSecHdr {
		timeFormat = firstTimePacket.TimeFormat
	} else if firstDynamicPacket != nil && firstDynamicPacket.HasSecHdr {
		timeFormat = firstDynamicPacket.TimeFormat
	}

	timestamp := int64(0)
	if firstTimePacket != nil && firstTimePacket.TimeStampUs >= 0 {
		timestamp = firstTimePacket.TimeStampUs
	} else if firstDynamicPacket != nil && firstDynamicPacket.TimeStampUs >= 0 {
		timestamp = firstDynamicPacket.TimeStampUs
	}
	if timestamp < 0 {
		timestamp = 0
	}

	packet, err := ch10.BuildTimePacket(ctx.Profile, channelID, timeFormat, timestamp)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to build time packet"
		return diag, false, err
	}

	plan := &ch10.StructuralPlan{
		Inserts:          []ch10.PacketInsert{{BeforeIndex: insertBefore, Packet: packet}},
		RenumberChannels: map[uint16]bool{channelID: true},
	}
	if len(remap) > 0 {
		plan.ChannelRemap = remap
	}

	outPath := ctx.InputFile + ".fixed.ch10"
	if err := ch10.RewriteWithPlan(ctx.InputFile, outPath, ctx.Profile, ctx.Index, plan); err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to insert time packet"
		return diag, false, err
	}

	reason := "missing time packet"
	if idx.HasTimePacket && !idx.TimeSeenBeforeDynamic {
		reason = "time packet observed after dynamic data"
	}

	diag.FixSuggested = true
	diag.FixApplied = true
	diag.FixPatchId = filepath.Base(outPath)
	diag.Severity = INFO
	diag.Message = fmt.Sprintf("inserted time reference packet on channel %d (%s), wrote %s", channelID, reason, filepath.Base(outPath))
	diag.ChannelId = int(channelID)
	diag.PacketIndex = insertBefore
	if insertBefore >= 0 && insertBefore < len(idx.Packets) {
		diag.Offset = fmt.Sprintf("0x%X", idx.Packets[insertBefore].Offset)
	} else if len(idx.Packets) > 0 {
		last := idx.Packets[len(idx.Packets)-1]
		diag.Offset = fmt.Sprintf("0x%X", last.Offset+int64(last.PacketLength)+4)
	} else {
		diag.Offset = "0x0"
	}
	diag.TimestampUs = int64Ptr(timestamp)
	src := string(ch10.TimestampSourceTimePacket)
	diag.TimestampSource = stringPtr(src)

	if tmatsPath, err := annotateTMATSModified(ctx, rule, fmt.Sprintf("Inserted time packet (%s)", reason)); err != nil {
		diag.Severity = WARN
		diag.Message += fmt.Sprintf(" (TMATS update failed: %v)", err)
	} else if tmatsPath != "" {
		diag.Message += fmt.Sprintf(", updated TMATS %s", filepath.Base(tmatsPath))
	}

	return diag, true, nil
}

func pcmChecksumLength(flags uint8) int {
	switch flags & 0x3 {
	case 1:
		return 1
	case 2:
		return 2
	case 3:
		return 4
	default:
		return 0
	}
}

func normalizePCMCSDW(info *ch10.PCMInfo) uint32 {
	if info == nil {
		return 0
	}
	hasIPH := info.HasIPH
	major := info.MajorFrame
	minor := info.MinorFrame
	minorStatus := info.MinorStatus
	majorStatus := info.MajorStatus
	throughput := info.Throughput
	packed := info.Packed
	unpacked := info.Unpacked
	syncOffset := info.SyncOffset

	if !hasIPH && !throughput {
		throughput = true
	}
	if throughput {
		packed = false
		unpacked = false
		hasIPH = false
		major = false
		minor = false
		minorStatus = 0
		majorStatus = 0
		syncOffset = 0
	} else {
		hasIPH = true
		if packed && unpacked {
			if syncOffset != 0 {
				packed = false
				unpacked = true
			} else {
				packed = true
				unpacked = false
			}
		} else if !packed && !unpacked {
			if syncOffset != 0 {
				unpacked = true
			} else {
				packed = true
			}
		}
		if packed {
			syncOffset = 0
		}
	}

	var csdw uint32
	if hasIPH {
		csdw |= pcmBitIPH
	}
	if major && !throughput {
		csdw |= pcmBitMajorFrame
	}
	if minor && !throughput {
		csdw |= pcmBitMinorFrame
	}
	if !throughput {
		csdw |= uint32(minorStatus&0x3) << 26
		csdw |= uint32(majorStatus&0x3) << 24
	}
	if info.AlignmentBits == 32 {
		csdw |= pcmBitAlignment32
	}
	if throughput {
		csdw |= pcmBitThroughput
	}
	if packed {
		csdw |= pcmBitPacked
	}
	if unpacked {
		csdw |= pcmBitUnpacked
	}
	csdw |= syncOffset & pcmMaskSyncOffset
	return csdw
}

func FixPCMAlign(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{
		Ts:       time.Now(),
		File:     ctx.InputFile,
		RuleId:   rule.RuleId,
		Severity: INFO,
		Message:  "PCM alignment verified",
		Refs:     rule.Refs,
	}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if ctx.Index == nil {
		if err := ctx.EnsureFileIndex(); err != nil {
			diag.Severity = ERROR
			diag.Message = "cannot index file"
			return diag, false, err
		}
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	f, err := os.Open(ctx.InputFile)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot open input file"
		return diag, false, err
	}
	defer f.Close()

	var edits []ch10.PatchEdit
	var headerFixes, fillerFixes int
	modifiedPackets := 0
	modified := make(map[int]struct{})
	firstFixIdx := -1
	var firstPkt *ch10.PacketIndex

	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if pkt.DataType != 0x08 {
			continue
		}

		payloadOffset := pkt.Offset + ch10PrimaryHeaderSize
		secLen := 0
		if pkt.HasSecHdr {
			payloadOffset += int64(ch10SecondaryHeaderSize)
			secLen = ch10SecondaryHeaderSize
		}

		dataLen := int(pkt.DataLength)
		if dataLen < 0 {
			dataLen = 0
		}
		if pkt.HasSecHdr {
			if dataLen >= ch10SecondaryHeaderSize {
				dataLen -= ch10SecondaryHeaderSize
			} else {
				dataLen = 0
			}
		}

		totalLen := int(pkt.PacketLength) + 4
		trailerLen := totalLen - ch10PrimaryHeaderSize - secLen - dataLen
		if trailerLen < 0 {
			trailerLen = 0
		}
		checksumLen := pcmChecksumLength(pkt.Flags)
		if checksumLen > trailerLen {
			checksumLen = trailerLen
		}
		fillerLen := trailerLen - checksumLen
		if fillerLen < 0 {
			fillerLen = 0
		}
		fillerOffset := payloadOffset + int64(dataLen)

		pcmInfo := pkt.PCM
		if pcmInfo == nil && dataLen >= 4 {
			var csdwBuf [4]byte
			if _, err := f.ReadAt(csdwBuf[:], payloadOffset); err == nil {
				decoded := ch10.DecodePCMCSDW(binary.BigEndian.Uint32(csdwBuf[:]))
				pcmInfo = &decoded
			}
		}
		if pcmInfo == nil {
			continue
		}

		newCsdw := normalizePCMCSDW(pcmInfo)
		if newCsdw != pcmInfo.CSDW {
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], newCsdw)
			edits = append(edits, ch10.PatchEdit{Offset: payloadOffset, Data: buf[:]})
			headerFixes++
			if _, seen := modified[i]; !seen {
				modified[i] = struct{}{}
				modifiedPackets++
			}
			if firstFixIdx < 0 {
				firstFixIdx = i
				firstPkt = pkt
			}
		}

		if fillerLen > 0 {
			filler := make([]byte, fillerLen)
			if _, err := f.ReadAt(filler, fillerOffset); err != nil && !errors.Is(err, io.EOF) {
				diag.Severity = ERROR
				diag.Message = fmt.Sprintf("cannot read PCM filler at offset 0x%X", fillerOffset)
				return diag, false, err
			}
			valid := true
			for _, b := range filler {
				if b != 0x00 && b != 0xFF {
					valid = false
					break
				}
			}
			if !valid {
				replacement := make([]byte, fillerLen)
				edits = append(edits, ch10.PatchEdit{Offset: fillerOffset, Data: replacement})
				fillerFixes++
				if _, seen := modified[i]; !seen {
					modified[i] = struct{}{}
					modifiedPackets++
				}
				if firstFixIdx < 0 {
					firstFixIdx = i
					firstPkt = pkt
				}
			}
		}
	}

	if headerFixes == 0 && fillerFixes == 0 {
		var pcmCount int
		for _, pkt := range ctx.Index.Packets {
			if pkt.DataType == 0x08 {
				pcmCount++
			}
		}
		if pcmCount == 0 {
			diag.Message = "no PCM Format 1 packets detected"
		}
		return diag, false, nil
	}

	if err := appendAuditEntries(ctx, rule, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = fmt.Sprintf("failed to record audit trail: %v", err)
		return diag, false, err
	}

	if err := ch10.ApplyPatch(ctx.InputFile, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to apply PCM alignment fixes"
		return diag, false, err
	}

	diag.FixSuggested = true
	diag.Message = fmt.Sprintf("fixed PCM alignment on %d packet(s) (%d header, %d filler)", modifiedPackets, headerFixes, fillerFixes)
	if firstFixIdx >= 0 && firstPkt != nil {
		diag.PacketIndex = firstFixIdx
		diag.ChannelId = int(firstPkt.ChannelID)
		diag.Offset = fmt.Sprintf("0x%X", firstPkt.Offset)
	}
	return diag, true, nil
}

func Check1553IpdhLen(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "1553 16PP194 IPDH lengths verified", Refs: rule.Refs}
	if ctx == nil {
		diag.Severity = ERROR
		diag.Message = "no context provided"
		return diag, false, errors.New("nil context")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	var found bool
	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if pkt.DataType != 0x19 {
			continue
		}
		found = true
		diag.PacketIndex = i
		diag.ChannelId = int(pkt.ChannelID)
		diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
		if pkt.MIL1553 == nil {
			diag.Severity = ERROR
			diag.Message = "1553 payload details unavailable"
			return diag, false, nil
		}
		info := pkt.MIL1553
		if info.ParseError != "" {
			diag.Severity = ERROR
			diag.Message = fmt.Sprintf("cannot inspect 16PP194 IPDH (%s)", info.ParseError)
			return diag, false, nil
		}
		for msgIdx, msg := range info.Messages {
			if msg.IPDHLength != 0x18 {
				diag.Severity = ERROR
				diag.Message = fmt.Sprintf("%s (message %d length=0x%X)", rule.Message, msgIdx+1, msg.IPDHLength)
				if pkt.TimeStampUs >= 0 {
					diag.TimestampUs = int64Ptr(pkt.TimeStampUs)
					src := string(pkt.Source)
					diag.TimestampSource = stringPtr(src)
				}
				return diag, false, nil
			}
		}
	}

	if !found {
		diag.Message = "no 16PP194 packets detected"
	}
	return diag, false, nil
}

func Warn1553Ttb(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "1553 TTB values verified", Refs: rule.Refs}
	if ctx == nil {
		diag.Severity = ERROR
		diag.Message = "no context provided"
		return diag, false, errors.New("nil context")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	var found bool
	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if pkt.DataType != 0x18 {
			continue
		}
		found = true
		if pkt.MIL1553 == nil {
			diag.Severity = WARN
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			diag.Message = "1553 CSDW not parsed"
			return diag, false, nil
		}
		info := pkt.MIL1553
		if info.ParseError != "" {
			diag.Severity = WARN
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			diag.Message = fmt.Sprintf("TTB not inspected (%s)", info.ParseError)
			return diag, false, nil
		}
		if info.TTB == 0x3 {
			diag.Severity = WARN
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			diag.Message = fmt.Sprintf("%s (value=0x%X)", rule.Message, info.TTB)
			if pkt.TimeStampUs >= 0 {
				diag.TimestampUs = int64Ptr(pkt.TimeStampUs)
				src := string(pkt.Source)
				diag.TimestampSource = stringPtr(src)
			}
			return diag, false, nil
		}
	}

	if !found {
		diag.Message = "no MIL-STD-1553 format 1 packets detected"
	}
	return diag, false, nil
}

func FixA429Gap(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "ARINC-429 gap inspection", Refs: rule.Refs}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if ctx.Profile == "" {
		diag.Severity = ERROR
		diag.Message = "profile required"
		return diag, false, errors.New("profile required")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	const gapLimit = 1_000_000
	splits := make(map[int][]int)
	var (
		firstPktIdx  = -1
		firstWordIdx = -1
		firstPacket  ch10.PacketIndex
		violations   int
	)

	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if pkt.DataType != 0x38 {
			continue
		}
		info := pkt.A429
		if info == nil {
			diag.Severity = ERROR
			diag.Message = "ARINC-429 metadata unavailable"
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			return diag, false, errors.New("a429 metadata missing")
		}
		if info.ParseError != "" {
			diag.Severity = ERROR
			diag.Message = fmt.Sprintf("cannot inspect ARINC-429 packet (%s)", info.ParseError)
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			return diag, false, nil
		}
		for w := 1; w < len(info.Words); w++ {
			if info.Words[w].GapTime0p1Us > gapLimit {
				splits[i] = append(splits[i], w)
				violations++
				if firstPktIdx < 0 {
					firstPktIdx = i
					firstWordIdx = w
					firstPacket = *pkt
				}
			}
		}
	}

	if len(splits) == 0 {
		diag.Message = "ARINC-429 gaps verified"
		return diag, false, nil
	}

	outPath, err := ch10.RewriteA429WithSplits(ctx.InputFile, ctx.Profile, ctx.Index, splits)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to rewrite ARINC-429 packets"
		return diag, false, err
	}

	diag.PacketIndex = firstPktIdx
	diag.ChannelId = int(firstPacket.ChannelID)
	diag.Offset = fmt.Sprintf("0x%X", firstPacket.Offset)
	if firstPacket.TimeStampUs >= 0 {
		offsetUs := computeA429WordOffset(firstPacket.A429, firstWordIdx)
		diag.TimestampUs = int64Ptr(firstPacket.TimeStampUs + offsetUs)
		src := string(firstPacket.Source)
		diag.TimestampSource = stringPtr(src)
	}
	if firstWordIdx >= 0 && firstPacket.A429 != nil && firstWordIdx < len(firstPacket.A429.Words) {
		gapMs := float64(firstPacket.A429.Words[firstWordIdx].GapTime0p1Us) / 10000.0
		diag.Message = fmt.Sprintf("fixed %d ARINC-429 gap violation(s), worst gap %.3f ms, wrote %s", violations, gapMs, filepath.Base(outPath))
	} else {
		diag.Message = fmt.Sprintf("fixed %d ARINC-429 gap violation(s), wrote %s", violations, filepath.Base(outPath))
	}
	diag.FixSuggested = true
	diag.FixApplied = true
	diag.FixPatchId = filepath.Base(outPath)
	if tmatsPath, err := annotateTMATSModified(ctx, rule, "ARINC-429 gap repair"); err != nil {
		diag.Severity = WARN
		diag.Message += fmt.Sprintf(" (TMATS update failed: %v)", err)
	} else if tmatsPath != "" {
		diag.Message += fmt.Sprintf(", updated TMATS %s", filepath.Base(tmatsPath))
	}
	return diag, true, nil
}

func WarnA429Parity(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "ARINC-429 parity verified", Refs: rule.Refs}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if pkt.DataType != 0x38 {
			continue
		}
		info := pkt.A429
		if info == nil {
			continue
		}
		if info.ParseError != "" {
			diag.Severity = WARN
			diag.Message = fmt.Sprintf("ARINC-429 parity not inspected (%s)", info.ParseError)
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			return diag, false, nil
		}
		for w, word := range info.Words {
			parityMismatch := !word.ComputedParity
			if !word.ParityErrorFlag && !parityMismatch {
				continue
			}
			diag.Severity = WARN
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			if pkt.TimeStampUs >= 0 {
				offsetUs := computeA429WordOffset(info, w)
				diag.TimestampUs = int64Ptr(pkt.TimeStampUs + offsetUs)
				src := string(pkt.Source)
				diag.TimestampSource = stringPtr(src)
			}
			reason := "parity flag"
			if parityMismatch && word.ParityErrorFlag {
				reason = "parity flag + recompute"
			} else if parityMismatch {
				reason = "parity recompute"
			}
			diag.Message = fmt.Sprintf("%s (label 0x%02X SDI=%d word=%d %s)", rule.Message, word.Label, word.SDI, w+1, reason)
			return diag, false, nil
		}
	}

	return diag, false, nil
}

func ValidateAgainstDictionaries(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "Dictionary compliance verified", Refs: rule.Refs}
	if ctx == nil {
		diag.Severity = ERROR
		diag.Message = "no context provided"
		return diag, false, errors.New("nil context")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}
	if ctx.Dictionaries == nil || ctx.Dictionaries.IsEmpty() {
		diag.Message = "no dictionaries provided"
		return diag, false, nil
	}
	if ctx.DictionaryReport == nil {
		ctx.DictionaryReport = &DictionaryComplianceReport{}
	}
	report := ctx.DictionaryReport
	report.MIL1553 = nil
	report.A429 = nil

	type milFindingKey struct {
		channel  uint16
		rt       uint8
		sa       uint8
		kind     byte
		observed int
		expected int
		issue    string
	}
	type a429FindingKey struct {
		channel uint16
		label   uint8
		sdi     uint8
		issue   string
	}
	type diagCandidate struct {
		severity    Severity
		packetIndex int
		channelID   uint16
		offset      string
		detail      string
	}

	severityRank := func(s Severity) int {
		switch s {
		case ERROR:
			return 3
		case WARN:
			return 2
		case INFO:
			return 1
		default:
			return 0
		}
	}

	var candidate *diagCandidate
	updateCandidate := func(pkt *ch10.PacketIndex, idx int, severity Severity, detail string) {
		r := severityRank(severity)
		if candidate == nil || r > severityRank(candidate.severity) || (r == severityRank(candidate.severity) && idx < candidate.packetIndex) {
			entry := diagCandidate{severity: severity, packetIndex: idx, detail: detail}
			if pkt != nil {
				entry.channelID = pkt.ChannelID
				entry.offset = fmt.Sprintf("0x%X", pkt.Offset)
			}
			candidate = &entry
		}
	}

	milMap := make(map[milFindingKey]*Dictionary1553Finding)
	a429Map := make(map[a429FindingKey]*DictionaryA429Finding)
	hasError := false
	hasWarn := false

	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if pkt.MIL1553 != nil {
			info := pkt.MIL1553
			if info.ParseError == "" {
				for _, msg := range info.Messages {
					if !msg.HasCommandWord {
						continue
					}
					cmd := msg.CommandWord
					rt := uint8((cmd >> 11) & 0x1F)
					sa := uint8((cmd >> 5) & 0x1F)
					raw := int(cmd & 0x1F)
					isMode := sa == 0 || sa == 0x1F
					observed := 0
					if isMode {
						observed = raw
					} else {
						if raw == 0 {
							observed = 32
						} else {
							observed = raw
						}
					}
					entry, ok := ctx.Dictionaries.LookupMIL1553(rt, sa)
					if !ok {
						hasWarn = true
						issue := "No dictionary entry"
						if isMode {
							issue = fmt.Sprintf("No dictionary entry for mode %d", observed)
						} else if observed > 0 {
							issue = fmt.Sprintf("No dictionary entry (WC=%d)", observed)
						}
						key := milFindingKey{channel: pkt.ChannelID, rt: rt, sa: sa, kind: 2, observed: observed, expected: -1, issue: issue}
						finding := milMap[key]
						if finding == nil {
							finding = &Dictionary1553Finding{
								ChannelID:   pkt.ChannelID,
								RT:          rt,
								SA:          sa,
								Occurrences: 1,
								Severity:    WARN,
								Issue:       issue,
							}
							if !isMode && observed > 0 {
								finding.WordCount = intPtr(observed)
							}
							if isMode {
								finding.ModeCode = intPtr(observed)
							}
							milMap[key] = finding
						} else {
							finding.Occurrences++
						}
						updateCandidate(pkt, i, WARN, fmt.Sprintf("RT %02d SA %02d: %s", rt, sa, issue))
						continue
					}
					name := strings.TrimSpace(entry.Name)
					if isMode {
						if expected, ok := entry.ModeCodeValue(); ok {
							if expected != raw {
								hasError = true
								issue := fmt.Sprintf("Mode code mismatch (observed %d expected %d)", raw, expected)
								key := milFindingKey{channel: pkt.ChannelID, rt: rt, sa: sa, kind: 1, observed: raw, expected: expected, issue: issue}
								finding := milMap[key]
								if finding == nil {
									finding = &Dictionary1553Finding{
										ChannelID:        pkt.ChannelID,
										RT:               rt,
										SA:               sa,
										Name:             name,
										Occurrences:      1,
										Severity:         ERROR,
										Issue:            issue,
										ModeCode:         intPtr(raw),
										ExpectedModeCode: intPtr(expected),
									}
									milMap[key] = finding
								} else {
									finding.Occurrences++
								}
								updateCandidate(pkt, i, ERROR, fmt.Sprintf("RT %02d SA %02d: %s", rt, sa, issue))
							}
						}
						continue
					}
					if expected, ok := entry.WordCountValue(); ok {
						if expected == 0 {
							expected = 32
						}
						if expected != observed {
							hasError = true
							issue := fmt.Sprintf("Word count mismatch (observed %d expected %d)", observed, expected)
							key := milFindingKey{channel: pkt.ChannelID, rt: rt, sa: sa, kind: 0, observed: observed, expected: expected, issue: issue}
							finding := milMap[key]
							if finding == nil {
								finding = &Dictionary1553Finding{
									ChannelID:         pkt.ChannelID,
									RT:                rt,
									SA:                sa,
									Name:              name,
									Occurrences:       1,
									Severity:          ERROR,
									Issue:             issue,
									WordCount:         intPtr(observed),
									ExpectedWordCount: intPtr(expected),
								}
								milMap[key] = finding
							} else {
								finding.Occurrences++
							}
							updateCandidate(pkt, i, ERROR, fmt.Sprintf("RT %02d SA %02d: %s", rt, sa, issue))
						}
					}
				}
			}
		}
		if pkt.A429 != nil {
			info := pkt.A429
			if info.ParseError == "" {
				for _, word := range info.Words {
					if _, ok := ctx.Dictionaries.LookupA429(word.Label, word.SDI); ok {
						continue
					}
					hasWarn = true
					issue := "No dictionary entry"
					key := a429FindingKey{channel: pkt.ChannelID, label: word.Label, sdi: word.SDI, issue: issue}
					finding := a429Map[key]
					if finding == nil {
						finding = &DictionaryA429Finding{
							ChannelID:   pkt.ChannelID,
							Label:       word.Label,
							SDI:         word.SDI,
							Occurrences: 1,
							Severity:    WARN,
							Issue:       issue,
						}
						a429Map[key] = finding
					} else {
						finding.Occurrences++
					}
					updateCandidate(pkt, i, WARN, fmt.Sprintf("Label 0x%02X SDI %d: %s", word.Label, word.SDI, issue))
				}
			}
		}
	}

	if len(milMap) > 0 {
		report.MIL1553 = make([]Dictionary1553Finding, 0, len(milMap))
		for _, f := range milMap {
			report.MIL1553 = append(report.MIL1553, *f)
		}
		sort.Slice(report.MIL1553, func(i, j int) bool {
			li := report.MIL1553[i]
			lj := report.MIL1553[j]
			ri := severityRank(li.Severity)
			rj := severityRank(lj.Severity)
			if ri != rj {
				return ri > rj
			}
			if li.ChannelID != lj.ChannelID {
				return li.ChannelID < lj.ChannelID
			}
			if li.RT != lj.RT {
				return li.RT < lj.RT
			}
			if li.SA != lj.SA {
				return li.SA < lj.SA
			}
			return li.Issue < lj.Issue
		})
	}
	if len(a429Map) > 0 {
		report.A429 = make([]DictionaryA429Finding, 0, len(a429Map))
		for _, f := range a429Map {
			report.A429 = append(report.A429, *f)
		}
		sort.Slice(report.A429, func(i, j int) bool {
			li := report.A429[i]
			lj := report.A429[j]
			ri := severityRank(li.Severity)
			rj := severityRank(lj.Severity)
			if ri != rj {
				return ri > rj
			}
			if li.ChannelID != lj.ChannelID {
				return li.ChannelID < lj.ChannelID
			}
			if li.Label != lj.Label {
				return li.Label < lj.Label
			}
			if li.SDI != lj.SDI {
				return li.SDI < lj.SDI
			}
			return li.Issue < lj.Issue
		})
	}

	totalMIL := len(report.MIL1553)
	totalA429 := len(report.A429)
	if totalMIL == 0 && totalA429 == 0 {
		diag.Message = "Dictionary compliance verified"
		return diag, false, nil
	}

	var parts []string
	if totalMIL > 0 {
		parts = append(parts, fmt.Sprintf("MIL-STD-1553=%d", totalMIL))
	}
	if totalA429 > 0 {
		parts = append(parts, fmt.Sprintf("ARINC-429=%d", totalA429))
	}
	diag.Message = fmt.Sprintf("Dictionary mismatches detected (%s)", strings.Join(parts, ", "))
	if candidate != nil && strings.TrimSpace(candidate.detail) != "" {
		diag.Message += "; first issue: " + candidate.detail
		diag.Severity = candidate.severity
		diag.PacketIndex = candidate.packetIndex
		diag.ChannelId = int(candidate.channelID)
		diag.Offset = candidate.offset
	}
	if hasError {
		diag.Severity = ERROR
	} else if hasWarn {
		diag.Severity = WARN
	}
	return diag, false, nil
}

func computeA429WordOffset(info *ch10.A429Info, idx int) int64 {
	if info == nil || idx <= 0 || idx >= len(info.Words) {
		return 0
	}
	var total uint64
	for i := 1; i <= idx && i < len(info.Words); i++ {
		total += uint64(info.Words[i].GapTime0p1Us)
	}
	return int64(total / 10)
}

func AddEthIPH(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "Ethernet IPH inspection", Refs: rule.Refs}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if ctx.Profile == "" {
		diag.Severity = ERROR
		diag.Message = "profile required"
		return diag, false, errors.New("profile required")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	f, err := os.Open(ctx.InputFile)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot open input file"
		return diag, false, err
	}
	defer f.Close()

	const (
		dataTypeEthernetFmt0 = 0x50
		frameIDDataMask      = 0x3FFF
	)

	var (
		inserts       []ch10.InsertEdit
		framesFixed   int
		firstPktIdx   = -1
		firstFrameIdx int
		firstPacket   ch10.PacketIndex
	)

	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if pkt.DataType != dataTypeEthernetFmt0 {
			continue
		}
		dataLen := int(pkt.DataLength)
		payloadOffset := pkt.Offset + int64(ch10PrimaryHeaderSize)
		if pkt.HasSecHdr {
			if dataLen < ch10SecondaryHeaderSize {
				continue
			}
			payloadOffset += ch10SecondaryHeaderSize
			dataLen -= ch10SecondaryHeaderSize
		}
		if dataLen <= 4 {
			continue
		}
		body := make([]byte, dataLen)
		if _, err := f.ReadAt(body, payloadOffset); err != nil {
			diag.Severity = ERROR
			diag.Message = fmt.Sprintf("read packet %d failed", i)
			return diag, false, err
		}
		csdw := binary.BigEndian.Uint32(body[0:4])
		if (csdw>>28)&0xF != 0 {
			// Not format 0.
			continue
		}
		frames, err := ch10.ParseEthFmt0PacketBody(body, csdw)
		if err != nil {
			diag.Severity = WARN
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			diag.Message = fmt.Sprintf("cannot parse Ethernet payload: %v", err)
			return diag, false, nil
		}
		for frameIdx, frame := range frames {
			if frame.HasIPH {
				continue
			}
			if frame.FrameLength <= 0 || frame.FrameLength > frameIDDataMask {
				continue
			}
			ts := uint64(0)
			if pkt.TimeStampUs >= 0 {
				ts = uint64(pkt.TimeStampUs)
			}
			iph := make([]byte, 12)
			binary.BigEndian.PutUint32(iph[0:4], uint32(ts&0xFFFFFFFF))
			binary.BigEndian.PutUint32(iph[4:8], uint32((ts>>32)&0xFFFFFFFF))
			frameID := uint32(frame.FrameLength & frameIDDataMask)
			binary.BigEndian.PutUint32(iph[8:12], frameID)
			inserts = append(inserts, ch10.InsertEdit{
				PacketOffset: pkt.Offset,
				InsertAt:     frame.FrameOffset,
				Bytes:        iph,
				Note:         fmt.Sprintf("pkt=%d frame=%d", i, frameIdx),
			})
			framesFixed++
			if firstPktIdx < 0 {
				firstPktIdx = i
				firstFrameIdx = frameIdx
				firstPacket = *pkt
			}
		}
	}

	if framesFixed == 0 {
		diag.Message = "Ethernet IPH already present"
		return diag, false, nil
	}

	outPath := ctx.InputFile + ".fixed.ch10"
	if err := ch10.RewriteWithInsertions(ctx.InputFile, outPath, ctx.Profile, inserts); err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to insert Ethernet IPH"
		return diag, false, err
	}

	diag.Message = fmt.Sprintf("inserted %d Ethernet IPH header(s), wrote %s", framesFixed, filepath.Base(outPath))
	diag.FixSuggested = true
	diag.FixApplied = true
	diag.FixPatchId = filepath.Base(outPath)
	diag.File = ctx.InputFile
	if firstPktIdx >= 0 {
		diag.PacketIndex = firstPktIdx
		diag.ChannelId = int(firstPacket.ChannelID)
		diag.Offset = fmt.Sprintf("0x%X", firstPacket.Offset)
		diag.Message += fmt.Sprintf(" (first fix packet %d frame %d)", firstPktIdx, firstFrameIdx)
		if firstPacket.TimeStampUs >= 0 {
			diag.TimestampUs = int64Ptr(firstPacket.TimeStampUs)
			src := string(firstPacket.Source)
			diag.TimestampSource = stringPtr(src)
		}
	}
	if tmatsPath, err := annotateTMATSModified(ctx, rule, "Ethernet IPH insertion"); err != nil {
		diag.Severity = WARN
		diag.Message += fmt.Sprintf(" (TMATS update failed: %v)", err)
	} else if tmatsPath != "" {
		diag.Message += fmt.Sprintf(", updated TMATS %s", filepath.Base(tmatsPath))
	}
	return diag, true, nil
}

func FixA664Lens(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "A664 length inspection", Refs: rule.Refs}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	f, err := os.Open(ctx.InputFile)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot open input file"
		return diag, false, err
	}
	defer f.Close()

	const dataTypeEthernetFmt1 = 0x51

	var (
		edits       []ch10.PatchEdit
		messagesFix int
		firstPktIdx = -1
		firstMsgIdx int
		firstPacket ch10.PacketIndex
	)

	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if pkt.DataType != dataTypeEthernetFmt1 {
			continue
		}
		dataLen := int(pkt.DataLength)
		payloadOffset := pkt.Offset + int64(ch10PrimaryHeaderSize)
		if pkt.HasSecHdr {
			if dataLen < ch10SecondaryHeaderSize {
				continue
			}
			payloadOffset += ch10SecondaryHeaderSize
			dataLen -= ch10SecondaryHeaderSize
		}
		if dataLen <= 4 {
			continue
		}
		body := make([]byte, dataLen)
		if _, err := f.ReadAt(body, payloadOffset); err != nil {
			diag.Severity = ERROR
			diag.Message = fmt.Sprintf("read packet %d failed", i)
			return diag, false, err
		}
		csdw := binary.BigEndian.Uint32(body[0:4])
		msgs, err := ch10.ParseEthFmt1PacketBody(body, csdw)
		if err != nil {
			diag.Severity = WARN
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			diag.Message = fmt.Sprintf("cannot parse A664 payload: %v", err)
			return diag, false, nil
		}
		for msgIdx, msg := range msgs {
			if msg.PayloadLength <= 0 || msg.PayloadLength > 0xFFFF-8 {
				continue
			}
			if msg.IPv4HeaderLength <= 0 || msg.UDPOffset < msg.IPv4Offset {
				continue
			}
			udpSegmentLen := msg.PayloadLength + 8
			if msg.UDPOffset+udpSegmentLen > len(body) {
				continue
			}
			if msg.IPv4Offset+msg.IPv4HeaderLength > len(body) {
				continue
			}

			desiredUDPLen := uint16(msg.PayloadLength + 8)
			desiredIPv4Len := uint16(msg.IPv4HeaderLength + int(desiredUDPLen))

			ipv4Header := make([]byte, msg.IPv4HeaderLength)
			copy(ipv4Header, body[msg.IPv4Offset:msg.IPv4Offset+msg.IPv4HeaderLength])
			udpSegment := make([]byte, udpSegmentLen)
			copy(udpSegment, body[msg.UDPOffset:msg.UDPOffset+udpSegmentLen])

			oldIPv4Len := uint16(msg.IPv4TotalLength)
			oldIPv4Checksum := binary.BigEndian.Uint16(ipv4Header[10:12])
			oldUDPLen := msg.UDPLength
			oldUDPChecksum := msg.UDPChecksum

			binary.BigEndian.PutUint16(ipv4Header[2:4], desiredIPv4Len)
			ipv4Header[10] = 0
			ipv4Header[11] = 0
			binary.BigEndian.PutUint16(udpSegment[4:6], desiredUDPLen)
			if oldUDPChecksum != 0 {
				udpSegment[6] = 0
				udpSegment[7] = 0
			}

			newIPv4Checksum := eth.IPv4HeaderChecksum(ipv4Header)
			newUDPChecksum := uint16(0)
			if oldUDPChecksum != 0 {
				newUDPChecksum = eth.UDPChecksum(ipv4Header, udpSegment)
				if newUDPChecksum == 0 {
					newUDPChecksum = 0xFFFF
				}
			}

			bodyBase := payloadOffset
			msgPatched := false

			if oldUDPLen != desiredUDPLen {
				edits = append(edits, ch10.PatchEdit{
					Offset: bodyBase + int64(msg.UDPOffset+4),
					Data:   []byte{byte(desiredUDPLen >> 8), byte(desiredUDPLen)},
				})
				msgPatched = true
			}
			if oldIPv4Len != desiredIPv4Len {
				edits = append(edits, ch10.PatchEdit{
					Offset: bodyBase + int64(msg.IPv4Offset+2),
					Data:   []byte{byte(desiredIPv4Len >> 8), byte(desiredIPv4Len)},
				})
				msgPatched = true
			}
			if oldIPv4Checksum != newIPv4Checksum {
				edits = append(edits, ch10.PatchEdit{
					Offset: bodyBase + int64(msg.IPv4Offset+10),
					Data:   []byte{byte(newIPv4Checksum >> 8), byte(newIPv4Checksum)},
				})
				msgPatched = true
			}
			if oldUDPChecksum != 0 && oldUDPChecksum != newUDPChecksum {
				edits = append(edits, ch10.PatchEdit{
					Offset: bodyBase + int64(msg.UDPOffset+6),
					Data:   []byte{byte(newUDPChecksum >> 8), byte(newUDPChecksum)},
				})
				msgPatched = true
			}

			if msgPatched {
				messagesFix++
				if firstPktIdx < 0 {
					firstPktIdx = i
					firstMsgIdx = msgIdx
					firstPacket = *pkt
				}
			}
		}
	}

	if messagesFix == 0 {
		diag.Message = "A664 lengths already consistent"
		return diag, false, nil
	}

	if err := appendAuditEntries(ctx, rule, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = fmt.Sprintf("failed to record audit trail: %v", err)
		return diag, false, err
	}

	if err := ch10.ApplyPatch(ctx.InputFile, edits); err != nil {
		diag.Severity = ERROR
		diag.Message = "failed to update A664 headers"
		return diag, false, err
	}

	diag.Message = fmt.Sprintf("fixed %d A664 message(s)", messagesFix)
	diag.FixSuggested = true
	diag.FixApplied = true
	if firstPktIdx >= 0 {
		diag.PacketIndex = firstPktIdx
		diag.ChannelId = int(firstPacket.ChannelID)
		diag.Offset = fmt.Sprintf("0x%X", firstPacket.Offset)
		diag.Message += fmt.Sprintf(" (first fix packet %d message %d)", firstPktIdx, firstMsgIdx)
		if firstPacket.TimeStampUs >= 0 {
			diag.TimestampUs = int64Ptr(firstPacket.TimeStampUs)
			src := string(firstPacket.Source)
			diag.TimestampSource = stringPtr(src)
		}
	}
	return diag, true, nil
}

func UpdateTMATSDigest(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	if ctx.TMATSFile == "" {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "no TMATS provided", Refs: rule.Refs}, false, nil
	}
	doc, err := tmats.Parse(ctx.TMATSFile)
	if err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: ERROR, Message: "TMATS parse failed", Refs: rule.Refs}, false, err
	}
	digest, err := doc.ComputeDigest()
	if err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: ERROR, Message: "digest compute failed", Refs: rule.Refs}, false, err
	}
	doc.Set("G\\SHA", digest)
	outPath := ctx.TMATSFile + ".fixed"
	if err := os.WriteFile(outPath, []byte(doc.String()), 0644); err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: ERROR, Message: "cannot write fixed TMATS", Refs: rule.Refs}, false, err
	}
	return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: INFO, Message: "TMATS digest updated, wrote " + filepath.Base(outPath), Refs: rule.Refs, FixSuggested: true}, true, nil
}

func NormalizeTMATSChannelMap(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: INFO, Message: "TMATS channel map normalization", Refs: rule.Refs}

	if ctx == nil {
		diag.Severity = ERROR
		diag.Message = "no context provided"
		return diag, false, errors.New("nil context")
	}
	if ctx.TMATSFile == "" {
		diag.Severity = WARN
		diag.Message = "no TMATS provided"
		return diag, false, nil
	}
	doc, err := tmats.Parse(ctx.TMATSFile)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "TMATS parse failed"
		return diag, false, err
	}
	if ctx.Index == nil {
		if err := ctx.EnsureFileIndex(); err != nil {
			diag.Severity = ERROR
			diag.Message = "cannot index Chapter 10 file"
			return diag, false, err
		}
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no Chapter 10 packets indexed"
		return diag, false, nil
	}

	summaries := make(map[uint16]*tmatsChannelSummary)
	for i := range ctx.Index.Packets {
		pkt := ctx.Index.Packets[i]
		summary, ok := summaries[pkt.ChannelID]
		if !ok {
			summary = newTMATSChannelSummary(pkt.ChannelID)
			summaries[pkt.ChannelID] = summary
		}
		summary.addPacket(pkt)
	}
	if len(summaries) == 0 {
		diag.Message = "no channels detected in Chapter 10"
		return diag, false, nil
	}

	ids := make([]int, 0, len(summaries))
	for id := range summaries {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)

	recordGroup := inferTMATSRecordGroup(doc)
	mapChanged := false

	for i, id := range ids {
		idx := i + 1
		summary := summaries[uint16(id)]
		keyCHE := fmt.Sprintf("%s\\CHE-%d", recordGroup, idx)
		if doc.Set(keyCHE, strconv.Itoa(int(summary.channelID))) {
			mapChanged = true
		}

		dtKey := fmt.Sprintf("%s\\CDT-%d", recordGroup, idx)
		dtName := tmats.DataTypeName(summary.dataType())
		if doc.Set(dtKey, dtName) {
			mapChanged = true
		}

		shtfKey := fmt.Sprintf("%s\\SHTF-%d", recordGroup, idx)
		if tf, ok := summary.timeFormat(); ok {
			tfName := tmats.TimeFormatName(tf)
			if doc.Set(shtfKey, tfName) {
				mapChanged = true
			}
		} else {
			if doc.Delete(shtfKey) {
				mapChanged = true
			}
		}
	}

	if removeExtraIndexedKeys(doc, recordGroup, "CHE", len(ids)) {
		mapChanged = true
	}
	if removeExtraIndexedKeys(doc, recordGroup, "CDT", len(ids)) {
		mapChanged = true
	}
	if removeExtraIndexedKeys(doc, recordGroup, "SHTF", len(ids)) {
		mapChanged = true
	}

	nsbKey := fmt.Sprintf("%s\\NSB", recordGroup)
	if doc.Set(nsbKey, strconv.Itoa(len(ids))) {
		mapChanged = true
	}

	digest, err := doc.ComputeDigest()
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "digest compute failed"
		return diag, false, err
	}

	changed := mapChanged
	if doc.Set("G\\SHA", digest) {
		changed = true
	}

	if !changed {
		diag.Message = "TMATS channel map already consistent with Chapter 10"
		return diag, false, nil
	}

	outPath := ctx.TMATSFile + ".fixed"
	if err := os.WriteFile(outPath, []byte(doc.String()), 0644); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot write fixed TMATS"
		return diag, false, err
	}

	diag.Message = fmt.Sprintf("TMATS channel map normalized for %d channels, wrote %s", len(ids), filepath.Base(outPath))
	diag.FixSuggested = true
	return diag, true, nil
}

type tmatsChannelSummary struct {
	channelID  uint16
	dataCounts map[uint16]int
	timeCounts map[uint8]int
}

func newTMATSChannelSummary(id uint16) *tmatsChannelSummary {
	return &tmatsChannelSummary{
		channelID:  id,
		dataCounts: make(map[uint16]int),
		timeCounts: make(map[uint8]int),
	}
}

func (s *tmatsChannelSummary) addPacket(pkt ch10.PacketIndex) {
	s.dataCounts[pkt.DataType]++
	if pkt.HasSecHdr {
		s.timeCounts[pkt.TimeFormat]++
	}
}

func (s *tmatsChannelSummary) dataType() uint16 {
	var best uint16
	var bestCount int
	for dt, count := range s.dataCounts {
		if count > bestCount || (count == bestCount && dt < best) {
			best = dt
			bestCount = count
		}
	}
	return best
}

func (s *tmatsChannelSummary) timeFormat() (uint8, bool) {
	var best uint8
	var bestCount int
	for tf, count := range s.timeCounts {
		if count > bestCount || (count == bestCount && tf < best) {
			best = tf
			bestCount = count
		}
	}
	if bestCount == 0 {
		return 0, false
	}
	return best, true
}

func inferTMATSRecordGroup(doc *tmats.Document) string {
	if doc == nil {
		return "R-1"
	}
	for _, key := range doc.Keys() {
		if strings.HasPrefix(key, "R-") {
			if idx := strings.Index(key, "\\"); idx > 0 {
				return key[:idx]
			}
		}
	}
	return "R-1"
}

func removeExtraIndexedKeys(doc *tmats.Document, recordGroup, field string, keep int) bool {
	if doc == nil {
		return false
	}
	prefix := fmt.Sprintf("%s\\%s-", recordGroup, field)
	changed := false
	for _, key := range doc.KeysWithPrefix(prefix) {
		idxStr := strings.TrimPrefix(key, prefix)
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			continue
		}
		if idx > keep {
			if doc.Delete(key) {
				changed = true
			}
		}
	}
	return changed
}

func SyncSecondaryTimeFmt(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "secondary time format inspection", Refs: rule.Refs}
	if ctx == nil {
		diag.Severity = ERROR
		diag.Message = "no context provided"
		return diag, false, errors.New("nil context")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot index file"
		return diag, false, err
	}
	if ctx.Index == nil || len(ctx.Index.Packets) == 0 {
		diag.Message = "no packets to inspect"
		return diag, false, nil
	}

	var (
		expected uint8
		have     bool
		mismatch = -1
	)

	for i := range ctx.Index.Packets {
		pkt := &ctx.Index.Packets[i]
		if !pkt.HasSecHdr || !pkt.SecHdrBytes || !pkt.SecHdrValid {
			continue
		}
		if !have {
			expected = pkt.TimeFormat
			have = true
			diag.PacketIndex = i
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			if pkt.TimeStampUs >= 0 {
				diag.TimestampUs = int64Ptr(pkt.TimeStampUs)
				src := string(pkt.Source)
				diag.TimestampSource = stringPtr(src)
			}
			continue
		}
		if pkt.TimeFormat != expected {
			mismatch = i
			break
		}
	}

	if !have {
		diag.Message = "no packets with secondary header timestamps"
		return diag, false, nil
	}

	if mismatch >= 0 {
		pkt := ctx.Index.Packets[mismatch]
		diag.Severity = WARN
		diag.PacketIndex = mismatch
		diag.ChannelId = int(pkt.ChannelID)
		diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
		diag.Message = fmt.Sprintf("secondary header time formats inconsistent: 0x%X vs 0x%X", pkt.TimeFormat, expected)
		if pkt.TimeStampUs >= 0 {
			diag.TimestampUs = int64Ptr(pkt.TimeStampUs)
			src := string(pkt.Source)
			diag.TimestampSource = stringPtr(src)
		}
		return diag, false, nil
	}

	diag.Message = fmt.Sprintf("secondary header time format consistent (0x%X)", expected)
	return diag, false, nil
}

func FixFileExtension(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	ext := filepath.Ext(ctx.InputFile)
	if ext == ".ch10" || ext == ".tf10" || ext == ".df10" {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "extension ok", Refs: rule.Refs}, false, nil
	}
	newPath := ctx.InputFile + ".ch10"
	if err := copyFile(ctx.InputFile, newPath); err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR, Message: "cannot copy with .ch10", Refs: rule.Refs}, false, err
	}
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "copied to " + filepath.Base(newPath), Refs: rule.Refs, FixSuggested: true}, true, nil
}

func ValidateOrRebuildDirectory(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "directory inspection", Refs: rule.Refs}
	if ctx == nil || ctx.InputFile == "" {
		diag.Severity = ERROR
		diag.Message = "no input file provided"
		return diag, false, errors.New("no input file")
	}
	ext := strings.ToLower(filepath.Ext(ctx.InputFile))
	if ext != ".tf10" && ext != ".df10" {
		diag.Message = "not a transfer/directory file"
		return diag, false, nil
	}
	info, err := os.Stat(ctx.InputFile)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = "cannot stat input file"
		return diag, false, err
	}
	img, err := ch10.ReadDirectoryImage(ctx.InputFile)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = fmt.Sprintf("cannot parse directory: %v", err)
		return diag, false, err
	}
	if err := ch10.ValidateDirectory(img, info.Size()); err == nil {
		diag.Message = "directory chain valid"
		return diag, false, nil
	}

	dataOffset := ch10.DeriveDataOffset(img)
	if dataOffset <= 0 || dataOffset > info.Size() {
		if candidate, ferr := ch10.FindFirstPacketOffset(ctx.InputFile); ferr == nil {
			dataOffset = candidate
		} else {
			dataOffset = img.TotalBytes()
		}
	}
	if dataOffset < img.TotalBytes() {
		dataOffset = img.TotalBytes()
	}
	blockSize := img.BlockSize
	if blockSize == 0 || dataOffset%int64(blockSize) != 0 {
		blockSize = ch10.SelectBlockSize(dataOffset)
	}

	plan := ch10.BuildDirectoryPlanFromImage(img, info.Size())
	plan.BlockSize = blockSize
	plan.Shutdown = 0xFF
	if len(plan.VolumeName) == 0 {
		plan.VolumeName = ch10.BaseNameFromPath(ctx.InputFile)
	}
	if len(plan.Entries) == 0 {
		size := info.Size() - dataOffset
		if size < 0 {
			size = 0
		}
		name := ch10.BaseNameFromPath(ctx.InputFile) + ".ch10"
		plan.Entries = []ch10.DirectoryBuildEntry{{
			Name:        name,
			StartOffset: dataOffset,
			Size:        size,
		}}
	} else {
		for i := range plan.Entries {
			if plan.Entries[i].Size < 0 {
				plan.Entries[i].Size = 0
			}
			if plan.Entries[i].StartOffset < dataOffset {
				dataOffset = plan.Entries[i].StartOffset
			}
		}
		if dataOffset < img.TotalBytes() {
			dataOffset = img.TotalBytes()
		}
	}

	newDir, err := ch10.BuildDirectory(plan, dataOffset)
	if err != nil {
		diag.Severity = ERROR
		diag.Message = fmt.Sprintf("cannot build directory: %v", err)
		return diag, false, err
	}

	base := strings.TrimSuffix(ctx.InputFile, ext)
	outPath := base + ".fixed" + ext
	if err := ch10.RewriteTransferFileWithDirectory(ctx.InputFile, outPath, newDir, dataOffset); err != nil {
		diag.Severity = ERROR
		diag.Message = fmt.Sprintf("failed to rewrite %s", filepath.Base(outPath))
		return diag, false, err
	}

	var additional []string
	if dataOffset < info.Size() {
		ch10Out := base + ".fixed.ch10"
		if err := ch10.CopyChapter10Data(ctx.InputFile, ch10Out, dataOffset); err == nil {
			additional = append(additional, filepath.Base(ch10Out))
		}
	}

	diag.FixSuggested = true
	diag.FixApplied = true
	diag.FixPatchId = filepath.Base(outPath)
	message := fmt.Sprintf("rebuilt directory (blockSize=%d, entries=%d) -> %s", plan.BlockSize, len(plan.Entries), filepath.Base(outPath))
	if len(additional) > 0 {
		message += fmt.Sprintf(", extracted %s", strings.Join(additional, ", "))
	}
	diag.Message = message

	if tmatsPath, err := annotateTMATSModified(ctx, rule, "Directory rebuilt"); err != nil {
		diag.Severity = WARN
		diag.Message += fmt.Sprintf(" (TMATS update failed: %v)", err)
	} else if tmatsPath != "" {
		diag.Message += fmt.Sprintf(", updated TMATS %s", filepath.Base(tmatsPath))
	}

	return diag, true, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 1024*1024)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return nil
}
