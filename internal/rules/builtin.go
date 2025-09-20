package rules

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"example.com/ch10gate/internal/ch10"
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

func stringPtr(s string) *string { return &s }

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
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN,
		Message: "channel id remap not implemented yet", Refs: rule.Refs,
	}, false, ErrNotImplemented
}

func RenumberSeq(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO,
		Message: "sequence renumber planned", Refs: rule.Refs,
	}, false, nil
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

func EnsureTimePacket(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	diag := Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "time packet inspection", Refs: rule.Refs}
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

	idx := ctx.Index
	if !idx.HasTimePacket {
		diag.Severity = ERROR
		diag.Message = "no time packets detected"
		return diag, false, nil
	}

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

	if !idx.TimeSeenBeforeDynamic {
		diag.Severity = WARN
		diag.Message = "first dynamic packet observed before time reference"
		if firstDynamicIdx >= 0 {
			pkt := idx.Packets[firstDynamicIdx]
			diag.PacketIndex = firstDynamicIdx
			diag.ChannelId = int(pkt.ChannelID)
			diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
			if diag.TimestampUs == nil && pkt.TimeStampUs >= 0 {
				diag.TimestampUs = int64Ptr(pkt.TimeStampUs)
				src := string(pkt.Source)
				diag.TimestampSource = stringPtr(src)
			}
		}
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

	diag.Message = "time packet present before first dynamic packet"
	if firstTimeIdx >= 0 {
		pkt := idx.Packets[firstTimeIdx]
		diag.PacketIndex = firstTimeIdx
		diag.ChannelId = int(pkt.ChannelID)
		diag.Offset = fmt.Sprintf("0x%X", pkt.Offset)
	}
	return diag, false, nil
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
	t, err := tmats.Parse(ctx.TMATSFile)
	if err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: ERROR, Message: "TMATS parse failed", Refs: rule.Refs}, false, err
	}
	d, err := tmats.ComputeDigest(t)
	if err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: ERROR, Message: "digest compute failed", Refs: rule.Refs}, false, err
	}
	out := tmats.WithDigest(t, d)
	outPath := ctx.TMATSFile + ".fixed"
	if err := os.WriteFile(outPath, []byte(out), 0644); err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: ERROR, Message: "cannot write fixed TMATS", Refs: rule.Refs}, false, err
	}
	return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: INFO, Message: "TMATS digest updated, wrote " + filepath.Base(outPath), Refs: rule.Refs, FixSuggested: true}, true, nil
}

func NormalizeTMATSChannelMap(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: INFO, Message: "TMATS channel map normalization deferred", Refs: rule.Refs}, false, nil
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
