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
	"example.com/ch10gate/internal/tmats"
)

const ch10PrimaryHeaderSize = 20

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
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "skipped (implemented in Part 2)", Refs: rule.Refs}, false, nil
}

func FixPCMAlign(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "PCM alignment fix not implemented", Refs: rule.Refs}, false, ErrNotImplemented
}

func Check1553IpdhLen(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "1553 IPDH len check deferred", Refs: rule.Refs}, false, nil
}

func Warn1553Ttb(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "TTB warning (placeholder)", Refs: rule.Refs}, false, nil
}

func FixA429Gap(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "ARINC-429 gap fix not implemented", Refs: rule.Refs}, false, ErrNotImplemented
}

func WarnA429Parity(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "ARINC-429 parity flagged (placeholder)", Refs: rule.Refs}, false, nil
}

func AddEthIPH(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "Ethernet IPH add not implemented", Refs: rule.Refs}, false, ErrNotImplemented
}

func FixA664Lens(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "A664 length fix not implemented", Refs: rule.Refs}, false, ErrNotImplemented
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
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "secondary time format sync deferred", Refs: rule.Refs}, false, nil
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
