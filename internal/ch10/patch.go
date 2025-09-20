package ch10

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

// PatchEdit represents an in-place modification to a Chapter 10 file.
type PatchEdit struct {
	Offset int64
	Data   []byte
}

// InsertEdit represents an insertion operation within a packet body.
type InsertEdit struct {
	PacketOffset int64
	InsertAt     int
	Bytes        []byte
	Note         string
}

// PacketInsert describes a full packet to insert before a packet index.
type PacketInsert struct {
	// BeforeIndex indicates the packet index in the existing file before
	// which the new packet should be written. Values less than zero insert
	// at the start of the file, while values greater than the number of
	// packets append to the end.
	BeforeIndex int
	Packet      []byte
}

// StructuralPlan captures high level structural mutations applied while
// rewriting a Chapter 10 recording.
type StructuralPlan struct {
	Inserts          []PacketInsert
	Deletes          map[int]struct{}
	ChannelRemap     map[uint16]uint16
	RenumberAll      bool
	RenumberChannels map[uint16]bool
}

// ApplyPatch applies the provided edits to path. Each edit must stay within the
// bounds of the file and does not change its length.
func ApplyPatch(path string, edits []PatchEdit) error {
	if len(edits) == 0 {
		return nil
	}
	// Make a defensive copy so callers can reuse the slice after return.
	ordered := make([]PatchEdit, 0, len(edits))
	for _, e := range edits {
		if len(e.Data) == 0 {
			continue
		}
		buf := make([]byte, len(e.Data))
		copy(buf, e.Data)
		ordered = append(ordered, PatchEdit{Offset: e.Offset, Data: buf})
	}
	if len(ordered) == 0 {
		return nil
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Offset < ordered[j].Offset
	})

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	for _, edit := range ordered {
		if edit.Offset < 0 {
			return fmt.Errorf("negative patch offset %d", edit.Offset)
		}
		end := edit.Offset + int64(len(edit.Data))
		if end > size {
			return fmt.Errorf("patch at %d with length %d exceeds file size %d", edit.Offset, len(edit.Data), size)
		}
		if _, err := f.Seek(edit.Offset, io.SeekStart); err != nil {
			return err
		}
		written := 0
		for written < len(edit.Data) {
			n, err := f.Write(edit.Data[written:])
			if err != nil {
				return err
			}
			written += n
		}
	}
	return f.Sync()
}

// RewriteWithInsertions rewrites packets in srcPath by inserting byte sequences
// at the specified body-relative offsets. The resulting file is written to
// dstPath. Header packet/data length fields and the header checksum are updated
// to account for the inserted bytes.
func RewriteWithInsertions(srcPath, dstPath, profile string, edits []InsertEdit) error {
	filtered := make([]InsertEdit, 0, len(edits))
	for _, e := range edits {
		if len(e.Bytes) == 0 {
			continue
		}
		filtered = append(filtered, e)
	}
	if len(filtered) == 0 {
		return errors.New("no insertions provided")
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].PacketOffset == filtered[j].PacketOffset {
			return filtered[i].InsertAt < filtered[j].InsertAt
		}
		return filtered[i].PacketOffset < filtered[j].PacketOffset
	})

	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() {
		out.Sync()
		out.Close()
	}()

	info, err := in.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	var (
		editIdx int
		offset  int64
	)
	header := make([]byte, primaryHeaderSize)
	for offset < size {
		if _, err := in.ReadAt(header, offset); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		packetLength := int64(binary.BigEndian.Uint32(header[4:8])) + 4
		if packetLength < primaryHeaderSize {
			return fmt.Errorf("packet at offset %d shorter than header", offset)
		}
		packet := make([]byte, packetLength)
		if _, err := in.ReadAt(packet, offset); err != nil {
			if !errors.Is(err, io.EOF) || int64(len(packet)) != packetLength {
				return err
			}
		}
		dataLength := int(binary.BigEndian.Uint32(packet[8:12]))
		hasSecHdr := packet[15]&packetFlagSecondaryHdr != 0
		secHdrLen := 0
		if hasSecHdr {
			secHdrLen = secondaryHeaderSize
		}
		dataStart := primaryHeaderSize + secHdrLen
		dataEnd := dataStart + dataLength
		if dataEnd > len(packet) {
			dataEnd = len(packet)
		}
		if dataStart > len(packet) {
			dataStart = len(packet)
		}
		body := packet[dataStart:dataEnd]

		var packetEdits []InsertEdit
		for editIdx < len(filtered) && filtered[editIdx].PacketOffset == offset {
			packetEdits = append(packetEdits, filtered[editIdx])
			editIdx++
		}
		if len(packetEdits) == 0 {
			if _, err := out.Write(packet); err != nil {
				return err
			}
			offset += packetLength
			continue
		}

		originalBodyLen := len(body)
		buf := bytes.NewBuffer(make([]byte, 0, originalBodyLen))
		cursor := 0
		for _, ins := range packetEdits {
			if ins.InsertAt < 0 || ins.InsertAt > originalBodyLen {
				return fmt.Errorf("insert position %d out of range for packet at %d", ins.InsertAt, offset)
			}
			if ins.InsertAt < cursor {
				return fmt.Errorf("insert positions must be non-decreasing for packet at %d", offset)
			}
			buf.Write(body[cursor:ins.InsertAt])
			buf.Write(ins.Bytes)
			cursor = ins.InsertAt
		}
		buf.Write(body[cursor:])
		newBody := buf.Bytes()

		newPacket := make([]byte, 0, len(packet)-len(body)+len(newBody))
		newPacket = append(newPacket, packet[:dataStart]...)
		newPacket = append(newPacket, newBody...)
		newPacket = append(newPacket, packet[dataEnd:]...)

		newDataLen := uint32(len(newBody) + secHdrLen)
		newPacketLen := uint32(len(newPacket) - 4)
		binary.BigEndian.PutUint32(newPacket[4:8], newPacketLen)
		binary.BigEndian.PutUint32(newPacket[8:12], newDataLen)
		newPacket[16] = 0
		newPacket[17] = 0
		checksum, err := ComputeHeaderChecksum(profile, newPacket[:primaryHeaderSize])
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(newPacket[16:18], checksum)

		if _, err := out.Write(newPacket); err != nil {
			return err
		}
		offset += packetLength
	}
	if editIdx != len(filtered) {
		return fmt.Errorf("not all insertions applied (%d of %d)", editIdx, len(filtered))
	}
	return nil
}

// RewriteA429WithSplits rewrites the Chapter 10 file at path by splitting the
// specified ARINC-429 packets at the provided word indices. The resulting file
// is written to "path.fixed.ch10". The splits map keys correspond to packet
// indices in idx.Packets and each value is a slice of word indices (0-based)
// that should begin a new packet.
func RewriteA429WithSplits(path, profile string, idx *FileIndex, splits map[int][]int) (string, error) {
	if len(splits) == 0 {
		return "", errors.New("no splits requested")
	}
	if idx == nil {
		return "", errors.New("no index available")
	}

	normalized := make(map[int][]int, len(splits))
	for pktIdx, positions := range splits {
		if pktIdx < 0 || pktIdx >= len(idx.Packets) {
			return "", fmt.Errorf("packet index %d out of range", pktIdx)
		}
		pkt := idx.Packets[pktIdx]
		if pkt.DataType != 0x38 {
			return "", fmt.Errorf("packet %d is not ARINC-429 format 0", pktIdx)
		}
		info := pkt.A429
		if info == nil {
			return "", fmt.Errorf("packet %d missing ARINC-429 metadata", pktIdx)
		}
		if info.ParseError != "" {
			return "", fmt.Errorf("packet %d cannot be rewritten (%s)", pktIdx, info.ParseError)
		}
		if len(info.Words) == 0 {
			return "", fmt.Errorf("packet %d has no ARINC-429 words", pktIdx)
		}
		if len(positions) == 0 {
			continue
		}
		sorted := append([]int(nil), positions...)
		sort.Ints(sorted)
		uniq := make([]int, 0, len(sorted))
		last := -1
		for _, pos := range sorted {
			if pos <= 0 || pos >= len(info.Words) {
				return "", fmt.Errorf("packet %d split index %d invalid", pktIdx, pos)
			}
			if pos != last {
				uniq = append(uniq, pos)
				last = pos
			}
		}
		if len(uniq) > 0 {
			normalized[pktIdx] = uniq
		}
	}
	if len(normalized) == 0 {
		return "", errors.New("no valid splits after normalization")
	}

	in, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer in.Close()

	outPath := path + ".fixed.ch10"
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	nextSeq := make(map[uint16]uint8)

	for pktIdx := range idx.Packets {
		pkt := idx.Packets[pktIdx]
		totalLen := int64(pkt.PacketLength) + 4
		section := io.NewSectionReader(in, pkt.Offset, totalLen)
		buf := make([]byte, totalLen)
		if _, err := io.ReadFull(section, buf); err != nil {
			return "", err
		}
		if len(buf) < primaryHeaderSize {
			return "", fmt.Errorf("packet %d shorter than primary header", pktIdx)
		}
		hdr := PacketHeader{
			Sync:         binary.BigEndian.Uint16(buf[0:2]),
			ChannelID:    binary.BigEndian.Uint16(buf[2:4]),
			PacketLength: binary.BigEndian.Uint32(buf[4:8]),
			DataLength:   binary.BigEndian.Uint32(buf[8:12]),
			DataType:     binary.BigEndian.Uint16(buf[12:14]),
			SeqNum:       buf[14],
			Flags:        buf[15],
		}

		seq, ok := nextSeq[pkt.ChannelID]
		if !ok {
			seq = hdr.SeqNum
		}

		if splitPoints, ok := normalized[pktIdx]; ok {
			segments, next, err := buildA429Segments(buf, hdr, &pkt, splitPoints, seq, profile)
			if err != nil {
				return "", err
			}
			for _, segment := range segments {
				if _, err := out.Write(segment); err != nil {
					return "", err
				}
			}
			nextSeq[pkt.ChannelID] = next
			continue
		}

		if err := updatePrimaryHeaderSequence(buf[:primaryHeaderSize], profile, seq); err != nil {
			return "", err
		}
		if _, err := out.Write(buf); err != nil {
			return "", err
		}
		nextSeq[pkt.ChannelID] = seq + 1
	}

	if err := out.Sync(); err != nil {
		return "", err
	}
	return outPath, nil
}

func updatePrimaryHeaderSequence(header []byte, profile string, seq uint8) error {
	if len(header) < primaryHeaderSize {
		return fmt.Errorf("header too short: %d", len(header))
	}
	header[14] = seq
	checksum, err := ComputeHeaderChecksum(profile, header)
	if err != nil {
		return err
	}
	header[16] = byte(checksum >> 8)
	header[17] = byte(checksum)
	return nil
}

func buildA429Segments(original []byte, hdr PacketHeader, pkt *PacketIndex, splitPoints []int, startSeq uint8, profile string) ([][]byte, uint8, error) {
	if pkt == nil {
		return nil, startSeq, errors.New("nil packet index")
	}
	info := pkt.A429
	if info == nil {
		return nil, startSeq, errors.New("missing ARINC-429 metadata")
	}
	totalWords := len(info.Words)
	if totalWords == 0 {
		return nil, startSeq, errors.New("ARINC-429 packet empty")
	}

	indices := make([]int, 0, len(splitPoints)+2)
	indices = append(indices, 0)
	indices = append(indices, splitPoints...)
	indices = append(indices, totalWords)

	secLen := 0
	if pkt.HasSecHdr {
		secLen = secondaryHeaderSize
		if len(original) < primaryHeaderSize+secLen {
			return nil, startSeq, fmt.Errorf("packet length %d too small for secondary header", len(original))
		}
	}

	baseTimeUs := pkt.TimeStampUs
	if baseTimeUs < 0 && pkt.HasSecHdr {
		tf := hdr.Flags & packetFlagTimeFormatMask
		if len(original) >= primaryHeaderSize+8 {
			ts, _, err := decodeIPTSToMicros(tf, original[primaryHeaderSize:primaryHeaderSize+8])
			if err == nil {
				baseTimeUs = ts
			}
		}
	}

	segments := make([][]byte, 0, len(indices)-1)
	currentSeq := startSeq
	for i := 0; i < len(indices)-1; i++ {
		start := indices[i]
		end := indices[i+1]
		if end <= start {
			continue
		}
		segLen := end - start

		payloadLen := 4 + segLen*8
		payload := make([]byte, payloadLen)
		csdw := (info.CSDW & 0xFFFF0000) | uint32(segLen)
		binary.BigEndian.PutUint32(payload[0:4], csdw)
		cursor := 4
		for w := start; w < end; w++ {
			word := info.Words[w]
			idWord := word.IDWord
			if w == start && start != 0 {
				idWord &^= 0x000FFFFF
			}
			binary.BigEndian.PutUint32(payload[cursor:cursor+4], idWord)
			cursor += 4
			binary.BigEndian.PutUint32(payload[cursor:cursor+4], word.DataWord)
			cursor += 4
		}

		header := make([]byte, primaryHeaderSize)
		copy(header, original[:primaryHeaderSize])
		dataLen := payloadLen
		var secondary []byte
		if secLen > 0 {
			dataLen += secLen
			secondary = make([]byte, secLen)
			copy(secondary, original[primaryHeaderSize:primaryHeaderSize+secLen])
			if i > 0 && baseTimeUs >= 0 {
				offsetUs := computeA429OffsetUs(info.Words, start)
				tsUs := baseTimeUs + offsetUs
				encoded, err := encodeSecondaryHeaderTime(header[15]&packetFlagTimeFormatMask, tsUs)
				if err != nil {
					return nil, startSeq, err
				}
				copy(secondary[0:len(encoded)], encoded)
				// Reserved field should be zeroed prior to checksum calculation.
				if len(secondary) >= 10 {
					secondary[8] = 0
					secondary[9] = 0
					checksum := computeSecondaryHeaderChecksum(secondary)
					binary.BigEndian.PutUint16(secondary[10:12], checksum)
				}
			} else if i > 0 && len(secondary) >= 10 {
				// Ensure checksum reflects duplicated time when timestamp unavailable.
				checksum := computeSecondaryHeaderChecksum(secondary)
				binary.BigEndian.PutUint16(secondary[10:12], checksum)
			}
		}

		binary.BigEndian.PutUint32(header[4:8], uint32(primaryHeaderSize+dataLen-4))
		binary.BigEndian.PutUint32(header[8:12], uint32(dataLen))
		if err := updatePrimaryHeaderSequence(header, profile, currentSeq); err != nil {
			return nil, startSeq, err
		}

		segment := make([]byte, len(header)+len(secondary)+len(payload))
		copy(segment, header)
		offset := len(header)
		if len(secondary) > 0 {
			copy(segment[offset:], secondary)
			offset += len(secondary)
		}
		copy(segment[offset:], payload)
		segments = append(segments, segment)
		currentSeq++
	}
	return segments, currentSeq, nil
}

func computeA429OffsetUs(words []A429Word, start int) int64 {
	if start <= 0 || start >= len(words) {
		return 0
	}
	var total uint64
	for i := 1; i <= start && i < len(words); i++ {
		total += uint64(words[i].GapTime0p1Us)
	}
	return int64(total / 10)
}

func encodeSecondaryHeaderTime(tf uint8, timestampUs int64) ([]byte, error) {
	if timestampUs < 0 {
		return nil, fmt.Errorf("negative timestamp %d", timestampUs)
	}
	buf := make([]byte, 8)
	switch tf {
	case timeFormatIRIG106:
		seconds := timestampUs / 1_000_000
		fractional := timestampUs % 1_000_000
		if fractional < 0 {
			fractional += 1_000_000
			seconds--
		}
		hundredths := fractional / 10_000
		usec := fractional % 10_000
		totalHundredths := seconds*100 + hundredths
		if totalHundredths < 0 {
			return nil, fmt.Errorf("timestamp underflow for IRIG format")
		}
		binary.BigEndian.PutUint16(buf[0:2], uint16(uint64(totalHundredths)>>16))
		binary.BigEndian.PutUint16(buf[2:4], uint16(uint64(totalHundredths)&0xFFFF))
		binary.BigEndian.PutUint16(buf[4:6], uint16(usec))
		buf[6] = 0
		buf[7] = 0
	case timeFormatIEEE1588:
		seconds := timestampUs / 1_000_000
		nanos := (timestampUs % 1_000_000) * 1000
		if nanos < 0 {
			nanos += 1_000_000 * 1000
			seconds--
		}
		if seconds < 0 {
			return nil, fmt.Errorf("timestamp underflow for IEEE 1588 format")
		}
		binary.BigEndian.PutUint32(buf[0:4], uint32(nanos))
		binary.BigEndian.PutUint32(buf[4:8], uint32(seconds))
	default:
		return nil, ErrUnsupportedTimeFormat
	}
	return buf, nil
}

func computeSecondaryHeaderChecksum(sec []byte) uint16 {
	if len(sec) < 2 {
		return 0
	}
	var sum uint32
	limit := len(sec) - 2
	for i := 0; i < limit; i += 2 {
		word := binary.BigEndian.Uint16(sec[i : i+2])
		sum += uint32(word)
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum & 0xFFFF)
}

// RewriteWithPlan rewrites the Chapter 10 file at srcPath according to the
// provided structural plan and writes the result to dstPath. The supplied index
// must describe the packets in srcPath.
func RewriteWithPlan(srcPath, dstPath, profile string, idx *FileIndex, plan *StructuralPlan) error {
	if idx == nil {
		return errors.New("no index available")
	}
	if plan == nil {
		return errors.New("no plan provided")
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() {
		out.Sync()
		out.Close()
	}()

	before := make(map[int][]PacketInsert)
	packetCount := len(idx.Packets)
	for _, ins := range plan.Inserts {
		target := ins.BeforeIndex
		if target < 0 {
			target = 0
		} else if target > packetCount {
			target = packetCount
		}
		if len(ins.Packet) == 0 {
			continue
		}
		before[target] = append(before[target], PacketInsert{BeforeIndex: target, Packet: ins.Packet})
	}

	state := newRewriteState(plan)

	writePacket := func(packet []byte) error {
		if len(packet) < primaryHeaderSize {
			return fmt.Errorf("packet shorter than primary header: %d", len(packet))
		}
		buf := make([]byte, len(packet))
		copy(buf, packet)
		if err := state.apply(profile, buf[:primaryHeaderSize]); err != nil {
			return err
		}
		_, err := out.Write(buf)
		return err
	}

	for i := 0; i < packetCount; i++ {
		if inserts := before[i]; len(inserts) > 0 {
			for _, ins := range inserts {
				if err := writePacket(ins.Packet); err != nil {
					return err
				}
			}
		}
		if plan.Deletes != nil {
			if _, skip := plan.Deletes[i]; skip {
				continue
			}
		}
		pkt := idx.Packets[i]
		totalLen := int64(pkt.PacketLength) + 4
		section := io.NewSectionReader(in, pkt.Offset, totalLen)
		buf := make([]byte, totalLen)
		if _, err := io.ReadFull(section, buf); err != nil {
			return err
		}
		if len(buf) < primaryHeaderSize {
			return fmt.Errorf("packet %d shorter than primary header", i)
		}
		if err := state.apply(profile, buf[:primaryHeaderSize]); err != nil {
			return err
		}
		if _, err := out.Write(buf); err != nil {
			return err
		}
	}

	if inserts := before[packetCount]; len(inserts) > 0 {
		for _, ins := range inserts {
			if err := writePacket(ins.Packet); err != nil {
				return err
			}
		}
	}

	return out.Sync()
}

// RewriteTransferFileWithDirectory rewrites the transfer file at srcPath to dstPath using
// the provided directory image while preserving the original data bytes beginning at
// dataOffset.
func RewriteTransferFileWithDirectory(srcPath, dstPath string, dir DirectoryImage, dataOffset int64) error {
	dirBytes, err := dir.Marshal()
	if err != nil {
		return err
	}
	if int64(len(dirBytes)) != dataOffset {
		return fmt.Errorf("directory length %d does not match data offset %d", len(dirBytes), dataOffset)
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() {
		out.Sync()
		out.Close()
	}()
	if _, err := out.Write(dirBytes); err != nil {
		return err
	}
	if _, err := in.Seek(dataOffset, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

// CopyChapter10Data writes the Chapter 10 byte range beginning at offset to dstPath.
func CopyChapter10Data(srcPath, dstPath string, offset int64) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	if _, err := in.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() {
		out.Sync()
		out.Close()
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

type rewriteState struct {
	plan    *StructuralPlan
	nextSeq map[uint16]uint8
}

func newRewriteState(plan *StructuralPlan) *rewriteState {
	return &rewriteState{plan: plan, nextSeq: make(map[uint16]uint8)}
}

func (p *StructuralPlan) shouldRenumber(channel uint16) bool {
	if p == nil {
		return false
	}
	if p.RenumberAll {
		return true
	}
	if len(p.RenumberChannels) == 0 {
		return false
	}
	return p.RenumberChannels[channel]
}

func (s *rewriteState) apply(profile string, header []byte) error {
	if len(header) < primaryHeaderSize {
		return fmt.Errorf("header too short: %d", len(header))
	}
	channel := binary.BigEndian.Uint16(header[2:4])
	if s.plan != nil && s.plan.ChannelRemap != nil {
		if newID, ok := s.plan.ChannelRemap[channel]; ok {
			channel = newID
			binary.BigEndian.PutUint16(header[2:4], newID)
		}
	}

	if s.plan != nil && s.plan.shouldRenumber(channel) {
		seq := s.nextSeq[channel]
		header[14] = seq
		s.nextSeq[channel] = seq + 1
	} else {
		seq := header[14]
		s.nextSeq[channel] = seq + 1
	}

	header[16] = 0
	header[17] = 0
	checksum, err := ComputeHeaderChecksum(profile, header)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(header[16:18], checksum)
	return nil
}

// BuildTimePacket constructs a minimal time data packet using the supplied
// parameters. The payload encodes the provided timestamp using the requested
// time format when possible.
func BuildTimePacket(profile string, channelID uint16, timeFormat uint8, timestampUs int64) ([]byte, error) {
	payload := make([]byte, secondaryTimeFieldLen)
	if timestampUs >= 0 {
		if encoded, err := encodeSecondaryHeaderTime(timeFormat, timestampUs); err == nil && len(encoded) == len(payload) {
			copy(payload, encoded)
		}
	}

	header := make([]byte, primaryHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], syncPattern)
	binary.BigEndian.PutUint16(header[2:4], channelID)
	binary.BigEndian.PutUint32(header[4:8], uint32(primaryHeaderSize+len(payload)-4))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint16(header[12:14], 0x0000)
	header[14] = 0
	header[15] = timeFormat & packetFlagTimeFormatMask
	header[16] = 0
	header[17] = 0
	checksum, err := ComputeHeaderChecksum(profile, header)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(header[16:18], checksum)

	packet := make([]byte, len(header)+len(payload))
	copy(packet, header)
	copy(packet[len(header):], payload)
	return packet, nil
}
