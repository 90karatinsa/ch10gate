package ch10

import (
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
