package ch10

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"

	"example.com/ch10gate/internal/common"
)

const (
	syncPattern           = 0xEB25
	primaryHeaderSize     = 20
	secondaryHeaderSize   = 12
	secondaryTimeFieldLen = 8
	defaultResyncWindow   = 64 * 1024

	packetFlagTimeFormatMask = 0x0C
	packetFlagSecondaryHdr   = 0x80

	timeFormatIRIG106  = 0x00
	timeFormatIEEE1588 = 0x04
)

var (
	ErrNoSync                = errors.New("sync pattern 0xEB25 not found at expected position")
	ErrUnsupportedProfile    = errors.New("unsupported Chapter 10 profile")
	ErrUnsupportedTimeFormat = errors.New("unsupported secondary header time format")
)

func ParsePrimaryHeader(r io.ReaderAt, offset int64) (PacketHeader, error) {
	var hdr PacketHeader
	buf := make([]byte, primaryHeaderSize)
	n, err := r.ReadAt(buf, offset)
	if err != nil {
		if errors.Is(err, io.EOF) && n < primaryHeaderSize {
			return hdr, io.ErrUnexpectedEOF
		}
		return hdr, err
	}
	if n < primaryHeaderSize {
		return hdr, io.ErrUnexpectedEOF
	}
	hdr.Sync = binary.BigEndian.Uint16(buf[0:2])
	hdr.ChannelID = binary.BigEndian.Uint16(buf[2:4])
	hdr.PacketLength = binary.BigEndian.Uint32(buf[4:8])
	hdr.DataLength = binary.BigEndian.Uint32(buf[8:12])
	hdr.DataType = binary.BigEndian.Uint16(buf[12:14])
	hdr.SeqNum = buf[14]
	hdr.Flags = buf[15]
	return hdr, nil
}

func parseSecHdrFlags(hdr *PacketHeader) (bool, uint8) {
	if hdr == nil {
		return false, 0
	}
	has := hdr.Flags&packetFlagSecondaryHdr != 0
	tf := hdr.Flags & packetFlagTimeFormatMask
	return has, tf
}

const (
	pcmBitReserved31   = uint32(1) << 31
	pcmBitIPH          = uint32(1) << 30
	pcmBitMajorFrame   = uint32(1) << 29
	pcmBitMinorFrame   = uint32(1) << 28
	pcmBitsMinorStatus = uint32(0x3) << 26
	pcmBitsMajorStatus = uint32(0x3) << 24
	pcmBitsReserved22  = uint32(0x3) << 22
	pcmBitAlignment32  = uint32(1) << 21
	pcmBitThroughput   = uint32(1) << 20
	pcmBitPacked       = uint32(1) << 19
	pcmBitUnpacked     = uint32(1) << 18
	pcmMaskSyncOffset  = uint32(0x3FFFF)
)

// DecodePCMCSDW interprets the PCM channel-specific data word and returns a
// populated PCMInfo describing the bitfield contents.
func DecodePCMCSDW(csdw uint32) PCMInfo {
	info := PCMInfo{CSDW: csdw}
	info.HasIPH = csdw&pcmBitIPH != 0
	info.MajorFrame = csdw&pcmBitMajorFrame != 0
	info.MinorFrame = csdw&pcmBitMinorFrame != 0
	info.MinorStatus = uint8((csdw >> 26) & 0x3)
	info.MajorStatus = uint8((csdw >> 24) & 0x3)
	if csdw&pcmBitAlignment32 != 0 {
		info.AlignmentBits = 32
	} else {
		info.AlignmentBits = 16
	}
	info.Throughput = csdw&pcmBitThroughput != 0
	info.Packed = csdw&pcmBitPacked != 0
	info.Unpacked = csdw&pcmBitUnpacked != 0
	modeCount := 0
	if info.Throughput {
		modeCount++
	}
	if info.Packed {
		modeCount++
	}
	if info.Unpacked {
		modeCount++
	}
	switch {
	case modeCount == 1 && info.Throughput:
		info.Mode = PCMModeThroughput
	case modeCount == 1 && info.Packed:
		info.Mode = PCMModePacked
	case modeCount == 1 && info.Unpacked:
		info.Mode = PCMModeUnpacked
	default:
		info.Mode = PCMModeUnknown
		if modeCount != 1 {
			info.ModeConflict = true
		}
	}
	info.SyncOffset = csdw & pcmMaskSyncOffset
	if csdw&pcmBitReserved31 != 0 || csdw&pcmBitsReserved22 != 0 {
		info.ReservedNonZero = true
	}
	return info
}

func isTimePacket(hdr *PacketHeader) bool {
	if hdr == nil {
		return false
	}
	return hdr.DataType == 0x0000
}

func decodeIPTSToMicros(tf uint8, raw []byte) (int64, SecondaryHeader, error) {
	secondary := SecondaryHeader{HasSecHdr: true, TimeFormat: tf, TimeStampUs: -1}
	if len(raw) < secondaryTimeFieldLen {
		return -1, secondary, fmt.Errorf("timestamp too short: %d bytes", len(raw))
	}
	switch tf {
	case timeFormatIRIG106:
		high := binary.BigEndian.Uint16(raw[0:2])
		low := binary.BigEndian.Uint16(raw[2:4])
		usec := binary.BigEndian.Uint16(raw[4:6])
		totalHundredths := uint64(high)*65536 + uint64(low)
		seconds := totalHundredths / 100
		hundredths := totalHundredths % 100
		fractionalMicros := uint64(hundredths)*10_000 + uint64(usec)
		if fractionalMicros >= 1_000_000 {
			seconds += fractionalMicros / 1_000_000
			fractionalMicros = fractionalMicros % 1_000_000
		}
		secondary.Seconds = uint32(seconds)
		secondary.Subsecond = uint32(fractionalMicros)
		secondary.TimeStampUs = int64(seconds*1_000_000 + fractionalMicros)
		return secondary.TimeStampUs, secondary, nil
	case timeFormatIEEE1588:
		nanos := binary.BigEndian.Uint32(raw[0:4])
		secs := binary.BigEndian.Uint32(raw[4:8])
		secondary.Seconds = secs
		secondary.Subsecond = nanos
		secondary.TimeStampUs = int64(secs)*1_000_000 + int64(nanos)/1_000
		return secondary.TimeStampUs, secondary, nil
	default:
		return -1, secondary, ErrUnsupportedTimeFormat
	}
}

// Reader iterates across a Chapter 10 file sequentially while building an index
// of packet metadata.
type Reader struct {
	file         *os.File
	size         int64
	offset       int64
	resyncWindow int64
	resyncBuf    []byte

	primary    PacketHeader
	primarySet bool
	index      FileIndex

	lastTimeRefUs         int64
	timeSeen              bool
	timeSeenBeforeDynamic bool
	dynamicSeen           bool
}

// NewReader opens the file at path and prepares an iterator.
func NewReader(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Reader{
		file:                  f,
		size:                  info.Size(),
		resyncWindow:          defaultResyncWindow,
		resyncBuf:             make([]byte, defaultResyncWindow),
		lastTimeRefUs:         -1,
		timeSeenBeforeDynamic: true,
		index: FileIndex{
			TimeSeenBeforeDynamic: true,
		},
	}, nil
}

// Close releases the underlying file handle.
func (r *Reader) Close() error {
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

// PrimaryHeader returns the first successfully parsed packet header.
func (r *Reader) PrimaryHeader() (PacketHeader, bool) {
	if !r.primarySet {
		return PacketHeader{}, false
	}
	return r.primary, true
}

// Index returns a copy of the accumulated file index.
func (r *Reader) Index() FileIndex {
	out := FileIndex{
		Packets:               make([]PacketIndex, len(r.index.Packets)),
		HasTimePacket:         r.index.HasTimePacket,
		TimeSeenBeforeDynamic: r.index.TimeSeenBeforeDynamic,
	}
	copy(out.Packets, r.index.Packets)
	return out
}

// Next advances to the next packet header. It returns io.EOF when the end of
// the file is reached.
func (r *Reader) Next() (PacketHeader, PacketIndex, error) {
	if r.file == nil {
		return PacketHeader{}, PacketIndex{}, io.EOF
	}
	for {
		if r.offset+primaryHeaderSize > r.size {
			if r.offset >= r.size {
				return PacketHeader{}, PacketIndex{}, io.EOF
			}
			return PacketHeader{}, PacketIndex{}, io.ErrUnexpectedEOF
		}
		hdr, err := ParsePrimaryHeader(r.file, r.offset)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return PacketHeader{}, PacketIndex{}, err
			}
			return PacketHeader{}, PacketIndex{}, err
		}
		if hdr.Sync != syncPattern {
			if err := r.resync("sync pattern"); err != nil {
				return PacketHeader{}, PacketIndex{}, err
			}
			continue
		}

		totalLen := int64(hdr.PacketLength) + 4
		if totalLen < primaryHeaderSize {
			if err := r.resync("packet length too small"); err != nil {
				return PacketHeader{}, PacketIndex{}, err
			}
			continue
		}
		nextOffset := r.offset + totalLen
		if nextOffset > r.size {
			if err := r.resync("packet length beyond file"); err != nil {
				return PacketHeader{}, PacketIndex{}, err
			}
			continue
		}

		if !r.primarySet {
			r.primary = hdr
			r.primarySet = true
		}

		hasSecHdr, timeFmt := parseSecHdrFlags(&hdr)
		isTime := isTimePacket(&hdr)
		idx := PacketIndex{
			Offset:       r.offset,
			ChannelID:    hdr.ChannelID,
			DataType:     hdr.DataType,
			SeqNum:       hdr.SeqNum,
			Flags:        hdr.Flags,
			PacketLength: hdr.PacketLength,
			DataLength:   hdr.DataLength,
			HasSecHdr:    hasSecHdr,
			TimeStampUs:  -1,
			TimeFormat:   timeFmt,
			Source:       TimestampSourceUnknown,
			IsTimePacket: isTime,
		}

		secOffset := r.offset + primaryHeaderSize
		if hasSecHdr {
			if secOffset+secondaryHeaderSize <= nextOffset && secOffset+secondaryHeaderSize <= r.size {
				idx.SecHdrBytes = true
				buf := make([]byte, secondaryTimeFieldLen)
				if _, err := r.file.ReadAt(buf, secOffset); err == nil {
					ts, secondary, err := decodeIPTSToMicros(timeFmt, buf)
					if err != nil {
						if errors.Is(err, ErrUnsupportedTimeFormat) {
							common.Logf("packet at offset %d uses unsupported time format 0x%X", r.offset, timeFmt)
						} else {
							common.Logf("packet at offset %d timestamp decode failed: %v", r.offset, err)
						}
					} else {
						idx.TimeStampUs = ts
						idx.SecHdrValid = true
						idx.TimeFormat = secondary.TimeFormat
						idx.Source = TimestampSourceSecondaryHeader
					}
				} else {
					common.Logf("packet at offset %d timestamp read failed: %v", r.offset, err)
				}
			} else {
				common.Logf("packet at offset %d missing secondary header bytes", r.offset)
			}
		}

		payloadOffset := secOffset
		payloadLen := int64(hdr.DataLength)
		if hasSecHdr {
			payloadOffset += int64(secondaryHeaderSize)
			if payloadLen >= int64(secondaryHeaderSize) {
				payloadLen -= int64(secondaryHeaderSize)
			} else {
				payloadLen = 0
			}
		}
		if payloadOffset > nextOffset {
			payloadLen = 0
		}
		maxPayload := nextOffset - payloadOffset
		if payloadLen > maxPayload {
			payloadLen = maxPayload
		}
		if payloadLen < 0 {
			payloadLen = 0
		}

		if hdr.DataType == 0x18 || hdr.DataType == 0x19 {
			info, err := parseMIL1553Payload(r.file, payloadOffset, payloadLen, hdr.DataType)
			if err != nil {
				common.Logf("1553 parse error at offset %d: %v", r.offset, err)
			} else if info != nil {
				if info.ParseError != "" {
					common.Logf("1553 parse warning at offset %d: %s", r.offset, info.ParseError)
				}
				idx.MIL1553 = info
			}
		} else if hdr.DataType == 0x08 {
			info, err := parsePCMPayload(r.file, payloadOffset, payloadLen)
			if err != nil {
				common.Logf("PCM parse error at offset %d: %v", r.offset, err)
			} else if info != nil {
				if info.ParseError != "" {
					common.Logf("PCM parse warning at offset %d: %s", r.offset, info.ParseError)
				}
				idx.PCM = info
			}
		} else if hdr.DataType == 0x38 {
			info, err := parseA429Payload(r.file, payloadOffset, payloadLen)
			if err != nil {
				common.Logf("ARINC-429 parse error at offset %d: %v", r.offset, err)
			} else if info != nil {
				if info.ParseError != "" {
					common.Logf("ARINC-429 parse warning at offset %d: %s", r.offset, info.ParseError)
				}
				idx.A429 = info
			}
		}

		if isTime {
			r.index.HasTimePacket = true
			if idx.TimeStampUs < 0 && payloadLen >= int64(secondaryTimeFieldLen) {
				buf := make([]byte, secondaryTimeFieldLen)
				if _, err := r.file.ReadAt(buf, payloadOffset); err == nil {
					ts, _, err := decodeIPTSToMicros(timeFmt, buf)
					if err == nil {
						idx.TimeStampUs = ts
					}
				}
			}
			if idx.TimeStampUs >= 0 {
				r.lastTimeRefUs = idx.TimeStampUs
				r.timeSeen = true
				idx.Source = TimestampSourceTimePacket
			}
		} else {
			if !r.dynamicSeen {
				r.dynamicSeen = true
				if !r.timeSeen {
					r.timeSeenBeforeDynamic = false
				}
			}
			if idx.TimeStampUs < 0 && payloadLen >= int64(secondaryTimeFieldLen) {
				buf := make([]byte, secondaryTimeFieldLen)
				if _, err := r.file.ReadAt(buf, payloadOffset); err == nil {
					ipts := int64(binary.BigEndian.Uint64(buf))
					if r.lastTimeRefUs >= 0 {
						idx.TimeStampUs = r.lastTimeRefUs + ipts
						idx.Source = TimestampSourceIPTS
					}
				}
			}
		}

		if idx.Source == TimestampSourceUnknown && idx.SecHdrValid && !isTime {
			idx.Source = TimestampSourceSecondaryHeader
		}
		if isTime && idx.Source == TimestampSourceSecondaryHeader {
			idx.Source = TimestampSourceTimePacket
		}

		r.index.TimeSeenBeforeDynamic = r.timeSeenBeforeDynamic

		r.index.Packets = append(r.index.Packets, idx)

		r.offset = nextOffset
		return hdr, idx, nil
	}
}

func (r *Reader) resync(reason string) error {
	common.Logf("resync at offset %d: %s", r.offset, reason)
	start := r.offset + 1
	if start >= r.size {
		r.offset = r.size
		return io.EOF
	}
	limit := start + r.resyncWindow
	if limit > r.size {
		limit = r.size
	}
	window := limit - start
	if window < 2 {
		r.offset = limit
		return io.EOF
	}
	if int64(len(r.resyncBuf)) < window {
		r.resyncBuf = make([]byte, window)
	}
	buf := r.resyncBuf[:window]
	n, err := r.file.ReadAt(buf, start)
	if n < 2 && err != nil {
		if errors.Is(err, io.EOF) {
			r.offset = r.size
			return io.EOF
		}
		return err
	}
	for i := 0; i < n-1; i++ {
		if buf[i] == 0xEB && buf[i+1] == 0x25 {
			r.offset = start + int64(i)
			common.Logf("resync successful, new offset %d", r.offset)
			return nil
		}
	}
	r.offset = limit
	if limit >= r.size || errors.Is(err, io.EOF) {
		return io.EOF
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return ErrNoSync
}

func ScanFileMin(path string) (PacketHeader, FileIndex, error) {
	reader, err := NewReader(path)
	if err != nil {
		return PacketHeader{}, FileIndex{}, err
	}
	defer reader.Close()

	for {
		_, _, err := reader.Next()
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		return PacketHeader{}, FileIndex{}, err
	}

	idx := reader.Index()
	hdr, ok := reader.PrimaryHeader()
	if !ok {
		return PacketHeader{}, idx, ErrNoSync
	}
	return hdr, idx, nil
}

func parsePCMPayload(r io.ReaderAt, offset int64, payloadLen int64) (*PCMInfo, error) {
	info := &PCMInfo{}
	if payloadLen <= 0 {
		info.ParseError = "payload empty"
		return info, nil
	}
	if payloadLen < 4 {
		info.ParseError = "payload shorter than CSDW"
		return info, nil
	}
	var csdwBuf [4]byte
	n, err := r.ReadAt(csdwBuf[:], offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return info, err
	}
	if n < 4 {
		info.ParseError = "payload shorter than CSDW"
		return info, nil
	}
	decoded := DecodePCMCSDW(binary.BigEndian.Uint32(csdwBuf[:]))
	*info = decoded
	return info, nil
}

func parseMIL1553Payload(r io.ReaderAt, offset int64, payloadLen int64, dataType uint16) (*MIL1553Info, error) {
	var format uint8
	switch dataType {
	case 0x18:
		format = 1
	case 0x19:
		format = 2
	default:
		return nil, nil
	}

	info := &MIL1553Info{Format: format}
	if payloadLen <= 0 {
		info.ParseError = "payload empty"
		return info, nil
	}
	if payloadLen < 4 {
		info.ParseError = "payload shorter than CSDW"
		return info, nil
	}

	var csdwBuf [4]byte
	n, err := r.ReadAt(csdwBuf[:], offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return info, err
	}
	if n < 4 {
		info.ParseError = "payload shorter than CSDW"
		return info, nil
	}
	info.CSDW = binary.BigEndian.Uint32(csdwBuf[:])
	cursor := offset + 4
	end := offset + payloadLen

	switch format {
	case 1:
		info.TTB = uint8((info.CSDW >> 30) & 0x3)
		info.MessageCount = info.CSDW & 0x00FFFFFF
	case 2:
		info.MessageCount = info.CSDW
	}

	for msgIdx := uint32(0); msgIdx < info.MessageCount; msgIdx++ {
		if cursor+8 > end {
			info.ParseError = fmt.Sprintf("message %d missing IPTS", msgIdx+1)
			break
		}
		var iptsBuf [8]byte
		n, err = r.ReadAt(iptsBuf[:], cursor)
		if err != nil && !errors.Is(err, io.EOF) {
			return info, err
		}
		if n < 8 {
			info.ParseError = fmt.Sprintf("message %d IPTS truncated", msgIdx+1)
			break
		}
		msg := MIL1553Message{IPTS: binary.BigEndian.Uint64(iptsBuf[:])}
		cursor += 8

		switch format {
		case 1:
			if cursor+6 > end {
				info.ParseError = fmt.Sprintf("message %d missing IPDH", msgIdx+1)
				return info, nil
			}
			var ipdhBuf [6]byte
			n, err = r.ReadAt(ipdhBuf[:], cursor)
			if err != nil && !errors.Is(err, io.EOF) {
				return info, err
			}
			if n < 6 {
				info.ParseError = fmt.Sprintf("message %d IPDH truncated", msgIdx+1)
				return info, nil
			}
			msg.BlockStatusWord = binary.BigEndian.Uint16(ipdhBuf[0:2])
			msg.GapTimeWord = binary.BigEndian.Uint16(ipdhBuf[2:4])
			msg.LengthWord = binary.BigEndian.Uint16(ipdhBuf[4:6])
			cursor += 6
			msgLen := int64(msg.LengthWord)
			if msgLen < 0 {
				info.ParseError = fmt.Sprintf("message %d length underflow", msgIdx+1)
				return info, nil
			}
			if cursor+msgLen > end {
				info.ParseError = fmt.Sprintf("message %d extends past payload", msgIdx+1)
				return info, nil
			}
			info.Messages = append(info.Messages, msg)
			cursor += msgLen
		case 2:
			if cursor+4 > end {
				info.ParseError = fmt.Sprintf("message %d missing IPDH", msgIdx+1)
				return info, nil
			}
			var ipdhBuf [4]byte
			n, err = r.ReadAt(ipdhBuf[:], cursor)
			if err != nil && !errors.Is(err, io.EOF) {
				return info, err
			}
			if n < 4 {
				info.ParseError = fmt.Sprintf("message %d IPDH truncated", msgIdx+1)
				return info, nil
			}
			msg.IPDHStatus = binary.BigEndian.Uint16(ipdhBuf[0:2])
			msg.IPDHLength = binary.BigEndian.Uint16(ipdhBuf[2:4])
			cursor += 4
			msgLen := int64(msg.IPDHLength)
			if msgLen < 0 {
				info.ParseError = fmt.Sprintf("message %d length underflow", msgIdx+1)
				return info, nil
			}
			if cursor+msgLen > end {
				info.ParseError = fmt.Sprintf("message %d extends past payload", msgIdx+1)
				return info, nil
			}
			info.Messages = append(info.Messages, msg)
			cursor += msgLen
		}
	}

	if info.ParseError == "" && info.MessageCount != uint32(len(info.Messages)) {
		info.ParseError = fmt.Sprintf("message count mismatch: expected %d, parsed %d", info.MessageCount, len(info.Messages))
	}
	return info, nil
}

func parseA429Payload(r io.ReaderAt, offset int64, payloadLen int64) (*A429Info, error) {
	info := &A429Info{}
	if payloadLen <= 0 {
		info.ParseError = "payload empty"
		return info, nil
	}
	if payloadLen < 4 {
		info.ParseError = "payload shorter than CSDW"
		return info, nil
	}

	var csdwBuf [4]byte
	n, err := r.ReadAt(csdwBuf[:], offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return info, err
	}
	if n < 4 {
		info.ParseError = "payload shorter than CSDW"
		return info, nil
	}
	info.CSDW = binary.BigEndian.Uint32(csdwBuf[:])
	info.MessageCount = uint32(info.CSDW & 0x0000FFFF)
	cursor := offset + 4
	end := offset + payloadLen

	if info.MessageCount == 0 {
		return info, nil
	}
	expectedLen := int64(info.MessageCount) * 8
	if cursor+expectedLen > end {
		info.ParseError = "payload shorter than ID/data words"
		return info, nil
	}

	info.Words = make([]A429Word, 0, info.MessageCount)
	var pairBuf [8]byte
	for wordIdx := uint32(0); wordIdx < info.MessageCount; wordIdx++ {
		if cursor+8 > end {
			info.ParseError = fmt.Sprintf("word %d truncated", wordIdx+1)
			return info, nil
		}
		n, err = r.ReadAt(pairBuf[:], cursor)
		if err != nil && !errors.Is(err, io.EOF) {
			return info, err
		}
		if n < 8 {
			info.ParseError = fmt.Sprintf("word %d truncated", wordIdx+1)
			return info, nil
		}
		idWord := binary.BigEndian.Uint32(pairBuf[0:4])
		dataWord := binary.BigEndian.Uint32(pairBuf[4:8])
		cursor += 8

		word := A429Word{
			IDWord:          idWord,
			DataWord:        dataWord,
			Bus:             uint8((idWord >> 24) & 0xFF),
			FormatError:     idWord&(1<<23) != 0,
			ParityErrorFlag: idWord&(1<<22) != 0,
			BusSpeedHigh:    idWord&(1<<21) != 0,
			GapTime0p1Us:    idWord & 0x000FFFFF,
			Label:           uint8(dataWord & 0xFF),
			SDI:             uint8((dataWord >> 8) & 0x3),
			SSM:             uint8((dataWord >> 29) & 0x3),
			ParityBit:       uint8((dataWord >> 31) & 0x1),
		}
		word.ComputedParity = bits.OnesCount32(dataWord)%2 == 1
		info.Words = append(info.Words, word)
	}

	if uint32(len(info.Words)) != info.MessageCount {
		info.ParseError = fmt.Sprintf("message count mismatch: expected %d, parsed %d", info.MessageCount, len(info.Words))
	}
	return info, nil
}

// ComputeHeaderChecksum calculates the header checksum for the supplied
// primary header bytes using the active profile rules.
func ComputeHeaderChecksum(profile string, header []byte) (uint16, error) {
	if len(header) < primaryHeaderSize {
		return 0, fmt.Errorf("header too short: %d bytes", len(header))
	}
	switch profile {
	case "106-15":
		var sum uint32
		// The checksum is computed across the first 16 bytes of the
		// primary header (through the flags field).
		for i := 0; i < 16; i += 2 {
			word := binary.BigEndian.Uint16(header[i : i+2])
			sum += uint32(word)
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
		return ^uint16(sum & 0xFFFF), nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedProfile, profile)
	}
}

// DataChecksum encapsulates a streaming CRC-16 calculation for payload data.
type DataChecksum struct {
	value  uint16
	poly   uint16
	xorOut uint16
}

type dataChecksumParams struct {
	poly   uint16
	init   uint16
	xorOut uint16
}

var dataChecksumProfiles = map[string]dataChecksumParams{
	"106-15": {poly: 0x1021, init: 0xFFFF, xorOut: 0x0000},
}

// NewDataChecksum returns an initialized checksum calculator for the supplied
// profile.
func NewDataChecksum(profile string) (*DataChecksum, error) {
	params, ok := dataChecksumProfiles[profile]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProfile, profile)
	}
	return &DataChecksum{value: params.init, poly: params.poly, xorOut: params.xorOut}, nil
}

// Write updates the checksum with the provided data.
func (c *DataChecksum) Write(p []byte) {
	if c == nil {
		return
	}
	for _, b := range p {
		c.value ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if c.value&0x8000 != 0 {
				c.value = (c.value << 1) ^ c.poly
			} else {
				c.value <<= 1
			}
			c.value &= 0xFFFF
		}
	}
}

// Sum16 returns the final checksum value.
func (c *DataChecksum) Sum16() uint16 {
	if c == nil {
		return 0
	}
	return (c.value ^ c.xorOut) & 0xFFFF
}

// ComputeDataChecksum calculates the checksum for the provided payload slice.
func ComputeDataChecksum(profile string, payload []byte) (uint16, error) {
	calc, err := NewDataChecksum(profile)
	if err != nil {
		return 0, err
	}
	calc.Write(payload)
	return calc.Sum16(), nil
}
