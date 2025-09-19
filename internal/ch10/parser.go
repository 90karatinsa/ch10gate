package ch10

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
		file:         f,
		size:         info.Size(),
		resyncWindow: defaultResyncWindow,
		resyncBuf:    make([]byte, defaultResyncWindow),
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
		Packets: make([]PacketIndex, len(r.index.Packets)),
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
		}

		if hasSecHdr {
			secOffset := r.offset + primaryHeaderSize
			if secOffset+secondaryHeaderSize <= nextOffset && secOffset+secondaryHeaderSize <= r.size {
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
						idx.HasSecHdr = secondary.HasSecHdr
					}
				} else {
					common.Logf("packet at offset %d timestamp read failed: %v", r.offset, err)
				}
			} else {
				common.Logf("packet at offset %d missing secondary header bytes", r.offset)
			}
		}

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
