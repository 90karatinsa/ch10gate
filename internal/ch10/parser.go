package ch10

import (
	"encoding/binary"
	"errors"
	"io"
	"os"

	"example.com/ch10gate/internal/common"
)

const (
	syncPattern         = 0xEB25
	primaryHeaderSize   = 20
	defaultResyncWindow = 64 * 1024
)

var (
	ErrNoSync = errors.New("sync pattern 0xEB25 not found at expected position")
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

		idx := PacketIndex{
			Offset:       r.offset,
			ChannelID:    hdr.ChannelID,
			DataType:     hdr.DataType,
			SeqNum:       hdr.SeqNum,
			Flags:        hdr.Flags,
			PacketLength: hdr.PacketLength,
			DataLength:   hdr.DataLength,
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
