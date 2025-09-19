package ch10

import (
	"encoding/binary"
	"errors"
	"io"
	"os"

	"example.com/ch10gate/internal/common"
)

var (
	ErrNoSync = errors.New("sync pattern 0xEB25 not found at expected position")
)

func ParsePrimaryHeader(r io.ReaderAt, offset int64) (PacketHeader, error) {
	var hdr PacketHeader
	buf := make([]byte, 20)
	_, err := r.ReadAt(buf, offset)
	if err != nil {
		return hdr, err
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

func ScanFileMin(path string) (PacketHeader, FileIndex, error) {
	var idx FileIndex
	f, err := os.Open(path)
	if err != nil {
		return PacketHeader{}, idx, err
	}
	defer f.Close()

	hdr, err := ParsePrimaryHeader(f, 0)
	if err != nil {
		return hdr, idx, err
	}
	if hdr.Sync != 0xEB25 {
		buf := make([]byte, 4096)
		_, _ = f.ReadAt(buf, 0)
		found := int64(-1)
		for i := 0; i < len(buf)-1; i++ {
			if buf[i] == 0xEB && buf[i+1] == 0x25 {
				found = int64(i)
				break
			}
		}
		if found >= 0 {
			common.Logf("Sync pattern found at offset %d; attempting reparse", found)
			hdr, err = ParsePrimaryHeader(f, found)
			if err != nil {
				return hdr, idx, err
			}
			idx.Packets = append(idx.Packets, PacketIndex{
				Offset:    found,
				ChannelID: hdr.ChannelID,
				DataType:  hdr.DataType,
				SeqNum:    hdr.SeqNum,
			})
			return hdr, idx, nil
		}
		return hdr, idx, ErrNoSync
	}

	idx.Packets = append(idx.Packets, PacketIndex{
		Offset:    0,
		ChannelID: hdr.ChannelID,
		DataType:  hdr.DataType,
		SeqNum:    hdr.SeqNum,
	})
	return hdr, idx, nil
}
