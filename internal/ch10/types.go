package ch10

type PacketHeader struct {
	Sync          uint16
	ChannelID     uint16
	PacketLength  uint32
	DataLength    uint32
	DataType      uint16
	SeqNum        uint8
	Flags         uint8
}

type PacketIndex struct {
	Offset      int64
	ChannelID   uint16
	DataType    uint16
	SeqNum      uint8
	HasSecHdr   bool
	HasTrailer  bool
	TimeStampUs int64
}

type FileIndex struct {
	Packets []PacketIndex
}
