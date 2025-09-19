package ch10

type PacketHeader struct {
	Sync         uint16
	ChannelID    uint16
	PacketLength uint32
	DataLength   uint32
	DataType     uint16
	SeqNum       uint8
	Flags        uint8
}

type SecondaryHeader struct {
	HasSecHdr   bool
	TimeFormat  uint8
	Seconds     uint32
	Subsecond   uint32
	TimeStampUs int64
}

type TimestampSource string

const (
	TimestampSourceUnknown         TimestampSource = ""
	TimestampSourceSecondaryHeader TimestampSource = "secondary_header"
	TimestampSourceTimePacket      TimestampSource = "time_packet"
	TimestampSourceIPTS            TimestampSource = "ipts"
)

type PacketIndex struct {
	Offset       int64
	ChannelID    uint16
	DataType     uint16
	SeqNum       uint8
	Flags        uint8
	PacketLength uint32
	DataLength   uint32
	HasSecHdr    bool
	SecHdrValid  bool
	SecHdrBytes  bool
	TimeFormat   uint8
	HasTrailer   bool
	TimeStampUs  int64
	Source       TimestampSource
	IsTimePacket bool
}

type FileIndex struct {
	Packets               []PacketIndex
	HasTimePacket         bool
	TimeSeenBeforeDynamic bool
}
