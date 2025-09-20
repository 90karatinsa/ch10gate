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
	MIL1553      *MIL1553Info
	A429         *A429Info
}

type FileIndex struct {
	Packets               []PacketIndex
	HasTimePacket         bool
	TimeSeenBeforeDynamic bool
}

type MIL1553Message struct {
	IPTS            uint64
	BlockStatusWord uint16
	GapTimeWord     uint16
	LengthWord      uint16
	IPDHStatus      uint16
	IPDHLength      uint16
}

type MIL1553Info struct {
	Format       uint8
	CSDW         uint32
	TTB          uint8
	MessageCount uint32
	Messages     []MIL1553Message
	ParseError   string
}

type A429Word struct {
	IDWord          uint32
	DataWord        uint32
	Bus             uint8
	FormatError     bool
	ParityErrorFlag bool
	BusSpeedHigh    bool
	GapTime0p1Us    uint32
	Label           uint8
	SDI             uint8
	SSM             uint8
	ParityBit       uint8
	ComputedParity  bool
}

type A429Info struct {
	CSDW         uint32
	MessageCount uint32
	Words        []A429Word
	ParseError   string
}
