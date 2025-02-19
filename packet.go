package packets

import "time"

type PacketBase interface {
	GetTimestamp() time.Time
}

type BasePacket struct {
	Timestamp time.Time `json:"timestamp" xml:"timestamp"`
}

func (bp BasePacket) GetTimestamp() time.Time {
	return bp.Timestamp
}

type Packet interface {
	PacketBase
	Serialize() ([]byte, error)
	Deserialize([]byte) error
}
