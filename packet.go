package packets

import (
	"time"
)

type PacketBase interface {
	GetTimestamp() time.Time
	SetTimestamp(time.Time)
	GetCode() uint16
}

type BasePacket struct {
	Timestamp  time.Time `json:"timestamp" xml:"timestamp"`
	PacketCode uint16    `json:"packet_code" xml:"packet_code"`
}

func (bp *BasePacket) GetTimestamp() time.Time {
	return bp.Timestamp
}

func (bp *BasePacket) SetTimestamp(timestamp time.Time) {
	bp.Timestamp = timestamp
}

func (bp *BasePacket) GetCode() uint16 {
	return bp.PacketCode
}

type Packet interface {
	PacketBase
	Serialize() ([]byte, error)
	Deserialize([]byte) error
}
