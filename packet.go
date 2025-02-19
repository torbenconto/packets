package packets

type Packet interface {
	Serialize() ([]byte, error)
	Deserialize([]byte) error
}
