package ethernet

type Opcode_t uint16

const (
	SendOpcode Opcode_t = 1
	RecvOpcode Opcode_t = 2
)
