package pkt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	_packets "github.com/torbenconto/packets"
	"github.com/torbenconto/packets/arp"
	"io"
	"time"
)

const (
	MagicNumber      uint32 = 0x504B5400
	Version          byte   = 0x01
	LittleEndianFlag byte   = 0x00
	BigEndianFlag    byte   = 0x01
	HeaderLength     int    = 12
)

// Write writes packets to a .pkt file.
func Write(w io.Writer, packets []_packets.Packet) error {
	// Write the header (big-endian)
	header := make([]byte, HeaderLength)
	binary.BigEndian.PutUint32(header[0:4], MagicNumber)
	header[4] = Version
	header[5] = 0x01                           // Big-endian
	binary.BigEndian.PutUint16(header[6:8], 0) // Reserved
	binary.BigEndian.PutUint32(header[8:12], uint32(len(packets)))

	_, err := w.Write(header)
	if err != nil {
		return err
	}

	for _, pkt := range packets {
		if pkt == nil {
			return fmt.Errorf("nil packet encountered")
		}

		var buf bytes.Buffer

		// Write type
		binary.Write(&buf, binary.BigEndian, pkt.GetCode())

		// Write timestamp
		binary.Write(&buf, binary.BigEndian, pkt.GetTimestamp())

		packetBytes, err := pkt.Serialize()
		if err != nil {
			return err
		}

		// Write packet length
		packetLen := uint32(len(packetBytes))
		binary.Write(&buf, binary.BigEndian, packetLen)

		// Write packet data
		buf.Write(packetBytes)

		_, err = w.Write(buf.Bytes())
		if err != nil {
			return err
		}
	}

	return nil
}

func Read(r io.Reader) ([]_packets.Packet, error) {
	// Read and validate the header
	header := make([]byte, HeaderLength)
	_, err := r.Read(header)
	if err != nil {
		return nil, err
	}

	if binary.BigEndian.Uint32(header[0:4]) != MagicNumber {
		return nil, fmt.Errorf("invalid magic number")
	}

	if header[5] != 0x01 { // Expecting big-endian
		return nil, fmt.Errorf("unsupported endianness (expected big-endian)")
	}

	packetCount := binary.BigEndian.Uint32(header[8:12])

	// Read packets
	var packets []_packets.Packet
	for i := uint32(0); i < packetCount; i++ {
		var packetLen uint32
		var packetType uint16

		// Read packet type
		err = binary.Read(r, binary.BigEndian, &packetType)
		if err != nil {
			return nil, err
		}

		var packet _packets.Packet
		switch packetType {
		case _packets.ARPCODE:
			packet = arp.NewPacket()
		}

		if packet == nil {
			return nil, fmt.Errorf("nil packet encountered")
		}

		// Use the provided factory function to create a new Packet instance
		//pkt := newPacket()
		//if pkt == nil {
		//	return nil, fmt.Errorf("newPacket() returned nil")
		//}

		// Read timestamp (big-endian, 8 bytes)
		var ts int64
		err = binary.Read(r, binary.BigEndian, &ts)
		if err != nil {
			return nil, err
		}

		packet.SetTimestamp(time.Unix(ts, 0))
		// Set the timestamp in the packet
		basePkt, ok := packet.(interface{ SetTimestamp(time.Time) })
		if ok {
			basePkt.SetTimestamp(time.Unix(ts, 0))
		}

		// Read packet length (big-endian, 4 bytes)
		err = binary.Read(r, binary.BigEndian, &packetLen)
		if err != nil {
			return nil, err
		}

		// Read packet data
		packetBytes := make([]byte, packetLen)
		_, err = r.Read(packetBytes)
		if err != nil {
			return nil, err
		}

		// Deserialize packet
		err = packet.Deserialize(packetBytes)
		if err != nil {
			return nil, err
		}

		// Append to packet slice
		packets = append(packets, packet)
	}

	return packets, nil
}
