package pkt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	_packets "github.com/torbenconto/packets"
	"github.com/torbenconto/packets/arp"
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
	header[5] = BigEndianFlag                  // Big-endian
	binary.BigEndian.PutUint16(header[6:8], 0) // Reserved
	binary.BigEndian.PutUint32(header[8:12], uint32(len(packets)))

	if _, err := w.Write(header); err != nil {
		return err
	}

	for _, pkt := range packets {
		if pkt == nil {
			return fmt.Errorf("nil packet encountered")
		}

		var buf bytes.Buffer

		fmt.Printf("Writing packet type: %d\n", pkt.GetCode())

		// Write type
		if err := binary.Write(&buf, binary.BigEndian, pkt.GetCode()); err != nil {
			return err
		}

		// Write timestamp
		if err := binary.Write(&buf, binary.BigEndian, pkt.GetTimestamp().Unix()); err != nil {
			return err
		}

		packetBytes, err := pkt.Serialize()
		if err != nil {
			return err
		}

		// Write packet length
		packetLen := uint32(len(packetBytes))
		if err := binary.Write(&buf, binary.BigEndian, packetLen); err != nil {
			return err
		}

		// Write packet data
		buf.Write(packetBytes)

		if _, err := w.Write(buf.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

// Read reads packets from a .pkt file.
func Read(r io.Reader) ([]_packets.Packet, error) {
	// Read and validate the header
	header := make([]byte, HeaderLength)
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	if binary.BigEndian.Uint32(header[0:4]) != MagicNumber {
		return nil, fmt.Errorf("invalid magic number")
	}

	if header[5] != BigEndianFlag { // Expecting big-endian
		return nil, fmt.Errorf("unsupported endianness (expected big-endian)")
	}

	packetCount := binary.BigEndian.Uint32(header[8:12])
	var packets []_packets.Packet

	for i := uint32(0); i < packetCount; i++ {
		var packetLen uint32
		var packetType uint16

		// Read packet type
		if err := binary.Read(r, binary.BigEndian, &packetType); err != nil {
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

		// Read timestamp
		var ts int64
		if err := binary.Read(r, binary.BigEndian, &ts); err != nil {
			return nil, err
		}

		packet.SetTimestamp(time.Unix(ts, 0))

		// Read packet length
		if err := binary.Read(r, binary.BigEndian, &packetLen); err != nil {
			return nil, err
		}

		// Read packet data
		packetBytes := make([]byte, packetLen)
		if _, err := r.Read(packetBytes); err != nil {
			return nil, err
		}

		// Deserialize packet
		if err := packet.Deserialize(packetBytes); err != nil {
			return nil, err
		}

		// Append to packet slice
		packets = append(packets, packet)
	}

	return packets, nil
}
