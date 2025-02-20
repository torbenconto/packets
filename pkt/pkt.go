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
	MagicNumber uint32 = 0x504B5400
	Version     byte   = 0x01
)

const HeaderLength int = 12

const (
	LittleEndianFlag byte = 0x00
	BigEndianFlag    byte = 0x01
)

type Header struct {
	MagicNumber uint32
	Version     byte
	Endian      byte
	Length      uint32
}

func (h Header) Bytes() []byte {
	header := make([]byte, HeaderLength)
	binary.BigEndian.PutUint32(header[0:4], h.MagicNumber)

	header[4] = h.Version
	header[5] = h.Endian

	// Reserved
	binary.BigEndian.PutUint32(header[6:8], 0)

	// Packet length
	binary.BigEndian.PutUint32(header[8:12], h.Length)

	return header
}

type Packet struct {
	Type      uint16
	Timestamp int64
	Length    uint32
	Data      []byte
}

// Write writes packets to a .pkt file.
func Write(w io.Writer, packets []_packets.Packet) error {
	// Write the header (big-endian)

	header := Header{
		MagicNumber: MagicNumber,
		Version:     Version,
		Endian:      LittleEndianFlag,
		Length:      uint32(len(packets)),
	}

	if _, err := w.Write(header.Bytes()); err != nil {
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
	var header Header

	// Read and decode the header
	if err := binary.Read(r, binary.LittleEndian, &header.MagicNumber); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &header.Endian); err != nil {
		return nil, err
	}

	// Skip reserved bytes
	var reserved uint16
	if err := binary.Read(r, binary.BigEndian, &reserved); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &header.Length); err != nil {
		return nil, err
	}

	// Validate header
	if header.MagicNumber != MagicNumber {
		return nil, fmt.Errorf("invalid magic number")
	}
	if header.Endian != BigEndianFlag {
		return nil, fmt.Errorf("unsupported endianness (expected big-endian)")
	}

	packetCount := header.Length
	packets := make([]_packets.Packet, 0, packetCount)

	for i := uint32(0); i < packetCount; i++ {
		var packet _packets.Packet
		var pkt_packet Packet

		// Read packet type
		if err := binary.Read(r, binary.BigEndian, &pkt_packet.Type); err != nil {
			return nil, err
		}

		switch pkt_packet.Type {
		case _packets.ARPCODE:
			packet = arp.NewPacket()
		default:
			return nil, fmt.Errorf("unknown packet type: %d", pkt_packet.Type)
		}

		// Read timestamp
		if err := binary.Read(r, binary.BigEndian, &pkt_packet.Timestamp); err != nil {
			return nil, err
		}

		// Read packet length
		if err := binary.Read(r, binary.BigEndian, &pkt_packet.Length); err != nil {
			return nil, err
		}

		// Read packet data
		if _, err := io.ReadFull(r, pkt_packet.Data); err != nil {
			return nil, err
		}

		packet.SetTimestamp(time.Unix(pkt_packet.Timestamp, 0))

		// Deserialize packet
		if err := packet.Deserialize(pkt_packet.Data); err != nil {
			return nil, err
		}

		packets = append(packets, packet)
	}

	return packets, nil
}
