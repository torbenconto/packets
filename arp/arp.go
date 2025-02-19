package arp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/torbenconto/packets/ethernet"
	"net"
)

type Packet struct {
	Header ethernet.Header `json:"header" xml:"header"`

	HardwareType ethernet.Hardware_t `json:"hardware_type" xml:"hardware_type"`
	ProtocolType ethernet.Protocol_t `json:"protocol_type" xml:"protocol_type"`

	HardwareSize uint8 `json:"hardware_size" xml:"hardware_size"`
	ProtocolSize uint8 `json:"protocol_size" xml:"protocol_size"`

	Opcode ethernet.Opcode_t `json:"opcode" xml:"opcode"`

	TargetMAC net.HardwareAddr `json:"target_mac" xml:"target_mac"`
	TargetIP  net.IP           `json:"target_ip" xml:"target_ip"`

	SourceMAC net.HardwareAddr `json:"source_mac" xml:"source_mac"`
	SourceIP  net.IP           `json:"source_ip" xml:"source_ip"`
}

func (p *Packet) Serialize() ([]byte, error) {
	// Validate MAC addresses length
	if len(p.SourceMAC) != 6 {
		return nil, fmt.Errorf("invalid source MAC address length: %d", len(p.SourceMAC))
	}
	if len(p.TargetMAC) != 6 {
		return nil, fmt.Errorf("invalid target MAC address length: %d", len(p.TargetMAC))
	}

	buf := new(bytes.Buffer)

	// EthernetHardware header
	buf.Write(p.Header.Target)
	buf.Write(p.Header.Source)
	if err := binary.Write(buf, binary.BigEndian, p.Header.Type); err != nil {
		return nil, err
	}

	// ARP header
	if err := binary.Write(buf, binary.BigEndian, p.HardwareType); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, p.ProtocolType); err != nil {
		return nil, err
	}
	buf.WriteByte(p.HardwareSize)
	buf.WriteByte(p.ProtocolSize)
	if err := binary.Write(buf, binary.BigEndian, p.Opcode); err != nil {
		return nil, err
	}
	buf.Write(p.SourceMAC)
	buf.Write(p.SourceIP.To4())
	buf.Write(p.TargetMAC)
	buf.Write(p.TargetIP.To4())

	return buf.Bytes(), nil
}

func (p *Packet) Deserialize(data []byte) error {
	// Check if there's enough data for a minimum ARP packet
	if len(data) < 42 {
		return fmt.Errorf("not enough data")
	}

	offset := 0

	// Ethernet header
	p.Header.Target = net.HardwareAddr(data[offset : offset+6])
	offset += 6
	p.Header.Source = net.HardwareAddr(data[offset : offset+6])
	offset += 6
	p.Header.Type = ethernet.Ethernet_t(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// ARP header
	p.HardwareType = ethernet.Hardware_t(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	p.ProtocolType = ethernet.Protocol_t(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	p.HardwareSize = data[offset]
	offset += 1
	p.ProtocolSize = data[offset]
	offset += 1
	p.Opcode = ethernet.Opcode_t(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Source MAC and IP
	p.SourceMAC = net.HardwareAddr(data[offset : offset+6])
	offset += 6
	p.SourceIP = net.IP(data[offset : offset+4])
	offset += 4

	// Target MAC and IP
	p.TargetMAC = net.HardwareAddr(data[offset : offset+6])
	offset += 6
	p.TargetIP = net.IP(data[offset : offset+4])

	return nil
}
