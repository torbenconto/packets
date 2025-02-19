package arp

import (
	"bytes"
	"github.com/torbenconto/packets/ethernet"
	"net"
	"testing"
)

func TestPacket_Serialize(t *testing.T) {
	tests := []struct {
		name    string
		packet  *Packet
		wantErr bool
		want    []byte
	}{
		{
			name: "valid ARP packet",
			packet: &Packet{
				Header: ethernet.Header{
					Source: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					Target: net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
					Type:   ethernet.EthernetARP,
				},
				HardwareType: ethernet.EthernetHardware,
				ProtocolType: ethernet.IPv4,
				HardwareSize: 6,
				ProtocolSize: 4,
				Opcode:       ethernet.SendOpcode,
				SourceMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				SourceIP:     net.IP{192, 168, 1, 1},
				TargetMAC:    net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
				TargetIP:     net.IP{192, 168, 1, 2},
			},
			wantErr: false,
			want: []byte{
				0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Target MAC
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC
				0x08, 0x06, // EthernetHardware Type: ARP
				0x00, 0x01, // Hardware Type: EthernetHardware
				0x08, 0x00, // Protocol Type: IPv4
				0x06,       // Hardware Size: 6
				0x04,       // Protocol Size: 4
				0x00, 0x01, // Opcode: Request
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC
				0xc0, 0xa8, 0x01, 0x01, // Source IP: 192.168.1.1
				0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Target MAC
				0xc0, 0xa8, 0x01, 0x02, // Target IP: 192.168.1.2
			},
		},
		{
			name: "invalid ARP packet (short MAC address)",
			packet: &Packet{
				Header: ethernet.Header{
					Source: net.HardwareAddr{0x00, 0x11, 0x22},
					Target: net.HardwareAddr{0x66, 0x77, 0x88, 0x99},
					Type:   ethernet.EthernetARP,
				},
				HardwareType: ethernet.EthernetHardware,
				ProtocolType: ethernet.IPv4,
				HardwareSize: 6,
				ProtocolSize: 4,
				Opcode:       ethernet.SendOpcode,
				SourceMAC:    net.HardwareAddr{0x00, 0x11, 0x22},
				SourceIP:     net.IP{192, 168, 1, 1},
				TargetMAC:    net.HardwareAddr{0x66, 0x77, 0x88, 0x99},
				TargetIP:     net.IP{192, 168, 1, 2},
			},
			wantErr: true,
			want:    nil, // Expecting an error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.packet.Serialize()
			if (err != nil) != tt.wantErr {
				t.Errorf("Packet.Serialize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("Packet.Serialize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPacket_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		want    *Packet
	}{
		{
			name: "valid ARP packet",
			data: []byte{
				0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Target MAC
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC
				0x08, 0x06, // EthernetHardware Type: ARP
				0x00, 0x01, // Hardware Type: EthernetHardware
				0x08, 0x00, // Protocol Type: IPv4
				0x06,       // Hardware Size: 6
				0x04,       // Protocol Size: 4
				0x00, 0x01, // Opcode: Request
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC
				0xc0, 0xa8, 0x01, 0x01, // Source IP: 192.168.1.1
				0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Target MAC
				0xc0, 0xa8, 0x01, 0x02, // Target IP: 192.168.1.2
			},
			wantErr: false,
			want: &Packet{
				Header: ethernet.Header{
					Source: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					Target: net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
					Type:   ethernet.EthernetARP,
				},
				HardwareType: ethernet.EthernetHardware,
				ProtocolType: ethernet.IPv4,
				HardwareSize: 6,
				ProtocolSize: 4,
				Opcode:       ethernet.SendOpcode,
				SourceMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				SourceIP:     net.IP{192, 168, 1, 1},
				TargetMAC:    net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
				TargetIP:     net.IP{192, 168, 1, 2},
			},
		},
		{
			name: "invalid ARP packet (short MAC address)",
			data: []byte{
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Target MAC
				0x00, 0x11, 0x22, 0x33, 0x44, // Incomplete Source MAC
				0x08, 0x06, // EthernetHardware Type: ARP
				0x00, 0x01, // Hardware Type: EthernetHardware
				0x08, 0x00, // Protocol Type: IPv4
				0x06,       // Hardware Size: 6
				0x04,       // Protocol Size: 4
				0x00, 0x01, // Opcode: Request
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC
				0xc0, 0xa8, 0x01, 0x01, // Source IP: 192.168.1.1
				0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Target MAC
				0xc0, 0xa8, 0x01, 0x02, // Target IP: 192.168.1.2
			},
			wantErr: true,
			want:    nil, // Expecting an error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Packet
			err := p.Deserialize(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Packet.Deserialize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !comparePackets(&p, tt.want) {
				t.Errorf("Packet.Deserialize() = %v, want %v", p, *tt.want)
			}
		})
	}
}

// Helper function to compare two Packet structs
func comparePackets(p1, p2 *Packet) bool {
	return p1.Header.Type == p2.Header.Type &&
		p1.Header.Target.String() == p2.Header.Target.String() &&
		p1.Header.Source.String() == p2.Header.Source.String() &&
		p1.HardwareType == p2.HardwareType &&
		p1.ProtocolType == p2.ProtocolType &&
		p1.HardwareSize == p2.HardwareSize &&
		p1.ProtocolSize == p2.ProtocolSize &&
		p1.Opcode == p2.Opcode &&
		p1.SourceMAC.String() == p2.SourceMAC.String() &&
		p1.SourceIP.String() == p2.SourceIP.String() &&
		p1.TargetMAC.String() == p2.TargetMAC.String() &&
		p1.TargetIP.String() == p2.TargetIP.String()
}
