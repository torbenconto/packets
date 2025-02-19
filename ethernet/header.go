package ethernet

import "net"

type Header struct {
	Target net.HardwareAddr
	Source net.HardwareAddr
	Type   Ethernet_t
}
