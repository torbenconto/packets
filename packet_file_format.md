# Specifications of .pkt file type for storing single packets.

| Field             | Size     |
|------------------|----------|
| Magic           | 4 bytes  |
| Ver            | 1 byte   |
| Endian         | 1 byte   |
| Reserved       | 2 bytes  |
| Packet Count   | 4 bytes  |
| Packet Type    | 2 bytes  |
| Timestamp      | 8 bytes  |
| Packet Length  | 4 bytes  |
| Packet Data    | Variable |


# Magic Number
pkt -> 0x504B5400

# Packet Type Numbers
- ARP - 0x00000001

