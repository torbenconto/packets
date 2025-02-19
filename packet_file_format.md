# Specifications of .pkt file type for storing single packets.

| Magic  | Ver | Endian | Reserved | Packet Count |
|--------|-----|--------|----------|--------------|
| 4 bytes| 1 B | 1 B    | 2 B      | 4 B          |
| Timestamp (8B) | Packet Length (4B) | Packet Data (Variable) |
|---------------|-------------------|----------------------|

# Magic Number
pkt -> 0x504B5400

