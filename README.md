# packets
This project is a golang library that provides a collection of common network packets in an easily modifiable manner. It contains first class support for serialization and deserialization of structs into valid network packets of the same type.

## The .pkt file format
Bundled along with this project is a file format for storing network packets (similar to a .pcap or .pcapng file).
You can write and read packets from these files using the built in `pkt` package using it's `Read()` & `Write()` methods.
You can find the file format specifications [here](packet_file_format.md).