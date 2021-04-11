#!/usr/bin/env python3

# This program uses the hexdump module, provided as a separate python file.

import hexdump
import socket
import struct
import sys


def parse_udp(segment):
    """
    Parse a UDP segment (including header).

    This function will parse a UDP segment and produce the following values:
    `src_port`, `dst_port`, `udp_length`, `checksum`, `data_length`, `payload`

    These values are:
        src_port: source port parsed from the UDP header
        dst_port: destination port parsed from the UDP header
        udp_length: length field parsed from the UDP header
        checksum: checksum field parsed from the UDP header

        data_length: length of the payload, computed from udp_length
        payload: actual payload of the segment, without the header
    """

    # Stub implementation returning bogus values to produce example output
    # while implementing. Remove this line before submitting and test your
    # work without it.

    # Your code extracting & computing the correct values goes here.
    header_length = 8
    header = segment[:header_length]
    src_port, dst_port, udp_length, checksum = struct.unpack('>4H', header[:8])
    
    payload = segment[header_length:udp_length]
    data_length = len(payload)

    return src_port, dst_port, udp_length, checksum, data_length, payload


def main():
    # Create the socket here.
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.bind(('',65535))
    
    while True:
        datagram, _ = s.recvfrom(65535)
        segment = extract_segment(datagram)
        dump_udp_to_console(segment)


def dump_udp_to_console(segment):
    (udp_src_port, udp_dst_port, udp_length, udp_checksum,
     udp_data_length, udp_payload) = parse_udp(segment)

    print("Full segment")
    hexdump.hexdump(segment)

    print("""\nUDP header:
    Src port:    {}
    Dst port:    {}
    UDP length:  {}
    Checksum:    0x{:04X}

Data length: {}""".format(udp_src_port, udp_dst_port,
                          udp_length, udp_checksum,
                          udp_data_length))
    print("Data:")
    hexdump.hexdump(udp_payload)
    print("\n\n")

    # Rudimentary testcases. Can't really check anything else without giving
    # the exercise away.
    if len(segment) != udp_length:
        print("Your parser is not retrieving the UDP length field correctly",
              file=sys.stderr)
    if len(udp_payload) != udp_data_length:
        print("Your parser is miscomputing the data length or not extracting the payload correctly",
              file=sys.stderr)


def extract_segment(datagram):
    header_length_in_bytes = (datagram[0] & 0x0F) * 4
    segment = datagram[header_length_in_bytes:]
    return segment


if __name__ == "__main__":
    main()
