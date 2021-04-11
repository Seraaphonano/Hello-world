#!/usr/bin/env python3

# This program uses the hexdump module, provided as a separate python file.

import hexdump
import ipaddress
import select
import socket
import struct
import sys


def compute_checksum(buffer: bytes) -> int:
    """
    Compute the checksum over a sequence of bytes. Don't forget to take the
    binary inverse of the sum result, and remember that 0xFFFF is special.

    Examples:
    >>> compute_checksum(b'\\xAB\\xCD')
    21554
    >>> compute_checksum(b'\\xAB\\xCD\\xEF')
    25905
    >>> compute_checksum(b'\\xFF\\xFF')
    65535
    >>> compute_checksum(b'\\x00\\x00')
    65535
    >>> compute_checksum(b'')
    0

    Already implemented by us, no need to change.
    """
    # Signal nonsensical request (checksum of nothing?) with 0x0000
    if not buffer:
        return 0x0000

    # Pad to an even number of bytes
    buffer += len(buffer) % 2 * b'\x00'

    # Sum the entire run as 16-bit integers in network byte order.
    acc = sum(x for (x,) in struct.iter_unpack(R'!H', buffer))

    # (Repeatedly) carry the overflow around until it fits in 16 bits.
    while acc > 0xFFFF:
        carry = acc >> 16
        acc &= 0xFFFF
        acc += carry

    # Return the binary inverse except when the result is 0xFFFF
    return acc if acc == 0xFFFF else (~acc & 0xFFFF)


def verify_checksum(buffer: bytes):
    return compute_checksum(buffer) == 0xFFFF


def build_pseudo_header_prefix(src_ip, dst_ip, proto, length):
    """
    Build the TCP or UDP checksum pseudo header prefix bytes from required
    information. Note this does not yet include the TCP or UDP header itself.

    Already implemented by us, no need to change.
    """
    return struct.pack("!4s4sBBH",
                       src_ip.packed, dst_ip.packed, 0, proto, length)


def parse_ethernet(frame):
    """
    Parse the ethernet frame header, return the parsed header fields we want,
    the header in its entirety, and the frame's payload.

    The frame does not have its footer when we get it from the socket.

    If the 802.1Q (VLAN trunk) tag is not present, the Ethertype is the two
    bytes immediately following the source MAC address. See slide 58 of lecture
    6 for details.

    Since you're not sniffing between two switches, usually you won't see an
    802.1Q tag. However, you *should* check the Ethertype for the value
    signalling the presence of an 802.1Q tag. If it's present, those two bytes
    will be 0x8100. In that case, you need to take 4 additional bytes as header
    and parse the Ethertype from the new location. Again, see slide 58 of
    lecture 6 for details of the frame header format.

    But nothing should break if you don't.

    You do NOT have to handle any kind of datagram fragmentation or reassembly!

    THIS IS WHERE YOU SHOULD IMPLEMENT THE PARSING OF ETHERNET FRAMES
    """
    header = b''
    payload = b''
    dst_mac = b'\x00\x00\x00\x00\x00\x00'
    src_mac = b'\x00\x00\x00\x00\x00\x00'
    eth_type = 0
    # IMPLEMENT HERE, REMOVE LINES ABOVE WHEN DONE
    header = frame[8:22]
    payload = frame[22:]
    dst_mac, src_mac, eth_type=  struct.unpack_from("!6s6sH", header) 
   
    # dst_mac = (dst_mac_1 << 8) | dst_mac_2
    # dst_mac = bytes(dst_mac)
    # src_mac = ((src_mac_1 << 8) | src_mac_2)
    
        # IMPLEMENT TO HERE, DO NOT CHANGE LINES BELOW
    return src_mac, dst_mac, eth_type, header, payload


def parse_ipv4(packet):
    """
    Parse the IPv4 packet header, return the parsed header fields we want, the
    header in its entirety, and the IPv4 payload.

    You do NOT have to handle any kind of datagram fragmentation or reassembly!

    Already implemented by us, no need to change.
    """
    # Determine the header length
    header_length_in_bytes = (packet[0] & 0x0F) * 4
    # Split the header from the payload
    header = packet[:header_length_in_bytes]
    payload = packet[header_length_in_bytes:]
    # Unpack the relevant fields from the header
    (ttl, protocol, hdr_checksum, src, dst) = struct.unpack_from("!8xBBHLL", header)
    # Coerce the addresses into "IPv4Address" objects
    src_addr = ipaddress.IPv4Address(src)
    dst_addr = ipaddress.IPv4Address(dst)
    return src_addr, dst_addr, protocol, ttl, hdr_checksum, header, payload


def parse_udp(segment):
    """
    Parse the UDP segment header, return the parsed header fields, the header
    in its entirety, and UDP payload.

    Already implemented for you, no need to change it.
    """
    header_length = 8
    # Slice header from segment
    header = segment[:header_length]
    # Slice payload from segment (don't need length to do so here, all
    # remaining bytes are payload)
    payload = segment[header_length:]
    # Use struct formatstring to parse the header as four unsigned shorts (H) in
    # network byte order (!).
    src_port, dst_port, udp_length, checksum = struct.unpack("!HHHH", header)
    # Compute data length by subtracting UDP header length (always 8 bytes)
    # from UDP length field.
    data_length = udp_length - 8
    return src_port, dst_port, udp_length, checksum, data_length, header, payload


def parse_tcp(segment):
    """
    Parse the TCP segment header, return the parsed header fields, the header
    in its entirety, and TCP payload.

    Already implemented for you, no need to change it.
    """
    # Determine where the data begins
    data_offset = ((segment[12] & 0xF0) >> 4) * 4
    # Split header from payload
    header = segment[:data_offset]
    payload = segment[data_offset:]
    # Unpack the header
    (src_port, dst_port, seq_num, ack_num, flags, window,
     checksum) = struct.unpack_from("!HHLLHHH", header)
    return src_port, dst_port, seq_num, ack_num, flags, window, checksum, header, payload


def main():
    """
    Open one raw socket, loop over receiving ethernet frames from it and parse
    them as IPv4 carrying UDP or TCP, accordingly.

    You should only have to change the code where we have put "???", i.e. you
    have to pass the correct arguments to the socket-creating call, and you
    have to insert the IPv4 Ethertype in an if-statement.
    """
    ether_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    #ether_sock.bind(("eth1", 0))
    while True:
        ready_socks, _, _ = select.select([ether_sock], [], [], 5)
        if not ready_socks:
            print("5 seconds passed without seeing link-layer traffic", file=sys.stderr)
        for s in ready_socks:
            frame, _ = s.recvfrom(65535)

            # Ethernet handling
            src_mac, dst_mac, eth_type, eth_header, eth_payload = parse_ethernet(frame)
            dump_ethernet_to_console(src_mac, dst_mac, eth_type, frame)
            if eth_type != 0x0800: # IPv4 Ethertype code here.
                print("Frame with ethernet type 0x{:04X} received; skipping further processing\n\n".format(
                      eth_type))
                continue

            # IPv4 handling
            # We can be certain that eth_payload is an IPv4 datagram now.
            src_addr, dst_addr, protocol, ttl, ip_hdr_checksum, ip_header, segment = parse_ipv4(eth_payload)
            checksum_valid = verify_checksum(ip_header)
            dump_ipv4_to_console(src_addr, dst_addr, ttl, protocol, ip_hdr_checksum, checksum_valid)

            # We can actually *verify* checksum validity for both TCP and UDP
            # before looking at the protocol, because the pseudo headers are
            # identical and checksum verification doesn't require us to parse
            # it out of the header.
            transport_layer_checksum_valid = verify_checksum(
                build_pseudo_header_prefix(src_addr, dst_addr, protocol, len(segment))
                + segment)

            if protocol == 17:  # UDP protocol number
                # UDP handling
                (udp_src_port, udp_dst_port, udp_length, udp_checksum,
                 udp_data_length, udp_header, udp_payload) = parse_udp(segment)
                dump_udp_to_console(udp_src_port, udp_dst_port,
                                    udp_length, udp_data_length,
                                    udp_checksum, transport_layer_checksum_valid)
                dump_payload_to_console(udp_payload)

            elif protocol == 6: # TCP protocol number
                # TCP handling
                (tcp_src_port, tcp_dst_port, tcp_seq_num, tcp_ack_num, tcp_flags,
                 tcp_window, tcp_checksum, tcp_header, tcp_payload) = parse_tcp(segment)
                dump_tcp_to_console(tcp_src_port, tcp_dst_port,
                                    tcp_seq_num, tcp_ack_num,
                                    tcp_flags, tcp_window,
                                    tcp_checksum, transport_layer_checksum_valid)
                dump_payload_to_console(tcp_payload)

            else:
                print("IPv4 datagram with protocol number {} received; skipping further processing\n\n".format(
                      protocol))


def dump_ethernet_to_console(src_mac, dst_mac, eth_type, frame):
    """
    Dump ethernet header fields to console.

    Already implemented by us, no need to change.
    """
    print("Full frame:")
    hexdump.hexdump(frame)

    print("""\nEthernet:
    Src MAC: {} ({})
    Dst MAC: {} ({})
    Type:    {:#06x}""".format(bytes_to_mac(src_mac), src_mac,
                               bytes_to_mac(dst_mac), dst_mac,
                               eth_type))


def dump_ipv4_to_console(src_addr, dst_addr, ttl, protocol, hdr_checksum, checksum_valid):
    """
    Dump IP header fields to console and state whether checksum verification
    has succeeded.

    Already implemented by us, no need to change.
    """
    print("""\nIP header:
    Src addr:    {}
    Dst addr:    {}
    TTL:         {:d}
    Protocol #:  {:d}
    Checksum:    0x{:04X}
    IP checksum {}
""".format(src_addr, dst_addr, ttl, protocol, hdr_checksum,
           "valid" if checksum_valid else "invalid, unverified, or offloaded to sending interface"))


def dump_udp_to_console(src_port, dst_port, length, data_length, checksum, checksum_valid):
    """
    Parse UDP segment and dump UDP information to console.

    Already implemented by us, no need to change.
    """

    print("""\nUDP header:
    Src port:    {:d}
    Dst port:    {:d}
    UDP length:  {:d}
    Checksum:    0x{:04X}
    UDP checksum {}

Data length: {:d}""".format(src_port, dst_port, length, checksum,
                            "valid" if checksum_valid else "invalid, unverified, or offloaded to sending interface",
                            data_length))


def dump_tcp_to_console(src_port, dst_port, seq_num, ack_num, flags, window, checksum, checksum_valid):
    """
    Parse TCP segment and dump IP & TCP information to console.

    Already implemented by us, no need to change.
    """
    print("""\nTCP header:
    Src port:    {:d}
    Dst port:    {:d}
    Seq num:     {:d}
    Ack num:     {:d}
    Flags:       {}
    Window:      {:d}
    Checksum:    0x{:04X}
    TCP checksum {}
""".format(src_port, dst_port, seq_num, ack_num, tcp_flags_str(flags), window, checksum,
           "valid" if checksum_valid else "invalid, unverified, or offloaded to sending interface"))


def dump_payload_to_console(payload):
    """
    Simple wrapper function to avoid code duplication for dumping payload data.

    Already implemented by us, no need to change.
    """
    print("Data:")
    if payload:
        hexdump.hexdump(payload)
    else:
        print("No data in segment")
    print("\n\n")


def tcp_flags_str(flags):
    """
    Turn 9 TCP flags bits into string listing the flags that are set in them.

    Already implemented by us, no need to change.
    """
    if not flags:
        return "None"
    mnemonics = list(reversed(['NS', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']))
    flag_strs = []
    for i in range(9):
        if (flags >> i) & 0x1:
            flag_strs.append(mnemonics[i])
    return ', '.join(flag_strs)


def bytes_to_mac(bytesmac):
    """
    Turn 6 MAC address bytes into a string in the usual MAC address
    representation.

    Already implemented by us, no need to change.
    """
    return ":".join("{:02x}".format(x) for x in bytesmac)


if __name__ == "__main__":
    main()
