#!/usr/bin/env python3

# This program uses the hexdump module, provided as a separate python file.

import hexdump
import ipaddress
import select
import socket
import struct
import sys

def ripple_carry_adder(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def compute_checksum(buffer: bytes) -> int:
    """
    Compute the checksum over a sequence of bytes. Don't forget to take the
    binary inverse of the sum result, and remember that 0xFFFF is special.

    This is your job, and you need it for the bTCP project anyway, so might as
    well do it here, right?

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
    """
    buffer_list = []
    #print(buffer)
    for i in  struct.iter_unpack("!B", buffer):
        #(current,) = i
        (current,) = i
        #print(current)
        buffer_list.append(current)

    if (len(buffer_list)==0):
        return 0
    if (len(buffer_list)%2!=0):
        buffer_list.append(0)
    
    s=0
    for i in range(0, len(buffer_list), 2):
     
        
        w = (buffer_list[i]<<8) + (buffer_list[i+1])
        s = ripple_carry_adder(s, w)
        #print(s,i)
    if (~s & 0xffff == 0):
        return s & 0xffff
    
    return ~s & 0xffff

    #struct.iter_unpack()

   
    # take the buffer and divider into 16 bits take the sum e.g. sum(array) with carry, shift the number
    # in the end check if the sum 
    #


    # Signal nonsensical request (checksum of nothing?) with 0x0000
    if not buffer:
        return 0x0000

    checksum = 0x0000
    # IMPLEMENT HERE, REMOVE LINE ABOVE WHEN DONE
    return checksum


def verify_checksum(buffer: bytes):
    return compute_checksum(buffer) == 0xFFFF


def build_pseudo_header_prefix(src_ip, dst_ip, proto, length):
    """
    Build the TCP or UDP checksum pseudo header prefix bytes from required
    information. Note this does not yet include the TCP or UDP header itself.

    We have already implemented this for you, no need to change it.
    """
    return struct.pack("!4s4sBBH",
                       src_ip.packed, dst_ip.packed, 0, proto, length)


def parse_ipv4(packet):
    """
    Parse the IPv4 packet header, return the parsed header fields we want, the
    header in its entirety, and the IPv4 payload.

    This is your job.

    For getting the header length, refer to the slides & recording of lecture 4
    Remember that the IHL field is in the 4 *least* significant bits of byte 0,
    and it contains the number of 4-byte *rows* in the header.
    """

    header = b''
    payload = b''
    (ttl, protocol, hdr_checksum, src, dst) = 0, 0, 0x0000, 0, 0
    # IMPLEMENT HERE, REMOVE LINES ABOVE WHEN DONE
    
    header_length = (packet[0] & 0x0F) *4
    

    header = packet[:header_length]
    payload = packet[header_length:]

    #print(header[9])
    #ttl, protocol, hdr_checksum = struct.unpack("!B",bytes(header[8]))
    total_length, ttl, protocol, hdr_checksum, src, dst =struct.unpack_from("!2xH4xBBHII", header)
 
    # IMPLEMENT TO HERE, DO NOT CHANGE LINES BELOW
    # Coerce the addresses into "IPv4Address" objects
    src_addr = ipaddress.IPv4Address(src)
    dst_addr = ipaddress.IPv4Address(dst)
    return src_addr, dst_addr, protocol, ttl, hdr_checksum, header, payload



def parse_udp(segment):
    """
    Parse the UDP segment header, return the parsed header fields, the header
    in its entirety, and UDP payload.

    Already implemented by us, use as inspiration for your own code.
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

    This is your job
    """
    # header = b''
    # payload = b''
    #(src_port, dst_port, seq_num, ack_num, flags, window, checksum) = 0, 0, 0, 0, 0x00, 0, 0x0000
    # IMPLEMENT HERE, REMOVE LINES ABOVE WHEN DONE
    header_length = ((segment[12] & 0xF0) >> 4) *4
    header = segment[:header_length]
    payload = segment[header_length:]

    src_port, dst_port, seq_num, ack_num, flags, window, checksum =  struct.unpack_from("!HHIIHHH",header)
    #flags =  flags_str(flags)
    
    # IMPLEMENT TO HERE, DO NOT CHANGE LINES BELOW
    return src_port, dst_port, seq_num, ack_num, flags, window, checksum, header, payload


def main():
    """
    Open two raw sockets, one for UDP/IP and one for TCP/IP, and loop over
    receiving IP packets from them and parse them as UDP or IP, accordingly.

    You should only have to change the code where we have put "???", i.e. you
    have to pass the correct arguments to both socket-creating calls, and
    insert the correct protocol numbers to distinguish between TCP and UDP.

    Even though we have separate sockets for UDP and TCP, you are *required*
    to use the IP header's protocol field to decide between sending the
    segment to the parse_udp or parse_tcp functions.
    """
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) # create raw UDP/IP socket here
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) # create raw TCP/IP socket here
    
    
    while True:
        ready_socks, _, _ = select.select([udp_sock, tcp_sock], [], [], 5)
        if not ready_socks:
            print("5 seconds passed without seeing UDP or TCP traffic", file=sys.stderr)
        for s in ready_socks:
            frame, _ = s.recvfrom(65535)
            src_addr, dst_addr, protocol, ttl, hdr_checksum, ip_header, segment = parse_ipv4(frame)
            if protocol == 17: # USE UDP PROTOCOL NUMBER HERE
                dump_udp_to_console(src_addr, dst_addr, ttl,
                                    hdr_checksum, ip_header, segment)
            if protocol == 6: # USE TCP PROTOCOL NUMBER HERE
                dump_tcp_to_console(src_addr, dst_addr, ttl,
                                    hdr_checksum, ip_header, segment)


def dump_udp_to_console(src_addr, dst_addr, ttl, hdr_checksum, ip_header, segment):
    """
    Parse UDP segment and dump IP & UDP information to console.

    Already implemented by us, no need to change.
    """
    dump_ip_to_console(src_addr, dst_addr, ttl, hdr_checksum, ip_header)

    print("Full segment")
    hexdump.hexdump(segment)

    (udp_src_port, udp_dst_port, udp_length, udp_checksum,
    udp_data_length, udp_header, udp_payload) = parse_udp(segment)
    checksum_valid = verify_checksum(build_pseudo_header_prefix(src_addr, dst_addr, 17, len(segment)) + segment)

    print("""\nUDP header:
    Src port:    {:d}
    Dst port:    {:d}
    UDP length:  {:d}
    Checksum:    0x{:04X}
    UDP checksum {}

Data length: {:d}""".format(udp_src_port, udp_dst_port,
                            udp_length, udp_checksum,
                            "valid" if checksum_valid else "invalid or unverified",
                            udp_data_length))
    print("Data:")
    hexdump.hexdump(udp_payload)
    print("\n\n")


def dump_tcp_to_console(src_addr, dst_addr, ttl, hdr_checksum, ip_header, segment):
    """
    Parse TCP segment and dump IP & TCP information to console.

    Already implemented by us, no need to change; you only have to implement
    parse_tcp(segment) which gets called from here.
    """
    dump_ip_to_console(src_addr, dst_addr, ttl, hdr_checksum, ip_header)

    print("Full segment")
    hexdump.hexdump(segment)

    (src_port, dst_port, seq_num, ack_num, flags,
     window, checksum, tcp_header, payload) = parse_tcp(segment)
    checksum_valid = verify_checksum(build_pseudo_header_prefix(src_addr, dst_addr, 6, len(segment)) + segment)

    print("""\nTCP header:
    Src port:    {:d}
    Dst port:    {:d}
    Seq num:     {:d}
    Ack num:     {:d}
    Flags:       {}
    Window:      {:d}
    Checksum:    0x{:04X}
    TCP checksum {}
""".format(src_port, dst_port, seq_num, ack_num, flags_str(flags), window, checksum,
           "valid" if checksum_valid else "invalid or unverified"))
    print("Data:")
    hexdump.hexdump(payload)
    print("\n\n")


def dump_ip_to_console(src_addr, dst_addr, ttl, hdr_checksum, ip_header):
    """
    Dump IP header fields to console and state whether checksum verification
    has succeeded.

    Already implemented by us, no need to change.
    """
    print("""\nIP header:
    Src addr:    {}
    Dst addr:    {}
    TTL:         {:d}
    Checksum:    0x{:02X}
    IP checksum {}
""".format(src_addr, dst_addr, ttl, hdr_checksum,
           "valid" if verify_checksum(ip_header) else "invalid or unverified"))


def flags_str(flags):
    """
    Turn 9 IPv4 flags bits into string listing the flags that are set in them.

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


if __name__ == "__main__":
    main()
