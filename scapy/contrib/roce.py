# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Haggai Eran <haggai.eran@gmail.com>
# This program is published under a GPLv2 license

# scapy.contrib.description = RoCE v2
# scapy.contrib.status = loads

"""
RoCE: RDMA over Converged Ethernet
"""

from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import ByteEnumField, ByteField, XByteField, X3BytesField, \
    ShortField, XShortField, XIntField, XLongField, BitField, XBitField, FCSField
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.compat import raw
from scapy.error import warning
from zlib import crc32
import struct
from scapy.compat import Tuple

_transports = {
    'RC': 0x00,
    'UC': 0x20,
    'RD': 0x40,
    'UD': 0x60,
    'XRC': 0xa0,
}

_ops = {
    'SEND_FIRST': 0x00,
    'SEND_MIDDLE': 0x01,
    'SEND_LAST': 0x02,
    'SEND_LAST_WITH_IMMEDIATE': 0x03,
    'SEND_ONLY': 0x04,
    'SEND_ONLY_WITH_IMMEDIATE': 0x05,
    'RDMA_WRITE_FIRST': 0x06,
    'RDMA_WRITE_MIDDLE': 0x07,
    'RDMA_WRITE_LAST': 0x08,
    'RDMA_WRITE_LAST_WITH_IMMEDIATE': 0x09,
    'RDMA_WRITE_ONLY': 0x0a,
    'RDMA_WRITE_ONLY_WITH_IMMEDIATE': 0x0b,
    'RDMA_READ_REQUEST': 0x0c,
    'RDMA_READ_RESPONSE_FIRST': 0x0d,
    'RDMA_READ_RESPONSE_MIDDLE': 0x0e,
    'RDMA_READ_RESPONSE_LAST': 0x0f,
    'RDMA_READ_RESPONSE_ONLY': 0x10,
    'ACKNOWLEDGE': 0x11,
    'ATOMIC_ACKNOWLEDGE': 0x12,
    'COMPARE_SWAP': 0x13,
    'FETCH_ADD': 0x14,
    'RESERVED': 0x15,
    'SEND_LAST_WITH_INVALIDATE': 0x16,
    'SEND_ONLY_WITH_INVALIDATE': 0x17,
}


CNP_OPCODE = 0x81


def opcode(transport, op):
    # type: (str, str) -> Tuple[int, str]
    return (_transports[transport] + _ops[op], '{}_{}'.format(transport, op))


_bth_opcodes_RC = dict([
    opcode('RC', 'SEND_FIRST'),
    opcode('RC', 'SEND_MIDDLE'),
    opcode('RC', 'SEND_LAST'),
    opcode('RC', 'SEND_LAST_WITH_IMMEDIATE'),
    opcode('RC', 'SEND_ONLY'),
    opcode('RC', 'SEND_ONLY_WITH_IMMEDIATE'),
    opcode('RC', 'RDMA_WRITE_FIRST'),
    opcode('RC', 'RDMA_WRITE_MIDDLE'),
    opcode('RC', 'RDMA_WRITE_LAST'),
    opcode('RC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    opcode('RC', 'RDMA_WRITE_ONLY'),
    opcode('RC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),
    opcode('RC', 'RDMA_READ_REQUEST'),
    opcode('RC', 'RDMA_READ_RESPONSE_FIRST'),
    opcode('RC', 'RDMA_READ_RESPONSE_MIDDLE'),
    opcode('RC', 'RDMA_READ_RESPONSE_LAST'),
    opcode('RC', 'RDMA_READ_RESPONSE_ONLY'),
    opcode('RC', 'ACKNOWLEDGE'),
    opcode('RC', 'ATOMIC_ACKNOWLEDGE'),
    opcode('RC', 'COMPARE_SWAP'),
    opcode('RC', 'FETCH_ADD'),
    opcode('RC', 'SEND_LAST_WITH_INVALIDATE'),
    opcode('RC', 'SEND_ONLY_WITH_INVALIDATE'),
])

_bth_opcodes_UC = dict([
    opcode('UC', 'SEND_FIRST'),
    opcode('UC', 'SEND_MIDDLE'),
    opcode('UC', 'SEND_LAST'),
    opcode('UC', 'SEND_LAST_WITH_IMMEDIATE'),
    opcode('UC', 'SEND_ONLY'),
    opcode('UC', 'SEND_ONLY_WITH_IMMEDIATE'),
    opcode('UC', 'RDMA_WRITE_FIRST'),
    opcode('UC', 'RDMA_WRITE_MIDDLE'),
    opcode('UC', 'RDMA_WRITE_LAST'),
    opcode('UC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    opcode('UC', 'RDMA_WRITE_ONLY'),
    opcode('UC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),
])

_bth_opcodes_RD = dict([
    opcode('RD', 'SEND_FIRST'),
    opcode('RD', 'SEND_MIDDLE'),
    opcode('RD', 'SEND_LAST'),
    opcode('RD', 'SEND_LAST_WITH_IMMEDIATE'),
    opcode('RD', 'SEND_ONLY'),
    opcode('RD', 'SEND_ONLY_WITH_IMMEDIATE'),
    opcode('RD', 'RDMA_WRITE_FIRST'),
    opcode('RD', 'RDMA_WRITE_MIDDLE'),
    opcode('RD', 'RDMA_WRITE_LAST'),
    opcode('RD', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    opcode('RD', 'RDMA_WRITE_ONLY'),
    opcode('RD', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),
    opcode('RD', 'RDMA_READ_REQUEST'),
    opcode('RD', 'RDMA_READ_RESPONSE_FIRST'),
    opcode('RD', 'RDMA_READ_RESPONSE_MIDDLE'),
    opcode('RD', 'RDMA_READ_RESPONSE_LAST'),
    opcode('RD', 'RDMA_READ_RESPONSE_ONLY'),
    opcode('RD', 'ACKNOWLEDGE'),
    opcode('RD', 'ATOMIC_ACKNOWLEDGE'),
    opcode('RD', 'COMPARE_SWAP'),
    opcode('RD', 'FETCH_ADD'),
])

_bth_opcodes_UD = dict([
    opcode('UD', 'SEND_ONLY'),
    opcode('UD', 'SEND_ONLY_WITH_IMMEDIATE'),
])

_bth_opcodes_XRC = dict([
    opcode('XRC', 'SEND_FIRST'),
    opcode('XRC', 'SEND_MIDDLE'),
    opcode('XRC', 'SEND_LAST'),
    opcode('XRC', 'SEND_LAST_WITH_IMMEDIATE'),
    opcode('XRC', 'SEND_ONLY'),
    opcode('XRC', 'SEND_ONLY_WITH_IMMEDIATE'),
    opcode('XRC', 'RDMA_WRITE_FIRST'),
    opcode('XRC', 'RDMA_WRITE_MIDDLE'),
    opcode('XRC', 'RDMA_WRITE_LAST'),
    opcode('XRC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    opcode('XRC', 'RDMA_WRITE_ONLY'),
    opcode('XRC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),
    opcode('XRC', 'RDMA_READ_REQUEST'),
    opcode('XRC', 'RDMA_READ_RESPONSE_FIRST'),
    opcode('XRC', 'RDMA_READ_RESPONSE_MIDDLE'),
    opcode('XRC', 'RDMA_READ_RESPONSE_LAST'),
    opcode('XRC', 'RDMA_READ_RESPONSE_ONLY'),
    opcode('XRC', 'ACKNOWLEDGE'),
    opcode('XRC', 'ATOMIC_ACKNOWLEDGE'),
    opcode('XRC', 'COMPARE_SWAP'),
    opcode('XRC', 'FETCH_ADD'),
    opcode('XRC', 'SEND_LAST_WITH_INVALIDATE'),
    opcode('XRC', 'SEND_ONLY_WITH_INVALIDATE'),
])

_bth_opcodes_CNP = dict([
    (CNP_OPCODE, 'CNP'),
])

class BTH(Packet):
    name = "BTH"
    fields_desc = [
        ByteEnumField("opcode", 0, _bth_opcodes_RC),
        BitField("solicited", 0, 1),
        BitField("migreq", 0, 1),
        BitField("padcount", 0, 2),
        BitField("version", 0, 4),
        XShortField("pkey", 0xffff),
        BitField("fecn", 0, 1),
        BitField("becn", 0, 1),
        BitField("resv6", 0, 6),
        BitField("dqpn", 0, 24),
        BitField("ackreq", 0, 1),
        BitField("resv7", 0, 7),
        BitField("psn", 0, 24),

        FCSField("icrc", None, fmt="!I")]

    @staticmethod
    def pack_icrc(icrc):
        # type: (int) -> bytes
        return struct.pack("!I", icrc & 0xffffffff)[::-1]

    def compute_icrc(self, p):
        # type: (bytes) -> bytes
        udp = self.underlayer
        if udp is None or not isinstance(udp, UDP):
            warning("Expecting UDP underlayer to compute checksum. Got %s.",
                    udp and udp.name)
            return self.pack_icrc(0)
        ip = udp.underlayer
        if isinstance(ip, IP):
            # pseudo-LRH / IP / UDP / BTH / payload
            pshdr = Raw(b'\xff' * 8) / ip.copy()
            pshdr.chksum = 0xffff
            pshdr.ttl = 0xff
            pshdr.tos = 0xff
            pshdr[UDP].chksum = 0xffff
            pshdr[BTH].fecn = 1
            pshdr[BTH].becn = 1
            pshdr[BTH].resv6 = 0xff
            bth = pshdr[BTH].self_build()
            payload = raw(pshdr[BTH].payload)
            # add ICRC placeholder just to get the right IP.totlen and
            # UDP.length
            icrc_placeholder = b'\xff\xff\xff\xff'
            pshdr[UDP].payload = Raw(bth + payload + icrc_placeholder)
            icrc = crc32(raw(pshdr)[:-4]) & 0xffffffff
            return self.pack_icrc(icrc)
        else:
            # TODO support IPv6
            warning("The underlayer protocol %s is not supported.",
                    ip and ip.name)
            return self.pack_icrc(0)

    # RoCE packets end with ICRC - a 32-bit CRC of the packet payload and
    # pseudo-header. Add the ICRC header if it is missing and calculate its
    # value.
    def post_build(self, p, pay):
        # type: (bytes, bytes) -> bytes
        p += pay
        if self.icrc is None:
            p = p[:-4] + self.compute_icrc(p)
        return p


class CNPPadding(Packet):
    name = "CNPPadding"
    fields_desc = [
        XLongField("reserved1", 0),
        XLongField("reserved2", 0),
    ]


def cnp(dqpn):
    # type: (int) -> BTH
    return BTH(opcode=CNP_OPCODE, becn=1, dqpn=dqpn) / CNPPadding()


class GRH(Packet):
    name = "GRH"
    fields_desc = [
        BitField("ipver", 6, 4),
        BitField("tclass", 0, 8),
        BitField("flowlabel", 6, 20),
        ShortField("paylen", 0),
        ByteField("nexthdr", 0),
        ByteField("hoplmt", 0),
        XBitField("sgid", 0, 128),
        XBitField("dgid", 0, 128),
    ]

# ACK Extended Transport Header (AETH) - 4 Bytes
class AETH(Packet):
    name = "AETH"
    fields_desc = [
        XByteField("syndrome", 0),
        XBitField("msn", 0, 24),
    ]

# Reliable Datagram Extended Transport Header (RDETH) - 4 Bytes
class RDETH(Packet):
    name = "RDETH"
    fields_desc = [
        XByteField("reserved", 0),
        XBitField("ee_context", 0, 24),
    ]

# Datagram Extended Transport Header (DETH) - 8 Bytes
class DETH(Packet):
    name = "DETH"
    fields_desc = [
        XBitField("q_key", 0, 32),
        XByteField("reserved", 0),
        XBitField("src_qp", 0, 24),
    ]

# RDMA Extended Transport Header (RETH) - 16 Bytes
class RETH(Packet):
    name = "RETH"
    fields_desc = [
        XBitField("virt_addr_63_to_32", 0, 32),
        XBitField("virt_addr_31_to_0", 0, 32),
        XBitField("r_key", 0, 32),
        XBitField("dma_len", 0, 32),
    ]

# Atomic Extended Transport Header (AtomicETH) - 28 bytes
class AtomicETH(Packet):
    name = "AtomicETH"
    fields_desc = [
        XBitField("virt_addr_63_to_32", 0, 32),
        XBitField("virt_addr_31_to_0", 0, 32),
        XBitField("r_key", 0, 32),
        XBitField("swap_or_add_data_63_to_32", 0, 32),
        XBitField("swap_or_add_data_31_to_0", 0, 32),
        XBitField("comp_data_63_to_32", 0, 32),
        XBitField("comp_data_31_to_0", 0, 32),
    ]

# Atomic Acknowledge Extended Transport Header (AtomicAETH) - 8 Bytes
class AtomicAETH(Packet):
    name = "AtomicAETH"
    fields_desc = [
        XBitField("orig_remote_data_63_to_32", 0, 32),
        XBitField("orig_remote_data_31_to_0", 0, 32),
    ]

# Immediate Extended Transport Header (ImmETH) - 4 Bytes
class ImmETH(Packet):
    name = "ImmETH"
    fields_desc = [
        XBitField("imm_data", 0, 32),
    ]

# Invalidate Extended Transport Header (IETH) - 4 Bytes
class IETH(Packet):
    name = "IETH"
    fields_desc = [
        XBitField("r_key", 0, 32),
    ]

# XRC Extended Transport Header (XRCETH)
class XRCETH(Packet):
    name = "XRCETH"
    fields_desc = [
        XByteField("reserved", 0),
        XBitField("xrc_srq", 0, 24),
    ]

bind_layers(BTH, CNPPadding, opcode=CNP_OPCODE)

bind_layers(Ether, GRH, type=0x8915) # RoCE
bind_layers(GRH, BTH)
bind_layers(BTH, AETH, opcode=opcode('RC', 'ACKNOWLEDGE')[0])
bind_layers(BTH, AETH, opcode=opcode('RD', 'ACKNOWLEDGE')[0])
bind_layers(UDP, BTH, dport=4791) # RoCEv2 packet format

"""
_transports = {
    0b000: 'RC',
    0b001: 'UC',
    0b010: 'RD',
    0b011: 'UD',
    0b100: 'CNP',
    0b101: 'XRC',
}

_ops = {
    0b00000: 'SEND_FIRST',
    0b00001: 'SEND_MIDDLE',
    0b00010: 'SEND_LAST',
    0b00011: 'SEND_LAST_WITH_IMMEDIATE',
    0b00100: 'SEND_ONLY',
    0b00101: 'SEND_ONLY_WITH_IMMEDIATE',
    0b00110: 'RDMA_WRITE_FIRST',
    0b00111: 'RDMA_WRITE_MIDDLE',
    0b01000: 'RDMA_WRITE_LAST',
    0b01001: 'RDMA_WRITE_LAST_WITH_IMMEDIATE',
    0b01010: 'RDMA_WRITE_ONLY',
    0b01011: 'RDMA_WRITE_ONLY_WITH_IMMEDIATE',
    0b01100: 'RDMA_READ_REQUEST',
    0b01101: 'RDMA_READ_RESPONSE_FIRST',
    0b01110: 'RDMA_READ_RESPONSE_MIDDLE',
    0b01111: 'RDMA_READ_RESPONSE_LAST',
    0b10000: 'RDMA_READ_RESPONSE_ONLY',
    0b10001: 'ACKNOWLEDGE',
    0b10010: 'ATOMIC_ACKNOWLEDGE',
    0b10011: 'COMPARE_SWAP',
    0b10100: 'FETCH_ADD',
    0b10101: 'RESYNC',
    0b10110: 'SEND_LAST_WITH_INVALIDATE',
    0b10111: 'SEND_ONLY_WITH_INVALIDATE',
}
"""
