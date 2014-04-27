# Copyright (c) 2005, Neville-Neil Consulting
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# Neither the name of Neville-Neil Consulting nor the names of its 
# contributors may be used to endorse or promote products derived from 
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# File: $Id: icmpv6.py,v 1.8 2006/08/30 02:10:40 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class which describes an ICMPv6 packet

import pcs
import pcs.packets.pseudoipv6
import pcs.packets.ipv4

import struct

# icmp6 type
ND_ROUTER_SOLICIT = 133
ND_ROUTER_ADVERT = 134  
ND_NEIGHBOR_SOLICIT = 135       
ND_NEIGHBOR_ADVERT = 136        
ND_REDIRECT = 137

MLD6_LISTENER_QUERY = 130
MLD6_LISTENER_REPORT = 131
MLD6_LISTENER_DONE = 132
MLD6_MTRACE_RESP = 200
MLD6_MTRACE = 201

ICMP6_ROUTER_RENUMBERING = 138
ICMP6_NI_QUERY = 139
ICMP6_NI_REPLY = 140
ICMP6_WRUREQUEST = 139  
ICMP6_WRUREPLY = 140    
ICMP6_DST_UNREACH = 1
ICMP6_PACKET_TOO_BIG = 2
ICMP6_TIME_EXCEEDED = 3
ICMP6_PARAM_PROB = 4
ICMP6_ECHO_REQUEST = 128        
ICMP6_ECHO_REPLY = 129

# router renumbering flags
ICMP6_RR_FLAGS_TEST     = 0x80
ICMP6_RR_FLAGS_REQRESULT = 0x40
ICMP6_RR_FLAGS_FORCEAPPLY = 0x20
ICMP6_RR_FLAGS_SPECSITE = 0x10
ICMP6_RR_FLAGS_PREVDONE = 0x08

class icmpv6(pcs.Packet):

    _layout = pcs.Layout()

    def __init__(self, type = 0, bytes = None, **kv):
        """icmpv6 header RFC2463 and RFC2461"""
        ty = pcs.Field("type", 8, default = type)
        code = pcs.Field("code", 8)
        cksum = pcs.Field("checksum", 16)
        if type == ICMP6_ECHO_REQUEST or type == ICMP6_ECHO_REPLY:
            id = pcs.Field("id", 16)
            seq = pcs.Field("sequence", 16)
            pcs.Packet.__init__(self, [ty, code, cksum, id, seq], bytes, **kv)
        elif type == ICMP6_TIME_EXCEEDED or type == ICMP6_DST_UNREACH or type == ND_ROUTER_SOLICIT:
            unused = pcs.Field("unused", 32)
            pcs.Packet.__init__(self, [ty, code, cksum, unused], bytes, **kv)
        elif type == ICMP6_PARAM_PROB:
            pointer = pcs.Field("pointer", 32)
            pcs.Packet.__init__(self, [ty, code, cksum, pointer], bytes, **kv)
        elif type == ICMP6_PACKET_TOO_BIG:
            mtu = pcs.Field("mtu", 32)
            pcs.Packet.__init__(self, [ty, code, cksum, mtu], bytes, **kv)
        elif type == ICMP6_NI_QUERY or type == ICMP6_NI_REPLY:
            qtype = pcs.Field("qtype", 16)
            flags = pcs.Field("flags", 16)
            nonce = pcs.Field("nonce", 64)
            pcs.Packet.__init__(self, [ty, code, cksum, qtype, flags, nonce], bytes, **kv)
        elif type == ND_ROUTER_ADVERT:
            chp = pcs.Field("current_hop_limit", 8)
            m = pcs.Field("m", 1)
            o = pcs.Field("o", 1)
            unused = pcs.Field("unused", 6)
            rlf = pcs.Field("router_lifetime", 16)
            rct = pcs.Field("reachable_time", 32)
            rtt = pcs.Field("retrans_timer", 32)
            pcs.Packet.__init__(self, [ty, code, cksum, chp, m, o, unused, rlf, rct, rtt], bytes, **kv)
        elif type == ND_NEIGHBOR_SOLICIT:
            reserved = pcs.Field("reserved", 32)
            target = pcs.StringField("target", 16 * 8)
            pcs.Packet.__init__(self, [ty, code, cksum, reserved, target], bytes, **kv)
        elif type == ND_NEIGHBOR_ADVERT:
            r = pcs.Field("router", 1)
            s = pcs.Field("solicited", 1)
            o = pcs.Field("override", 1)
            reserved = pcs.Field("reserved", 29)
            target = pcs.StringField("target", 16 * 8)
            pcs.Packet.__init__(self, [ty, code, cksum, r, s, o, reserved, target], bytes, **kv)
        elif type == ND_REDIRECT:
            reserved = pcs.Field("reserved", 32)
            target = pcs.StringField("target", 16 * 8)
            dest = pcs.StringField("destination", 16 * 8)
            pcs.Packet.__init__(self, [ty, code, cksum, reserved, target, dest], bytes, **kv)
        elif type == MLD6_LISTENER_QUERY or type == MLD6_LISTENER_REPORT or type == MLD6_LISTENER_DONE:
            md = pcs.Field("maxdelay", 16)
            reserved = pcs.Field("reserved", 16)
            mcast = pcs.StringField("mcastaddr", 16 * 8)
            pcs.Packet.__init__(self, [ty, code, cksum, md, reserved, mcast], bytes, **kv)            
        else:
            pcs.Packet.__init__(self, [ty, code, cksum], bytes, **kv)

    def cksum(self, ip, data = "", nx = 0):
        """Calculate the checksum for this ICMPv6 header, outside
           of a chain."""
        p6 = pseudoipv6.pseudoipv6()
        p6.src = ip.src
        p6.dst = ip.dst
        p6.length = len(self.getbytes()) + len (data)
        if nx:
            p6.next_header = nx
        else:
            p6.next_header = ip.next_header
        pkt = p6.getbytes() + self.getbytes() + data
        return ipv4.ipv4_cksum(pkt)

    def calc_checksum(self):
        """Calculate and store the checksum for this ICMPv6 header.
           ICMPv6 checksums are computed over data payloads and
           next-headers. The packet must be part of a chain."""
        self.checksum = 0
        if self._head is not None:
            payload = self._head.collate_following(self)
            ip6 = self._head.find_preceding(self, pcs.packets.ipv6)
            assert ip6 is not None, "No preceding IPv6 header."
            pip6 = pseudoipv6.pseudoipv6()
            pip6.src = ip6.src
            pip6.dst = ip6.dst
            pip6.next_header = ip6.next_header
            pip6.length = len(self.getbytes()) + len(payload)
            tmpbytes = pip6.getbytes() + self.getbytes() + payload
        else:
            tmpbytes = self.getbytes()
        self.checksum = ipv4.ipv4_cksum(tmpbytes)

class icmpv6option(pcs.Packet):

    _layout = pcs.Layout()
    
    def __init__(self, type = 0, bytes = None, **kv):
        """add icmp6 option header RFC2461"""
        ty = pcs.Field("type", 8, default = type)
        length = pcs.Field("length", 8)
        # Source Link-Layer Address.
        if type == 1:
            source = pcs.StringField("source", 48)
            pcs.Packet.__init__(self, [ty, length, source], bytes, **kv)
        # Target Link-Layer Address
        elif type == 2:
            target = pcs.StringField("target", 48)
            pcs.Packet.__init__(self, [ty, length, target], bytes, **kv)
        # Prefix Information.
        elif type == 3:
            plength = pcs.Field("prefix_length", 8)
            l = pcs.Field("L", 1)
            a = pcs.Field("A", 1)
            reserved1 = pcs.Field("reserved1", 6)
            vlf = pcs.Field("valid_lifetime", 32)
            plf = pcs.Field("preferred_lifetime", 32)
            reserved2 = pcs.Field("reserved2", 32)
            prefix = pcs.StringField("prefix", 16 * 8)
            pcs.Packet.__init__(self, [ty, length, plength, l, a, reserved1, vlf, plf, reserved2, prefix], bytes, **kv)
        # Redirected Header.
        elif type == 4:
            reserved = pcs.StringField("reserved", 48)
            pcs.Packet.__init__(self, [ty, length, reserved], bytes, **kv)
        # MTU 
        elif type == 5:
            reserved = pcs.Field("reserved", 16)
            mtu = pcs.Field("mtu", 32)
            pcs.Packet.__init__(self, [ty, length, reserved, mtu], bytes, **kv)
        else:
            pcs.Packet.__init__(self, [ty, length], bytes, **kv)
