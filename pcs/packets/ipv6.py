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
# File: $Id: ipv6.py,v 1.6 2006/08/01 13:35:58 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class that implements an IPv6 packet.
#

import pcs
import os
from socket import AF_INET6, IPPROTO_UDP, IPPROTO_TCP, IPPROTO_AH, IPPROTO_ESP, IPPROTO_ICMP, inet_ntop

import udp, tcp, icmpv4

# extension header next header field.
IPV6_HOPOPTS = 0
IPV6_RTHDR = 43
IPV6_FRAG = 44
IPV6_ESP = 50
IPV6_AH = 51
IPV6_NONE = 59
IPV6_DSTOPTS = 60

class ipv6(pcs.Packet):
    """A class that contains the IPv6 header.  All other data is
    chained on the end."""

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """IPv6 Packet from RFC 2460"""
        version = pcs.Field("version", 4, default = 6)
        traffic = pcs.Field("traffic_class", 8)
        flow = pcs.Field("flow", 20)
        length = pcs.Field("length", 16)
        next = pcs.Field("next_header", 8)
        hop = pcs.Field("hop", 8)
        src = pcs.StringField("src", 16 * 8)
        dst = pcs.StringField("dst", 16 * 8)
        pcs.Packet.__init__(self,
                            [version, traffic, flow, length, next, hop,
                             src, dst], bytes)
        self.description = "IPv6"

        if (bytes != None):
            ## 40 bytes is the standard size of an IPv6 header
            offset = 40
            self.data = self.next(bytes[offset:len(bytes)])
        else:
            self.data = None
        
    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields.  Addresses are printed if and only if they are set and not 0."""
        retval = ""
        for field in self.layout:
            if (field.name == "src" or field.name == "dst"):
                value = inet_ntop(AF_INET6, self.__dict__[field.name])
                retval += "%s %s\n" % (field.name, value)
            else:
                retval += "%s %d\n" % (field.name, self.__dict__[field.name])
        return retval

    def getipv6(self, iface):
        """return one ipv6 address associated to iface"""
        v6 = ""
        # XXX: improve this using getifaddrs() wrapper.
        for line in os.popen("/sbin/ifconfig %s" % iface):
            if line.find('inet6') > -1:
                if line.split()[1][:4] == "fe80" or line.split()[1][:4] == "fec0":
                    continue
                v6 = line.split()[1]
                break
        return v6

    def next(self, bytes):
        "Decode extension headers and the rest of the packets."
        if self.next_header == IPPROTO_UDP:
            return udp.udp(bytes)
        elif self.next_header == IPPROTO_TCP:
            return tcp.tcp(bytes)
        elif self.next_header == IPPROTO_AH:
            return ipsec.ah(bytes)
        elif self.next_header == IPPROTO_ESP:
            return ipsec.esp(bytes)
        elif self.next_header == IPPROTO_ICMP:
            return icmpv4.icmpv4(bytes)
        # Fall through
        return None
        
class rthdr(pcs.Packet):
    """A class that contains the IPv6 routing extension-headers."""

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """IPv6 routing extension header from RFC 2460"""
        next = pcs.Field("next_header", 8)
        len = pcs.Field("length", 8)
        type = pcs.Field("type", 8)
        segments_left = pcs.Field("segments_left", 8)
        pcs.Packet.__init__(self,
                            [next, len, type, segments_left], bytes)

    def rthdr0(self, seg = 1, bytes = None):
        """IPv6 routing extension header type 0"""
        reserved = pcs.Field("reserved", 32, default = 0)
        header = [ reserved ]
        for i in range(seg):
            header.append(pcs.StringField("address" + str(i), 128))
        pcs.Packet.__add__(self, header)

class hopopts(pcs.Packet):
    """A class that contains the IPv6 hop-by-hop options 
    extension-headers."""

    layout = pcs.Layout()

    op = 0
    
    def __init__(self, bytes = None):
        """IPv6 hopbyhop options extension header from RFC 2460"""
        global op
        op = 0
        next = pcs.Field("next_header", 8)
        len = pcs.Field("length", 8)
        type = pcs.Field("type", 8)
        pcs.Packet.__init__(self,
                            [next, len, type], bytes)
    
    def option(self, len = 0):
        """add option header to the hop-by-hop extension header"""
        # XXX: pad0 option has not this header.
        global op
        op += 1
        otype = pcs.Field("otype" + str(op), 8)
        olen = pcs.Field("olength" + str(op), 8, default = len / 8)
        if len != 0:
            odata = pcs.Field("odata" + str(op), len)
            pcs.Packet.__add__(self, [otype, olen, odata])
        else:
            pcs.Packet.__add__(self, [otype, olen])

class dstopts(pcs.Packet):
    """A class that contains the IPv6 destination options 
    extension-headers."""

    layout = pcs.Layout()

    op = 0
    
    def __init__(self, bytes = None):
        """IPv6 destination options extension header from RFC 2460"""
        global op
        op = 0
        next = pcs.Field("next_header", 8)
        len = pcs.Field("length", 8)
        type = pcs.Field("type", 8)
        pcs.Packet.__init__(self,
                            [next, len, type], bytes)

    def option(self, len = 0):
        """add option header to the destination extension header"""
        # XXX: pad0 option has not this header.
        global op
        op += 1
        otype = pcs.Field("otype" + str(op), 8)
        olen = pcs.Field("olength" + str(op), 8, default = len / 8)
        if len != 0:
            odata = pcs.Field("odata" + str(op), len)
            pcs.Packet.__add__(self, [otype, olen, odata])
        else:
            pcs.Packet.__add__(self, [otype, olen])

class frag(pcs.Packet):
    """A class that contains the IPv6 fragmentation extension-headers."""

    layout = pcs.Layout()
    
    def __init__(self, bytes = None):
        """IPv6 fragmentation extension header from RFC 2460"""
        next = pcs.Field("next_header", 8)
        reserved = pcs.Field("reserved", 8)
        offset = pcs.Field("offset", 13)
        res = pcs.Field("res", 2)
        m = pcs.Field("m", 1)
        identification = pcs.Field("identification", 32)
        pcs.Packet.__init__(self,
                            [next, reserved, offset, res, m, identification], bytes)
