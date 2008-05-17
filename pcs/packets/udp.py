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
# File: $Id: udp.py,v 1.4 2006/09/01 05:24:04 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class which implements UDP v4 packets

import pcs
import udp_map

import inspect
import socket
import time


class udp(pcs.Packet):
    """UDP"""

    _layout = pcs.Layout()
    _map = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize a UDP packet"""
        sport = pcs.Field("sport", 16)
        dport = pcs.Field("dport", 16)
        length = pcs.Field("length", 16)
        checksum = pcs.Field("checksum", 16)
        pcs.Packet.__init__(self, [sport, dport, length, checksum],
                            bytes, **kv)
        self.description = inspect.getdoc(self)
        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (bytes != None):
            self.data = self.next(bytes[8:len(bytes)], timestamp)
        else:
            self.data = None

    # XXX UDP MUST have its own next() and rdiscriminate() functions,
    # so that it can discriminate on either sport or dport.

    def next(self, bytes, timestamp):
        """Decode higher level services."""
        if (self.dport in udp_map.map):
            return udp_map.map[self.dport](bytes, timestamp = timestamp)
        if (self.sport in udp_map.map):
            return udp_map.map[self.sport](bytes, timestamp = timestamp)

        return None

    def rdiscriminate(self, packet, discfieldname = None, map = udp_map.map):
        """Reverse-map an encapsulated packet back to a discriminator
           field value. Like next() only the first match is used."""
        #print "reverse discriminating %s" % type(packet)
        result = pcs.Packet.rdiscriminate(self, packet, "dport", map)
        if result == False:
            result = pcs.Packet.rdiscriminate(self, packet, "sport", map)
        return result

    def calc_checksum(self):
        """Calculate and store the checksum for this UDP datagram.
           The packet must be part of a chain.
           We attempt to infer whether IPv4 or IPv6 encapsulation
           is in use for the payload. The closest header wins the match.
           The network layer header must immediately precede the UDP
           datagram (for now)."""
        from pcs.packets.ipv4 import ipv4
        ip = None
        ip6 = None
        if self._head is not None:
            (ip, iip) = self._head.find_preceding(self, pcs.packets.ipv4.ipv4)
            (ip6, iip6) = self._head.find_preceding(self, pcs.packets.ipv6.ipv6)
        # Either this UDP header is not in a chain, or no IPv4/IPv6
        # outer header was found.
        if ip is None and ip6 is None:
            self.checksum = 0
            self.checksum = ipv4.ipv4_cksum(self.getbytes())
            return
        # If we found both IPv4 and IPv6 headers then we must break the tie.
        # The closest outer header wins and is used for checksum calculation.
        if ip is not None and ip6 is not None:
            assert iip != iip6, "ipv4 and ipv6 cannot be at same index"
            if iip6 > iip:
                ip = None	# ip6 is nearest outer header, ignore ip
            else:
                ip6 = None	# ip is nearest outer header, ignore ip6
        if ip is not None:
            self.calc_checksum_v4(ip)
        else:
            self.calc_checksum_v6(ip6)

    def calc_checksum_v4(self, ip):
        """Calculate and store the checksum for the UDP datagram
           when encapsulated as an IPv4 payload with the given header."""
        #print "udp.calc_checksum_v4()"
        from pcs.packets.ipv4 import ipv4
        from pcs.packets.ipv4 import pseudoipv4
        self.checksum = 0
        payload = self._head.collate_following(self)
        pip = pseudoipv4()
        pip.src = ip.src
        pip.dst = ip.dst
        pip.protocol = socket.IPPROTO_UDP
        pip.length = len(self.getbytes()) + len(payload)
        tmpbytes = pip.getbytes() + self.getbytes() + payload
        self.checksum = ipv4.ipv4_cksum(tmpbytes)

    def calc_checksum_v6(self, ip6):
        """Calculate and store the checksum for the UDP datagram
           when encapsulated as an IPv6 payload with the given header."""
        #print "udp.calc_checksum_v6()"
        from pcs.packets.ipv4 import ipv4
        from pcs.packets.pseudoipv6 import pseudoipv6
        self.checksum = 0
        payload = self._head.collate_following(self)
        pip6 = pseudoipv6()
        pip6.src = ip6.src
        pip6.dst = ip6.dst
        pip6.next_header = ip6.next_header
        pip6.length = len(self.getbytes()) + len(payload)
        tmpbytes = pip6.getbytes() + self.getbytes() + payload
        self.checksum = ipv4.ipv4_cksum(tmpbytes)

    def calc_length(self):
        """Calculate and store the length field(s) for this packet."""
        self.length = len(self.getbytes())
        if self._head is not None:
            self.length += len(self._head.collate_following(self))
