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
# File: $Id: icmpv4.py,v 1.7 2006/09/05 07:30:56 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class which describes an ICMPv4 packet

import pcs

import time

#
# ICMP types.
#
ICMP_ECHOREPLY = 0              # echo reply 
ICMP_UNREACH = 3                # dest unreachable, codes: 
ICMP_SOURCEQUENCH = 4           # packet lost, slow down 
ICMP_REDIRECT = 5               # shorter route
ICMP_ALTHOSTADDR = 6            # alternate host address 
ICMP_ECHO = 8                   # echo service 
ICMP_ROUTERADVERT = 9           # router advertisement 
ICMP_ROUTERSOLICIT = 10         # router solicitation 
ICMP_TIMXCEED = 11              # time exceeded, code: 
ICMP_PARAMPROB = 12             # ip header bad 
ICMP_TSTAMP = 13                # timestamp request 
ICMP_TSTAMPREPLY = 14           # timestamp reply 
ICMP_IREQ = 15                  # information request 
ICMP_IREQREPLY = 16             # information reply 
ICMP_MASKREQ = 17               # address mask request 
ICMP_MASKREPLY = 18             # address mask reply 
ICMP_TRACEROUTE = 30            # traceroute 
ICMP_DATACONVERR = 31           # data conversion error 
ICMP_MOBILE_REDIRECT = 32       # mobile host redirect 
ICMP_IPV6_WHEREAREYOU = 33      # IPv6 where-are-you 
ICMP_IPV6_IAMHERE = 34          # IPv6 i-am-here 
ICMP_MOBILE_REGREQUEST = 35     # mobile registration req 
ICMP_MOBILE_REGREPLY = 36       # mobile registration reply 
ICMP_SKIP = 39                  # SKIP 
ICMP_PHOTURIS = 40              # Photuris 

#
# ICMP codes.
#
ICMP_UNREACH_NET = 0                    # bad net 
ICMP_UNREACH_HOST = 1                   # bad host 
ICMP_UNREACH_PROTOCOL = 2               # bad protocol 
ICMP_UNREACH_PORT = 3                   # bad port 
ICMP_UNREACH_NEEDFRAH = 4               # IP_DF caused drop 
ICMP_UNREACH_SRCFAIL = 5                # src route failed 
ICMP_UNREACH_NET_UNKNOWN = 6            # unknown net 
ICMP_UNREACH_HOST_UNKNOWN = 7           # unknown host 
ICMP_UNREACH_ISOLATED = 8               # src host isolated 
ICMP_UNREACH_NET_PROHIB = 9             # prohibited access 
ICMP_UNREACH_HOST_PROHIB = 10           # ditto 
ICMP_UNREACH_TOSNET = 11                # bad tos for net 
ICMP_UNREACH_TOSHOST = 12               # bad tos for host 
ICMP_UNREACH_FILTER_PROHIB = 13         # admin prohib 
ICMP_UNREACH_HOST_PRECEDENCE = 14       # host prec vio. 
ICMP_UNREACH_PRECEDENCE_CUTOFF = 1      # prec cutoff 
ICMP_REDIRECT_NET = 0                   # for network 
ICMP_REDIRECT_HOST = 1                  # for host 
ICMP_REDIRECT_TOSNET = 2                # for tos and net 
ICMP_REDIRECT_TOSHOST = 3               # for tos and host 
ICMP_ROUTERADVERT_NORMAL = 0            # normal advertisement 
ICMP_ROUTERADVERT_NOROUTE_COMMON = 1    # selective routing 
ICMP_TIMXCEED_INTRANS = 0               # ttl==0 in transit 
ICMP_TIMXCEED_REASS = 1                 # ttl==0 in reass 
ICMP_PARAMPROB_ERRATPTR = 0             # error at param ptr 
ICMP_PARAMPROB_OPTABSENT = 1            # req. opt. absent 
ICMP_PARAMPROB_LENGTH = 2               # bad length 
ICMP_PHOTURIS_UNKNOWN_INDEX = 1         # unknown sec index 
ICMP_PHOTURIS_AUTH_FAILED = 2           # auth failed 
ICMP_PHOTURIS_DECRYPT_FAILED = 3        # decrypt failed 

class icmpv4echo(pcs.Packet):
    """ICMPv4 Echo"""

    _layout = pcs.Layout()

    def __init__(self, pdata = None, timestamp = None, **kv):
        """initialize an ICMPv4 echo packet, used by ping(8) and others"""
        id = pcs.Field("id", 16)
        seq = pcs.Field("sequence", 16)
        pcs.Packet.__init__(self, [id, seq], pdata, **kv)
        self.description = "ICMPv4 Echo"
        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if pdata is not None:
            offset = self.sizeof()
            from pcs.packets import payload
            self.data = payload.payload(pdata[offset:len(pdata)])
        else:
            self.data = None

# Gnarly: Python can't forward declare, and this module depends upon
# things being defined in a certain order.

icmp_map = {
        ICMP_ECHOREPLY: icmpv4echo,
        ICMP_ECHO:      icmpv4echo
}

descr = {
        ICMP_ECHOREPLY: "ICMPv4 Echo Reply",
        ICMP_ECHO:      "ICMPv4 Echo Request"
}

class icmpv4(pcs.Packet):
    """ICMPv4"""

    _layout = pcs.Layout()
    _map = icmp_map
    _descr = descr

    def __init__(self, pdata = None, timestamp = None, **kv):
        """initialize a ICMPv4 packet"""
        type = pcs.Field("type", 8, discriminator=True)
        code = pcs.Field("code", 8)
        cksum = pcs.Field("checksum", 16)
        pcs.Packet.__init__(self, [type, code, cksum], pdata, **kv)
        self.description = "ICMPv4"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if pdata is not None:
            offset = self.sizeof()
            # XXX Workaround Packet.next() -- it only returns something
            # if it can discriminate.
            self.data = self.next(pdata[offset:len(pdata)],
                                  timestamp = timestamp)
            if self.data is None:
                from pcs.packets.payload import payload
                self.data = payload(pdata[offset:len(pdata)])
        else:
            self.data = None

    def calc_checksum(self):
        """Calculate and store the checksum for this ICMP header.
           ICMP checksums are computed over payloads, but not IP headers."""
        self.checksum = 0
        tmppdata = self.getpdata()
        if not self._head is None:
            tmppdata += self._head.collate_following(self)
        from pcs.packets.ipv4 import ipv4
        self.checksum = ipv4.ipv4_cksum(tmppdata)

    def rdiscriminate(self, packet, discfieldname = None, map = icmp_map):
        """Reverse-map an encapsulated packet back to a discriminator
           field value. Like next() only the first match is used."""
        print("reverse discriminating %s" % type(packet))
        return pcs.Packet.rdiscriminate(self, packet, "type", map)

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        retval = self._descr[self.type] + "\n"
        for field in self._layout:
            retval += "%s %s\n" % (field.name, field.value)
        return retval
