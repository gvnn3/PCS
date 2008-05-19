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

import inspect
import time

#
# ICMP types.
#
ICMP_ECHOREPLY = 0		# echo reply 
ICMP_UNREACH = 3		# dest unreachable, codes: 
ICMP_SOURCEQUENC = 4		# packet lost, slow down 
ICMP_REDIRECT = 5		# shorter route
ICMP_ALTHOSTADD = 6		# alternate host address 
ICMP_ECHO = 8			# echo service 
ICMP_ROUTERADVER = 9		# router advertisement 
ICMP_ROUTERSOLICI = 10		# router solicitation 
ICMP_TIMXCEED = 11		# time exceeded, code: 
ICMP_PARAMPROB = 12		# ip header bad 
ICMP_TSTAMP = 13		# timestamp request 
ICMP_TSTAMPREPL = 14		# timestamp reply 
ICMP_IREQ = 15			# information request 
ICMP_IREQREPLY = 16		# information reply 
ICMP_MASKREQ = 17		# address mask request 
ICMP_MASKREPLY = 18		# address mask reply 
ICMP_TRACEROUTE = 30		# traceroute 
ICMP_DATACONVER = 31		# data conversion error 
ICMP_MOBILE_REDIREC = 32	# mobile host redirect 
ICMP_IPV6_WHEREAREYO = 33	# IPv6 where-are-you 
ICMP_IPV6_IAMHER = 34		# IPv6 i-am-here 
ICMP_MOBILE_REGREQUES = 35	# mobile registration req 
ICMP_MOBILE_REGREPL = 36	# mobile registration reply 
ICMP_SKIP = 39			# SKIP 
ICMP_PHOTURIS = 40		# Photuris 

#
# ICMP codes.
#
ICMP_UNREACH_NE = 0		# bad net 
ICMP_UNREACH_HOS = 1		# bad host 
ICMP_UNREACH_PROTOCO = 2	# bad protocol 
ICMP_UNREACH_POR = 3		# bad port 
ICMP_UNREACH_NEEDFRA = 4	# IP_DF caused drop 
ICMP_UNREACH_SRCFAI = 5		# src route failed 
ICMP_UNREACH_NET_UNKNOWN = 6	# unknown net 
ICMP_UNREACH_HOST_UNKNOWN = 7	# unknown host 
ICMP_UNREACH_ISOLATE = 8	# src host isolated 
ICMP_UNREACH_NET_PROHI = 9	# prohibited access 
ICMP_UNREACH_HOST_PROHIB = 10	# ditto 
ICMP_UNREACH_TOSNE = 11		# bad tos for net 
ICMP_UNREACH_TOSHOS = 12	# bad tos for host 
ICMP_UNREACH_FILTER_PROHIB = 13	# admin prohib 
ICMP_UNREACH_HOST_PRECEDENCE = 14	# host prec vio. 
ICMP_UNREACH_PRECEDENCE_CUTOFF = 1	# prec cutoff 
ICMP_REDIRECT_NE = 0		# for network 
ICMP_REDIRECT_HOS = 1		# for host 
ICMP_REDIRECT_TOSNE = 2		# for tos and net 
ICMP_REDIRECT_TOSHOS = 3	# for tos and host 
ICMP_ROUTERADVERT_NORMAL = 0		# normal advertisement 
ICMP_ROUTERADVERT_NOROUTE_COMMO = 1	# selective routing 
ICMP_TIMXCEED_INTRAN = 0		# ttl==0 in transit 
ICMP_TIMXCEED_REAS = 1			# ttl==0 in reass 
ICMP_PARAMPROB_ERRATPTR = 0		# error at param ptr 
ICMP_PARAMPROB_OPTABSENT = 1		# req. opt. absent 
ICMP_PARAMPROB_LENGTH = 2		# bad length 
ICMP_PHOTURIS_UNKNOWN_INDE = 1		# unknown sec index 
ICMP_PHOTURIS_AUTH_FAILE = 2		# auth failed 
ICMP_PHOTURIS_DECRYPT_FAILE = 3		# decrypt failed 

class icmpv4(pcs.Packet):
    """ICMPv4"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize a ICMPv4 packet"""
        from pcs.packets import payload
        type = pcs.Field("type", 8)
        code = pcs.Field("code", 8)
        cksum = pcs.Field("checksum", 16)
        pcs.Packet.__init__(self, [type, code, cksum], bytes, **kv)
        self.description = inspect.getdoc(self)
        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (bytes != None):
            offset = type.width + code.width + cksum.width
            self.data = payload.payload(bytes[offset:len(bytes)])
        else:
            self.data = None

    def calc_checksum(self):
        """Calculate and store the checksum for this ICMP header.
           ICMP checksums are computed over payloads, but not IP headers."""
        from pcs.packets.ipv4 import ipv4
        self.checksum = 0
        tmpbytes = self.getbytes()
        if not self._head is None:
            tmpbytes += self._head.collate_following(self)
        self.checksum = ipv4.ipv4_cksum(tmpbytes)

class icmpv4echo(pcs.Packet):
    """ICMPv4 Echo"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize an ICMPv4 echo packet, used by ping(8) and others"""
        from pcs.packets import payload
        id = pcs.Field("id", 16)
        seq = pcs.Field("sequence", 16)
        pcs.Packet.__init__(self, [id, seq], bytes, **kv)
        self.description = inspect.getdoc(self)
        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (bytes != None):
            offset = id.width + seq.width
            self.data = payload.payload(bytes[offset:len(bytes)])
        else:
            self.data = None

