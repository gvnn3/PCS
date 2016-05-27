# Copyright (c) 2005-2016, Neville-Neil Consulting
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
import udp, tcp, icmpv4
import ipv6_map

import os
from socket import AF_INET6, inet_ntop
import time

# extension header next header field.
IPV6_HOPOPTS = 0
IPV6_RTHDR = 43
IPV6_FRAG = 44
IPV6_ESP = 50
IPV6_AH = 51
IPV6_NONE = 59
IPV6_DSTOPTS = 60

class ipv6(pcs.Packet):
    """IPv6"""

    _layout = pcs.Layout()
    _map = ipv6_map.map
    
    def __init__(self, bytes = None, timestamp = None, **kv):
        """IPv6 Packet from RFC 2460"""
        version = pcs.Field("version", 4, default = 6)
        traffic = pcs.Field("traffic_class", 8)
        flow = pcs.Field("flow", 20)
        length = pcs.Field("length", 16)
        next_header = pcs.Field("next_header", 8, discriminator=True)
        hop = pcs.Field("hop", 8)
        src = pcs.StringField("src", 16 * 8)
        dst = pcs.StringField("dst", 16 * 8)
        pcs.Packet.__init__(self,
                            [version, traffic, flow, length, next_header, hop,
                             src, dst], bytes, **kv)
        self.description = "IPv6"
        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp


        if (bytes is not None):
            ## 40 bytes is the standard size of an IPv6 header
            offset = 40
            self.data = self.next(bytes[offset:len(bytes)],
                                  timestamp = timestamp)
        else:
            self.data = None
        
    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields.  Addresses are printed if and only if they are set and not 0."""
        retval = ""
        for field in self._layout:
            if (field.name == "src" or field.name == "dst"):
                value = inet_ntop(AF_INET6, field.value)
                retval += "%s %s\n" % (field.name, value)
            else:
                retval += "%s %d\n" % (field.name, field.value)
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

