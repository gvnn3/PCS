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
# File: $Id: udpv6.py,v 1.1 2006/07/06 09:31:57 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class which implements UDP v6 packets

import sys
sys.path.append("../src")

import pcs
import pcs.packets.udp

class udpv6(pcs.packets.udp.udp):

    _layout = pcs.Layout()
    _map = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        """Initialize a UDP packet for IPv6"""
        pcs.packets.udp.udp.__init__(self, bytes, timestamp, **kv)

    def cksum(self, ip, data = "", nx = 0):
        """Calculate the checksum for this UDPv6 header, outside
           of any existing chain."""
        from pcs.packets.ipv4 import ipv4
        from pcs.packets.pseudoipv6 import pseudoipv6
        p6 = pseudoipv6()
        p6.src = ip.src
        p6.dst = ip.dst
        p6.length = len(self.getbytes()) + len(data)
        if nx:
            p6.next_header = nx
        else:
            p6.next_header = ip.next_header
        tmpbytes = p6.getbytes() + self.getbytes() + data
        return ipv4.ipv4_cksum(tmpbytes)

    def calc_checksum(self):
        """Calculate and store the checksum for this UDPv6 datagram.
           The packet SHOULD be part of a chain, and have an IPv6 header.
           udpv6 is a specialization of udp whose outer header must
           always be ipv4, therefore we enforce this."""
        from pcs.packets.ipv4 import ipv4
        ip6 = None
        if self._head is not None:
            ip6 = self._head.find_preceding(self, pcs.packets.ipv6.ipv6)
        if ip6 is None:
            self.checksum = 0
            self.checksum = ipv4.ipv4_cksum(self.getbytes())
            return
        pcs.packets.udp.udp.calc_checksum_v6(self, ip6)
