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
# File: $Id: udpv4.py,v 1.1 2005/10/14 00:53:16 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class which implements UDP v4 packets

import sys
sys.path.append("../src")

import pcs
import pcs.packets.udp

class udpv4(pcs.packets.udp.udp):

    _layout = pcs.Layout()
    _map = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        """Initialize a UDP packet for IPv4"""
        pcs.packets.udp.udp.__init__(self, bytes, timestamp, **kv)

    def cksum(self, ip, data = ""):
        """Calculate the checksum for this UDPv4 header,
           outside of a chain."""
        from socket import IPPROTO_UDP
        from pcs.packets.ipv4 import ipv4
        from pcs.packets.ipv4 import pseudoipv4
        tmpip = pseudoipv4()
        tmpip.src = ip.src
        tmpip.dst = ip.dst
        tmpip.protocol = IPPROTO_UDP
        tmpip.length = len(self.getbytes()) + len(data)
        tmpbytes = tmpip.getbytes() + self.getbytes() + data
        return ipv4.ipv4_cksum(tmpbytes)

    def calc_checksum(self):
        """Calculate and store the checksum for this UDPv4 datagram.
           The packet must be part of a chain.
           udpv4 is a specialization of udp whose outer header must
           always be ipv4, therefore we enforce this."""
        from pcs.packets.ipv4 import ipv4
        ip = None
        if self._head is not None:
            ip = self._head.find_preceding(self, pcs.packets.ipv4.ipv4)
        if ip is None:
            self.checksum = 0
            self.checksum = ipv4.ipv4.ipv4_cksum(self.getbytes())
            return
        pcs.packets.udp.udp.calc_checksum_v4(self, ip)
