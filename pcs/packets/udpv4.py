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
import socket

class udpv4(pcs.packets.udp.udp):

    _layout = pcs.Layout()
    _map = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        """Initialize a UDP packet for IPv4"""
        pcs.packets.udp.udp.__init__(self, bytes, timestamp, **kv)

    def cksum(self, ip, data = ""):
        """return tcpv4 checksum"""
        from pcs.packets.ipv4 import pseudoipv4
        import struct
        total = 0
        tmpip = pseudoipv4(None, None, socket.IPPROTO_UDP)
        tmpip.src = ip.src
        tmpip.dst = ip.dst
        tmpip.length = len(self.getbytes()) + len(data)
        pkt = tmpip.getbytes() + self.getbytes() + data
        if len(pkt) % 2 == 1:
            pkt += "\0"
        for i in range(len(pkt)/2):
            total += (struct.unpack("!H", pkt[2*i:2*i+2])[0])
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return  ~total & 0xffff
