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
# File: $Id: tcpv6.py,v 1.1 2006/07/06 09:31:57 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class that describes a TCP packet for IPv6.

import pcs
import struct
from pseudoipv6 import *

class tcpv6(pcs.Packet):
    """A TCP class for IPv6"""
    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a TCP packet for IPv6"""
        sport = pcs.Field("sport", 16)
        dport = pcs.Field("dport", 16)
        seq = pcs.Field("sequence", 32)
        acknum = pcs.Field("ack_number", 32)
        off = pcs.Field("offset", 4)
        reserved = pcs.Field("reserved", 6)
        urg = pcs.Field("urgent", 1)
        ack = pcs.Field("ack", 1)
        psh = pcs.Field("push", 1)
        rst = pcs.Field("reset", 1)
        syn = pcs.Field("syn", 1)
        fin = pcs.Field("fin", 1)
        window = pcs.Field("window", 16)
        cksum = pcs.Field("checksum", 16)
        urgptr = pcs.Field("urg_pointer", 16)
        pcs.Packet.__init__(self, [sport, dport, seq, acknum, off, reserved,
                                   urg, ack, psh, rst, syn, fin, window, cksum, urgptr],
                            bytes = bytes)

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields.  Addresses are printed if and only if they are set and not 0."""
        retval = ""
        for field in self.layout:
            if (field.type == str):
                retval += "%s %s\n" % (field.name, self.__dict__[field.name])
            else:
                retval += "%s %d\n" % (field.name, self.__dict__[field.name])
        return retval

    def cksum(self, ip, data = "", nx = 0):
        """return tcpv6 checksum"""
        total = 0
        p6 = pseudoipv6()
        p6.src = ip.src
        p6.dst = ip.dst
        p6.length = len(self.getbytes()) + len (data)
        if nx:
            p6.next_header = nx
        else:
            p6.next_header = ip.next_header
        pkt = p6.getbytes() + self.getbytes() + data
        if len(pkt) % 2 == 1:
            pkt += "\0"
        for i in range(len(pkt)/2):
            total += (struct.unpack("!H", pkt[2*i:2*i+2])[0])
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return  ~total
