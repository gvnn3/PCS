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
# File: $Id: tcp.py,v 1.5 2006/07/06 09:31:57 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class that describes a TCP packet.

import pcs
from pcs.packets import payload
import tcp_map

class tcp(pcs.Packet):
    """A TCP class for IPv4"""
    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a TCP packet"""
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
        urgp = pcs.Field("urg_pointer",16)
        pcs.Packet.__init__(self, [sport, dport, seq, acknum, off, reserved,
                                   urg, ack, psh, rst, syn, fin, window,
                                   cksum, urgp],
                            bytes = bytes)
        self.description = "TCP"

        if (bytes != None and (self.offset * 4 < len(bytes))):
            print self.offset * 4
            print len(bytes)
            print bytes[(self.offset * 4):len(bytes)]
            self.data = self.next(bytes[(self.offset * 4):len(bytes)])
        else:
            self.data = None

    def next(self, bytes):
        """Decode higher layer packets contained in TCP."""
        if (self.dport in tcp_map.map):
            return tcp_map.map[self.dport](bytes)
        if (self.sport in tcp_map.map):
            return tcp_map.map[self.sport](bytes)

        return None

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields.  Addresses are printed if and only if they are set and not 0."""
        retval = "TCP\n"
        for field in self.layout:
            retval += "%s %s\n" % (field.name, self.__dict__[field.name])
        return retval

    def pretty(self, attr):
        """Pretty prting a field"""
        pass

