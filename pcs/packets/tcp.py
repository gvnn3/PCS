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

import sys

import pcs
from pcs.packets import payload
import tcp_map

import inspect
import time

class tcp(pcs.Packet):
    """TCP"""
    _layout = pcs.Layout()
    _map = None
    
    def __init__(self, bytes = None, timestamp = None):
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
        checksum = pcs.Field("checksum", 16)
        urgp = pcs.Field("urg_pointer",16)
        options = pcs.OptionListField("options")
        pcs.Packet.__init__(self, [sport, dport, seq, acknum, off, reserved,
                                   urg, ack, psh, rst, syn, fin, window,
                                   checksum, urgp, options],
                            bytes = bytes)
        self.description = inspect.getdoc(self)
        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # Handle options processing
        if bytes != None:
            if (self.offset * 4 > self.sizeof()):
                curr = self.sizeof()
                while (curr <= self.offset * 4):
                    if bytes[curr] == 0:
                        self.options.append([0, pcs.Field("nop", 8)])
                        curr += 1
                    elif bytes[curr] == 1:
                        self.options.append([1, pcs.Field("end", 8)])
                        curr += 1
                    else:
                        print "unknown option"
                        curr += 1

        if (bytes != None and (self.offset * 4 < len(bytes))):
            self.data = self.next(bytes[(self.offset * 4):len(bytes)],
                                  timestamp = timestamp)
        else:
            self.data = None

    # XXX TCP MUST have it's own next() function so that it can discrimnate
    # on either sport or dport.

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
        for field in self._layout:
            retval += "%s %s\n" % (field.name, self.__dict__[field.name])
        return retval

    def pretty(self, attr):
        """Pretty prting a field"""
        pass

    def cksum(self, ip, data = ""):
        """return tcpv4 checksum"""
        from pcs.packets.ipv4 import pseudoipv4
        import struct
        total = 0
        tmpip = pseudoipv4()
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
