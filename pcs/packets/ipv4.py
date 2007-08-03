# Copyright (c) 2005, Neville-Neil Consulting
#
# All rights reserved.
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
# File: $Id: ipv4.py,v 1.6 2006/09/05 07:30:56 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class which implements an IPv4 packet

import pcs
from socket import AF_INET, inet_ntop
import ipv4_map
import struct

class ipv4(pcs.Packet):

    _layout = pcs.Layout()
    _map = ipv4_map.map

    def __init__(self, bytes = None):
        """ define the fields of an IPv4 packet, from RFC 791
        This version does not include options."""
        version = pcs.Field("version", 4, default = 4)
        hlen = pcs.Field("hlen", 4)
        tos = pcs.Field("tos", 8)
        length = pcs.Field("length", 16)
        id = pcs.Field("id", 16)
        flags = pcs.Field("flags", 3)
        offset = pcs.Field("offset", 13)
        ttl = pcs.Field("ttl", 8, default = 64)
        protocol = pcs.Field("protocol", 8, discriminator=True)
        checksum = pcs.Field("checksum", 16)
        src = pcs.Field("src", 32)
        dst = pcs.Field("dst", 32)
        pcs.Packet.__init__(self,
                            [version, hlen, tos, length, id, flags, offset,
                             ttl, protocol, checksum, src, dst],
                            bytes = bytes)
        # Description MUST be set after the PCS layer init
        self.description = "IPv4"

        if (bytes != None):
            offset = self.hlen << 2
            self.data = self.next(bytes[offset:len(bytes)])
        else:
            self.data = None

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        retval = "IPv4\n"
        for field in self._layout:
            if (field.name == "src" or field.name == "dst"):
                value = inet_ntop(AF_INET,
                                  struct.pack('!L', self.__dict__[field.name]))
                retval += "%s %s\n" % (field.name, value)
            else:
                retval += "%s %s\n" % (field.name, self.__dict__[field.name])
        return retval

    def pretty(self, attr):
        if attr == "src" or attr == "dst":
                return inet_ntop(AF_INET,
                                 struct.pack('!L', getattr(self,attr)))

    def cksum(self):
        """calculate the IPv4 checksum over a packet

        returns the calculated checksum
        """
        total = 0
        packet = ipv4(self.bytes)
        packet.checksum = 0
        bytes = packet.bytes
        if len(bytes) % 2 == 1:
            bytes += "\0"
        for i in range(len(bytes)/2):
            total += (struct.unpack("!H", bytes[2*i:2*i+2])[0])
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ~total & 0xffff

