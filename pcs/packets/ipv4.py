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
from pcs import UnpackError
from socket import AF_INET, inet_ntop
import ipv4_map

import struct
import inspect
import time

#
# IPv4 address constants.
#
INADDR_ANY		= 0x00000000	# 0.0.0.0
INADDR_NONE		= 0x00000000	# 0.0.0.0
INADDR_BROADCAST	= 0xffffffff	# 255.255.255.255
INADDR_LOOPBACK		= 0x7f000001	# 127.0.0.1
INADDR_UNSPEC_GROUP	= 0xe0000000	# 224.0.0.0
INADDR_ALLHOSTS_GROUP	= 0xe0000001	# 224.0.0.1
INADDR_ALLRTRS_GROUP	= 0xe0000002	# 224.0.0.2
INADDR_DVMRP_GROUP	= 0xe0000004	# 224.0.0.4
INADDR_ALLPIM_ROUTERS_GROUP = 0xe000000d	# 224.0.0.13
INADDR_ALLRPTS_GROUP	= 0xe0000016	# 224.0.0.22, IGMPv3
INADDR_MAX_LOCAL_GROUP	= 0xe00000ff	# 224.0.0.255

#
# IPv4 options.
#
IPOPT_EOL = 0
IPOPT_NOP = 1
IPOPT_RA = 148

def IN_LINKLOCAL(i):
    """Return True if the given address is in the 169.254.0.0/16 range."""
    return (((i) & 0xffff0000) == 0xa9fe0000)

def IN_MULTICAST(i):
    """Return True if the given address is in the 224.0.0.0/4 range."""
    return (((i) & 0xf0000000) == 0xe0000000)

def IN_LOCAL_GROUP(i):
    """Return True if the given address is in the 224.0.0.0/24 range."""
    return (((i) & 0xffffff00) == 0xe0000000)

def IN_EXPERIMENTAL(i):
    """Return True if the given address is in the 240.0.0.0/24 range."""
    return (((i) & 0xf0000000) == 0xf0000000)

def IN_PRIVATE(i):
    """Return True if the given address is in any of the 10.0.0.0/8,
       172.16.0.0/16, or 192.168.0.0/24 ranges from RFC 1918."""
    return ((((i) & 0xff000000) == 0x0a000000) or \
            (((i) & 0xfff00000) == 0xac100000) or \
            (((i) & 0xffff0000) == 0xc0a80000))

class ipv4opt(pcs.TypeLengthValueField):
    """Syntactic sugar for IPv4 option use in constructors.
       XXX Currently only Router Alert is supported properly. """

    def __init__(self, type, **kv):
        pcs.TypeLengthValueField.__init__(self, "", \
                                          pcs.Field("", 8, default = type), \
                                          pcs.Field("", 8), \
                                          pcs.Field("", 16)) # XXX

class ipv4(pcs.Packet):
    """IPv4"""

    _layout = pcs.Layout()
    _map = ipv4_map.map

    def __init__(self, bytes = None, timestamp = None, **kv):
        """ define the fields of an IPv4 packet, from RFC 791."""
        version = pcs.Field("version", 4, default = 4)
        hlen = pcs.Field("hlen", 4, default = 5)
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
        options = pcs.OptionListField("options")
        pcs.Packet.__init__(self,
                            [version, hlen, tos, length, id, flags, offset,
                             ttl, protocol, checksum, src, dst, options],
                            bytes = bytes, **kv)
        # Description MUST be set after the PCS layer init
        self.description = inspect.getdoc(self)

        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes != None:
            hlen_bytes = self.hlen * 4
            options_len = hlen_bytes - self.sizeof()

            if hlen_bytes > len(bytes):
                raise UnpackError, \
                      "IP header is larger than input (%d > %d)" % \
                      (hlen_bytes, len(bytes))

            if options_len > 0:
                curr = self.sizeof()
                while curr < hlen_bytes:
                    option = struct.unpack('!B', bytes[curr])[0]

                    if option == IPOPT_EOL:
                        options.append(pcs.Field("end", 8, default = IPOPT_EOL))
                        curr += 1
                        continue
                    elif option == IPOPT_NOP:
                        options.append(pcs.Field("nop", 8, default = IPOPT_NOP))
                        curr += 1
                        continue

                    optlen = struct.unpack('!B', bytes[curr+1])[0]
                    if option == IPOPT_RA:
                        # The IPv4 Router Alert option (RFC 2113) is a
                        # single 16 bit value. Its existence indicates
                        # that a router must examine the packet. It is
                        # 32 bits wide including option code and length.
                        if optlen != 4:
                            raise UnpackError, \
                                  "Bad length %d for IP option %d, " \
                                  "should be %d" % (optlen, option, 4)
                        value = struct.unpack("!H", bytes[curr+2:curr+4])[0]
                        options.append(pcs.TypeLengthValueField("ra",
                                       pcs.Field("t", 8, default = option),
                                       pcs.Field("l", 8, default = optlen),
                                       pcs.Field("v", 16, default = value)))
                        curr += optlen
                    else:
                        print "warning: unknown IP option %d" % option
                        optdatalen = optlen - 2
                        options.append(pcs.TypeLengthValueField("unknown",
                                       pcs.Field("t", 8, default = option),
                                       pcs.Field("l", 8, default = optlen),
                                       pcs.Field("v", optdatalen * 8,
                                                 default = value)))
                        curr += optlen

        if (bytes != None):
            offset = self.hlen << 2
            self.data = self.next(bytes[offset:len(bytes)],
                                  timestamp = timestamp)
        else:
            self.data = None

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        retval = "IPv4\n"
        for field in self._layout:
            if (field.name == "src" or field.name == "dst"):
                value = inet_ntop(AF_INET,
                                  struct.pack('!L', field.value))
                retval += "%s %s\n" % (field.name, value)
            else:
                retval += "%s %s\n" % (field.name, field.value)
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

#
# Convenience object for higher level protocols that need a fake IPv4
# header to calculate a checksum.

class pseudoipv4(pcs.Packet):
    """IPv4 Pseudo Header"""

    _layout = pcs.Layout()
    _map = None

    from socket import IPPROTO_TCP

    def __init__(self, bytes = None, timestamp = None, proto = IPPROTO_TCP):
        """For a pseudo header we only need the source and destination ddresses."""
        src = pcs.Field("src", 32)
        dst = pcs.Field("dst", 32)
        reserved = pcs.Field("reserved", 8, default = 0)
        protocol = pcs.Field("protocol", 8, default = proto)
        length = pcs.Field("length", 16)
        pcs.Packet.__init__(self, [src, dst, reserved, protocol, length],
                            bytes = bytes)
        # Description MUST be set after the PCS layer init
        self.description = inspect.getdoc(self)
        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        self.data = None
