# Copyright (c) 2007, Neville-Neil Consulting
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
# File: $Id: $
#
# Author: George V. Neville-Neil
#
# Description: The Ethernet packet class

import pcs
import ethernet_map
import pcs.packets.ipv4
from pcs.packets.ipv6 import ipv6
from pcs.packets.arp import arp

import inspect
import time

def ETHER_IS_MULTICAST(e):
    return (e[0] & 0x01) == 0x01

def ETHER_MAP_IP_MULTICAST(i):
    import struct
    return '\x01\x00\x5e' + struct.pack("!I", i)[1:4]

def ETHER_MAP_IPV6_MULTICAST(i):
    return '\x33\x33' + i[12:16]

class ethernet(pcs.Packet):
    """Ethernet"""
    _layout = pcs.Layout()
    _map = ethernet_map.map
    
    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize an ethernet packet"""
        src = pcs.StringField("src", 48)
        dst = pcs.StringField("dst", 48)
        type = pcs.Field("type", 16, discriminator=True)

        pcs.Packet.__init__(self, [dst, src, type], bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (bytes is not None):
            self.data = self.next(bytes[self.sizeof():len(bytes)],
                                  timestamp = timestamp)
        else:
            self.data = None

    def __repr__(self):
        """return a human readable version of an Ethernet packet"""
        retval = "<Ethernet: "
        retval += "dst: "

        if len(self.dst) >= 6:
            for byte in range(0,5):
                retval += "%x:" % ord(self.dst[byte])
            retval += "%x " % ord(self.dst[5])

        retval += "src: "
        if len(self.src) >= 6:
            for byte in range(0,5):
                retval += "%x:" % ord(self.src[byte])
            retval += "%x " % ord(self.src[5])

        retval += "type: 0x%x>" % self.type

        return retval

    def __str__(self):
        """return a human readable version of an Ethernet packet"""
        retval = "Ethernet\n"

        retval += "dst: "
        if len(self.dst) >= 6:
            for byte in range(0,5):
                retval += "%x:" % ord(self.dst[byte])
            retval += "%x" % ord(self.dst[5])

        retval += "\nsrc: "
        if len(self.dst) >= 6:
            for byte in range(0,5):
                retval += "%x:" % ord(self.src[byte])
            retval += "%x" % ord(self.src[5])

        retval += "\ntype: 0x%x" % self.type

        return retval

    def pretty(self, attr):
        """pretty print a particular attribute"""
        if attr == "src" or attr == "dst":
            return ether_btoa(getattr(self, attr))
#
# Functions defined for the module.
#
def ether_atob(pretty):
    """Take a pretty version of an ethernet address and convert it to a
    string of bytes.

    The input string MUST be of the form xx:yy:zz:aa:bb:cc and leading
    zero's must be supplied.  Nor error checking is performed.
    """
    addr = ""
    for i in 0, 3, 6, 9, 12, 15:
        addr += "%c" % int(pretty[i:i+2], 16)
    return addr


def ether_btoa(bytes):
    """Take a set of bytes and convert them to a pretty version of
    and Ethernet address.

    The input buffer MUST be at least 6 bytes long and bytes after the
    sixth are ignored.  No error checking is performed.
    """

    pretty = ""
    for i in (range(5)):
        pretty += hex(ord(bytes[i]))[2:4] # Strip the 0x from the string
        pretty += ':'
        
    pretty += hex(ord(bytes[5]))[2:4] # Strip the 0x from the string

    return pretty
