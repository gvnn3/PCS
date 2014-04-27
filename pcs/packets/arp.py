# Copyright (c) 2006, Neville-Neil Consulting
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
# File: $Id: arp.py,v 1.2 2006/08/01 13:35:58 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description:  ARP packet class
import pcs
import struct
from socket import AF_INET, inet_ntop, inet_ntoa
import time

ARPHRD_ETHER = 1        # ethernet hardware format
ARPHRD_IEEE802 = 6      # token-ring hardware format
ARPHRD_ARCNET = 7       # arcnet hardware format
ARPHRD_FRELAY = 15      # frame relay hardware format
ARPHRD_IEEE1394 = 24    # firewire hardware format

ARPOP_REQUEST = 1       # request to resolve address
ARPOP_REPLY = 2         # response to previous request
ARPOP_REVREQUEST = 3    # request protocol address given hardware
ARPOP_REVREPLY = 4      # response giving protocol address
ARPOP_INVREQUEST = 8    # request to identify peer
ARPOP_INVREPLY = 9      # response identifying peer

class arp(pcs.Packet):
    """ARP"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize an ARP packet"""
        hrd = pcs.Field("hrd", 16, default = 1)
        pro = pcs.Field("pro", 16, default = 0x800)
        hln = pcs.Field("hln", 8, default = 6)
        pln = pcs.Field("pln", 8, default = 4)
        op = pcs.Field("op", 16)
        sha = pcs.StringField("sha", 48)
        spa = pcs.Field("spa", 32)
        tha = pcs.StringField("tha", 48)
        tpa = pcs.Field("tpa", 32)
        
        pcs.Packet.__init__(self, [hrd, pro, hln, pln, op,
                                   sha, spa, tha, tpa], bytes = bytes, **kv)
        self.description = "ARP"
        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        self.data = None

    def __str__(self):
        """return a human readable version of an ARP packet"""
        retval = "ARP\n"
        retval += "hrd: "
        retval += "%d\n" % self.hrd
        retval += "pro: "
        retval += "%d\n" % self.pro
        retval += "hln: "
        retval += "%d\n" % self.hln
        retval += "pln: "
        retval += "%d\n" % self.pln
        retval += "op: "
        retval += "%d\n" % self.op
        
        retval += "sha: "
        if len(self.sha) >= 6:
            for byte in range(0,5):
                retval += "%s:" % hex(ord(self.sha[byte]))[2:4]
            retval += "%s\n" % hex(ord(self.sha[5]))[2:4]

        retval += "spa: "
        retval += "%s\n" % inet_ntop(AF_INET, struct.pack('!L', self.spa))
        
        retval += "tha: "
        if len(self.tha) >= 6:
            for byte in range(0,5):
                retval += "%s:" % hex(ord(self.tha[byte]))[2:4]
            retval += "%s\n" % hex(ord(self.tha[5]))[2:4]

        retval += "tpa: "
        retval += "%s\n" % inet_ntop(AF_INET, struct.pack('!L', self.tpa))

        return retval

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
    for i in (list(range(5))):
        pretty += hex(bytes[i])[2:4] # Strip the 0x from the string
        pretty += ':'
        
    pretty += hex(bytes[5])[2:4] # Strip the 0x from the string

    return pretty
