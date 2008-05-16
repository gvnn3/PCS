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
# File: $Id: udp.py,v 1.4 2006/09/01 05:24:04 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class which implements UDP v4 packets

import pcs
import udp_map

import inspect
import time

class udp(pcs.Packet):
    """UDP"""

    _layout = pcs.Layout()
    _map = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize a UDP packet"""
        sport = pcs.Field("sport", 16)
        dport = pcs.Field("dport", 16)
        length = pcs.Field("length", 16)
        checksum = pcs.Field("checksum", 16)
        pcs.Packet.__init__(self, [sport, dport, length, checksum],
                            bytes, **kv)
        self.description = inspect.getdoc(self)
        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (bytes != None):
            self.data = self.next(bytes[8:len(bytes)], timestamp)
        else:
            self.data = None

    # XXX UDP MUST have its own next() and rdiscriminate() functions,
    # so that it can discriminate on either sport or dport.

    def next(self, bytes, timestamp):
        """Decode higher level services."""
        if (self.dport in udp_map.map):
            return udp_map.map[self.dport](bytes, timestamp = timestamp)
        if (self.sport in udp_map.map):
            return udp_map.map[self.sport](bytes, timestamp = timestamp)

        return None

    def rdiscriminate(self, packet, discfieldname = None, map = udp_map.map):
        """Reverse-map an encapsulated packet back to a discriminator
           field value. Like next() only the first match is used."""
        #print "reverse discriminating %s" % type(packet)
        result = pcs.Packet.rdiscriminate(self, packet, "dport", map)
        if result == False:
            result = pcs.Packet.rdiscriminate(self, packet, "sport", map)
        return result
