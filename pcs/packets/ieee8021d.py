# Copyright (c) 2008, Bruce M. Simpson.
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
# Neither the name of the author nor the names of other
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
# File: $Id$
#
# Author: Bruce M. Simpson
#
# Description: Classes which describe IEEE 802.1d and GARP headers.
#

import struct
import time

import pcs
import pcs.packets.payload

#
# How you tell GMRP and GVRP apart.
#
ETHER_DEST_GMRP = "\x01\x80\xc2\x00\x00\x20"
ETHER_DEST_GVRP = "\x01\x80\xc2\x00\x00\x21"

PROTO_STP = 0x0000
PROTO_GARP = 0x0001

# TODO: GARP, GMRP and GVRP TLVs.

ATTR_END = 0
ATTR_GROUP = 1
ATTR_VID = ATTR_GROUP           # Alias for GVRP
ATTR_REQUIREMENT = 2

# GARP attribute event types
EVENT_LEAVE_ALL = 0
EVENT_JOIN_EMPTY = 1
EVENT_JOIN_IN = 2
EVENT_LEAVE_EMPTY = 3
EVENT_LEAVE_IN = 4 
EVENT_EMPTY = 5

# GARP message: 1byte attribute type + 1..N attribute + end mark
# lengths are inclusive:
# GARP attribute TLV: 1/1/n length/event/value
# GVRP attribute TLV: 1/1/2 length/event/vlanid

class garp(pcs.Packet):
    """IEEE 802.1d GARP PDU"""

    def __init__(self, bytes = None, timestamp = None, **kv):
        attributes = pcs.OptionListField("attributes")

        pcs.Packet.__init__(self, [ attributes ], bytes = bytes, **kv)
        self.description = "IEEE 802.1d GARP PDU"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp
        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            # TODO parse GARP attribute list..
            if self.data is None:
                self.data = payload.payload(bytes[curr:remaining], \
                                            timestamp=timestamp)
        else:
            self.data = None

class stp(pcs.Packet):
    """IEEE 802.1d STP PDU"""

    _layout = pcs.Layout()
    _flagbits = "\x01ACK\x02AGREE\x03FORWARDING\x04LEARNING\x05BACKUP" \
                "\x06ROOT\x07PROPOSAL\x08CHANGED"

    def __init__(self, bytes = None, timestamp = None, **kv):
        version = pcs.Field("version", 8)
        type = pcs.Field("type", 8)
        flags = pcs.Field("flags", 8)
        root = pcs.StringField("root", 8 * 8)
        cost = pcs.Field("cost", 32)
        src = pcs.StringField("src", 8 * 8)
        pid = pcs.Field("pid", 16)
        age = pcs.Field("age", 16)
        maxage = pcs.Field("maxage", 16)
        interval = pcs.Field("interval", 16)
        delay = pcs.Field("delay", 16)
        #opt = pcs.OptionListField("opt")

        pcs.Packet.__init__(self, [ version, type, flags, root, \
                                    cost, src, pid, age, maxage, interval, \
                                    delay ], bytes = bytes, **kv)
        self.description = "IEEE 802.1d STP PDU"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            # 802.1d shouldn't have any trailers.
            self.data = payload.payload(bytes[curr:remaining], \
                                        timestamp = timestamp)
        else:
            self.data = None

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        s = self._descr[self.type] + "\n"
        for fn in self._layout:
            f = self._fieldnames[fn.name]
            if fn.name == "flags":
                bs = bsprintf(f.value, self._flagbits)
                s += "%s %s\n" % (fn.name, bs)
            else:
                s += "%s %s\n" % (fn.name, f.value)
        return s

map = {
        PROTO_STP: stp,
        PROTO_GARP: garp
}

class bpdu(pcs.Packet):
    """IEEE 802.1d bridge PDU header"""

    _layout = pcs.Layout()
    _map = map

    def __init__(self, bytes = None, timestamp = None, **kv):
        protocol = pcs.Field("protocol", 16, discriminator=True)

        pcs.Packet.__init__(self, [ protocol ], bytes = bytes, **kv)
        self.description = "IEEE 802.1d bridge PDU header"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            self.data = self.next(bytes[curr:remaining], timestamp=timestamp)
            if self.data is None:
                self.data = payload.payload(bytes[curr:remaining], \
                                            timestamp=timestamp)
        else:
            self.data = None
