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
# Description: Classes which describe Multiprotocol Label Switching (MPLS)
#

import inspect
import struct
import time

import pcs
import pcs.packets.payload

#
# Default labels
#
LABEL_IPV4_NULL		= 0
LABEL_ROUTER_ALERT	= 1
LABEL_IPV6_NULL		= 2
LABEL_NULL		= 3

#
# LDP TLV: U:1 F:1 type: 13 len: 16 <value>
# TODO: format.
#
LDP_TLV_FEC		= 0x0100
LDP_TLV_ADDRESSES	= 0x0101
LDP_TLV_HOPCOUNT	= 0x0103
LDP_TLV_PATHVEC		= 0x0104
LDP_TLV_LABEL		= 0x0200
LDP_TLV_ATM		= 0x0201
LDP_TLV_FR		= 0x0202
LDP_TLV_STATUS		= 0x0300

#
# FEC TLV elements
#
FEC_ELEM_PREFIX = 2
FEC_ELEM_HOST = 3

#
# Message types
#
LDP_MSG_NOTIFY		= 0x0001
LDP_MSG_HELLO		= 0x0100
LDP_MSG_INIT		= 0x0200
LDP_MSG_KEEPALIVE	= 0x0201
LDP_MSG_ADDR_ANNOUNCE	= 0x0300
LDP_MSG_ADDR_WITHDRAW	= 0x0301
LDP_MSG_MAPPING		= 0x0400
LDP_MSG_REQUEST		= 0x0401
LDP_MSG_WITHDRAW	= 0x0402
LDP_MSG_RELEASE		= 0x0403
LDP_MSG_ABORT		= 0x0404

class ldpmsg(pcs.Packet):
    """RFC 3036 LDP message header """

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        u = pcs.Field("u", 1)
        type = pcs.Field("exp", 15)
        length = pcs.Field("length", 16)
        id = pcs.Field("id", 32)
        mparams = pcs.OptionListField("")
        oparams = pcs.OptionListField("")

        pcs.Packet.__init__(self, [ u, type, length, id, mparams, oparams ], \
                            bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            self.data = payload.payload(bytes[curr:remaining], \
                                        timestamp = timestamp)
        else:
            self.data = None

class ldphdr(pcs.Packet):
    """RFC 3036 LDP packet header """

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        version = pcs.Field("label", 16)
        length = pcs.Field("exp", 16)
        id = pcs.StringField("id", 48)

        pcs.Packet.__init__(self, [ version, length, id ], \
                            bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            self.data = payload.payload(bytes[curr:remaining], \
                                        timestamp = timestamp)
        else:
            self.data = None

class lse(pcs.Packet):
    """RFC 3032 MPLS label stack entry"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        label = pcs.Field("label", 20)
        exp = pcs.Field("exp", 3)
        s = pcs.Field("s", 1)
        ttl = pcs.Field("ttl", 8)

        pcs.Packet.__init__(self, [ label, exp, s, ttl ], bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            self.data = payload.payload(bytes[curr:remaining], \
                                        timestamp = timestamp)
        else:
            self.data = None
