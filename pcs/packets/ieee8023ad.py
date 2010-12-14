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
# Description: Classes which describe IEEE 802.3ad Slow Protocols.
#

import struct
import time

import pcs
import pcs.packets.payload

# TODO: Ethernet OAM support.
# TODO: Hook up to Ethernet decoder.

ETHER_GROUP_SLOW = "\x01\x80\xc2\x00\x00\x02"

SLOWPROTOCOLS_SUBTYPE_LACP = 1
SLOWPROTOCOLS_SUBTYPE_MARKER = 2
SLOWPROTOCOLS_SUBTYPE_OAM = 3

# LACP TLVs.
# I *think* 0 marks the end of the TLVs.
LACP_TYPE_ACTORINFO = 1
LACP_TYPE_PARTNERINFO = 2
LACP_TYPE_COLLECTORINFO = 3

MARKER_TYPE_INFO = 0x01
MARKER_TYPE_RESPONSE = 0x02

# OAM is:
# [version byte from slowhdr is actually upper 8 bits of flags, ignored.]
# flagslo 1
# code 1
# 0..N OAM TLVs
# TODO: The OAM flags need double checking against spec for IEEE bit order.

# OAM Flags
OAM_F_REMOTE_STABLE = 0x01
OAM_F_REMOTE_EVALUATING = 0x02
OAM_F_LOCAL_STABLE = 0x04
OAM_F_LOCAL_EVALUATING = 0x08
OAM_F_CRITICAL_EVENT = 0x10
OAM_F_DYING_GASP = 0x20
OAM_F_FAULT = 0x40

# OAM Type
OAM_TYPE_INFO = 0
OAM_TYPE_NOTIFY = 1
OAM_TYPE_REQUEST = 2
OAM_TYPE_RESPONSE = 3
OAM_TYPE_LOOPBACK = 4

# OAMPDU Loopback commands
OAM_LOOPBACK_ENABLE = 0x01
OAM_LOOPBACK_DISABLE = 0x02

# OAMPDU INFO frame TLV types
OAM_INFO_TLV_LOCAL = 0x01
OAM_INFO_TLV_REMOTE = 0x02

# OAMPDU State field
OAM_STATE_F_MUX_ACTION =  0x04
OAM_STATE_F_PARSE_ACTION = 0x03	# mask 0:1

# OAMPDU Config field
OAM_CFG_F_HAS_RETRIEVAL = 0x10
OAM_CFG_F_HAS_EVENTS = 0x08
OAM_CFG_F_HAS_LOOPBACK = 0x04
OAM_CFG_F_HAS_SIMPLEX = 0x02
OAM_CFG_F_IS_ACTIVE = 0x01

# TODO: OAM Link Event TLV Types Table 57-12

class lacp(pcs.Packet):
    """IEEE 802.3ad Slow Protocols -- LACP"""
    # composed of: actor, partner, collector, term TLVs.
    _layout = pcs.Layout()
    _map = None
    _descr = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        # composed entirely of TLVs.
        tlvs = pcs.OptionListField("tlvs")

        pcs.Packet.__init__(self, [ tlvs ], bytes = bytes, **kv)
        self.description = "IEEE 802.3ad Slow Protocols -- LACP"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = 0
            remaining = len(bytes)
            # XXX Need to decode the LACP TLVs here, however,
            # TLV needs to be able to contain OptionLists to proceed...
            self.data = payload(bytes[self.sizeof():len(bytes)],
                                timestamp = timestamp)
        else:
            self.data = None

class marker(pcs.Packet):
    """IEEE 802.3ad Slow Protocols -- Marker"""

    _layout = pcs.Layout()
    _map = None
    _descr = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        # XXX: TLV fields can't contain multiple values yet, so we
        # kludge by making the first TLV fields exposed here.
        it = pcs.Field("info_type", 8)
        il = pcs.Field("info_len", 8)
        port = pcs.Field("port", 16)
        system = pcs.StringField("system", 6*8)
        xid = pcs.Field("xid", 32)
        pad = pcs.Field("pad", 16)
        tt = pcs.Field("term_type", 8)
        tl = pcs.Field("term_len", 8)
        resv = pcs.StringField("resv", 90 * 8)

        pcs.Packet.__init__(self, [ it, il, port, system, xid, pad, \
                                    tt, tl, resv ], bytes = bytes, **kv)
        self.description = "IEEE 802.3ad Slow Protocols -- Marker"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            self.data = payload(bytes[self.sizeof():len(bytes)],
                                timestamp = timestamp)
        else:
            self.data = None

map = {
	SLOWPROTOCOLS_SUBTYPE_LACP: lacp,
	SLOWPROTOCOLS_SUBTYPE_MARKER: marker
	#SLOWPROTOCOLS_SUBTYPE_OAM: oam
}

class slowhdr(pcs.Packet):
    """IEEE 802.3ad Slow Protocols -- common header"""

    _layout = pcs.Layout()
    _map = map
    _descr = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        subtype = pcs.Field("subtype", 8)
        version = pcs.Field("version", 8)

        pcs.Packet.__init__(self, [subtype, version], bytes = bytes, **kv)
        self.description = "IEEE 802.3ad Slow Protocols -- common header"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            self.data = frame(bytes[self.sizeof():len(bytes)],
                              timestamp = timestamp)
        else:
            self.data = None
