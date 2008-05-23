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
# Description: RFC 4271 Border Gateway Protocol version 4
#

import inspect
import struct
import time

import pcs
import pcs.packets.payload

# TODO: Add capabilities to OPEN.
# TODO: Parse variable length fields in UPDATE.
# TODO: Finish off TLVs.
# TODO: Add error subcodes.
# TODO: Add AS-path parser.
# TODO: Add 32-bit AS support.
# TODO: Add MPLS label support to NLRI.

OPEN = 1
UPDATE = 2
NOTIFICATION = 3
KEEPALIVE = 4

HEADER_ERROR = 1
OPEN_ERROR = 2
UPDATE_ERROR = 3
HOLD_TIMER_EXPIRED = 4
FSM_ERROR = 5
CEASE = 6

class notification(pcs.Packet):
    """RFC 4271 BGP NOTIFICATION message."""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        code = pcs.Field("code", 8)
        subcode = pcs.Field("subcode", 8)
        opt = pcs.OptionListField("opt")

        pcs.Packet.__init__(self, [ code, subcode, opt ], bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            if remaining > 0:
                value = pcs.StringField("data", remaining*8, \
                                        default=bytes[curr:remaining])
                opt._options.append(value)
        else:
            self.data = None

# where the meat is. lotsa tlvs.
class update(pcs.Packet):
    """RFC 4271 BGP UPDATE message."""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        nwithdrawn = pcs.Field("nwithdrawn", 16)
        withdrawn = pcs.OptionListField("withdrawn")
        npathattrs = pcs.Field("npathattrs", 16)
        pathattrs = pcs.OptionListField("pathattrs")
        nlri = pcs.OptionListField("nlri")

        pcs.Packet.__init__(self, [ nwithdrawn, withdrawn, npathattrs, \
                                    pathattrs, nlri ], bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = nwithdrawn.width
            curr = offset
            remaining = len(bytes) - offset
            # TODO parse withdrawn
            # TODO parse pathattrs
            # TODO parse nlri
            if remaining > 0:
                self.data = payload.payload(bytes[curr:remaining], \
                                            timestamp = timestamp)
        else:
            self.data = None

class open(pcs.Packet):
    """RFC 4271 BGP OPEN message."""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        version = pcs.Field("version", 8, default=4)
        asnum = pcs.Field("asnum", 16)
        holdtime = pcs.Field("holdtime", 16)
        id = pcs.Field("id", 32)
        optlen = pcs.Field("optlen", 8)
        opt = pcs.OptionField("opt")

        pcs.Packet.__init__(self, \
                            [ version, asnum, holdtime, id, optlen, opt], \
                            bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # TODO: Parse the Capabilities TLV (RFC 3392).
        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            if optlen > 0 and remaining == optlen:
                opt._options.append(pcs.StringField("opts", optlen*8, \
                                                    bytes[curr:curr+optlen]))
                curr += optlen
                remaining -= optlen
            if remaining > 0:
                self.data = payload.payload(bytes[curr:remaining], \
                                            timestamp = timestamp)
        else:
            self.data = None

_map = {
	OPEN:		open,
	UPDATE:		update,
	NOTIFICATION:	notification
	# keepalive is just a plain header.
}

class header(pcs.Packet):
    """RFC 4271 BGP message header."""

    _layout = pcs.Layout()
    _marker = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"\
              "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"

    def __init__(self, bytes = None, timestamp = None, **kv):
        marker = pcs.StringField("marker", 16 * 8, default=_marker)
        length = pcs.Field("length", 16)
        type = pcs.Field("type", 8, discriminator=True)

        pcs.Packet.__init__(self, [ marker, length, type ], bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            curr = offset
            remaining = len(bytes) - offset
            self.data = self.next(bytes[curr:remaining], \
                                  timestamp = timestamp)
            if self.data is None:
                self.data = payload.payload(bytes[curr:remaining], \
                                            timestamp = timestamp)
        else:
            self.data = None
