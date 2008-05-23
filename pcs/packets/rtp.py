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
# Description: Classes which describe RFC 3550 RTP packets.
#

import inspect
import struct
import time

import pcs
from pcs.packets import payload
#import rtp_map

# TODO: Make sender header inherit from rtcp as it needs
# to see the Report Count.
# TODO: RTCP BYE, APP, SDES.
# TODO: SDES: CNAME, NAME, EMAIL, PHONE, LOC, TOOL, NOTE, PRIV TLVs.
# TODO: Sender report blocks.
# TODO: Receiver reports.

class rtp(pcs.Packet):
    """RFC 3550 Real Time Protocol"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        v = pcs.Field("v", 2)		# version
        p = pcs.Field("p", 1)		# padded
        x = pcs.Field("x", 1)		# extended
        cc = pcs.Field("cc", 4)		# csrc count
        m = pcs.Field("m", 4)		# m-bit
        pt = pcs.Field("pt", 7, discriminator=True)	# payload type
        seq = pcs.Field("seq", 16)	# sequence
        ssrc = pcs.Field("ssrc", 32)	# source
        opt = pcs.OptionListField("opt")	# optional fields

        pcs.Packet.__init__(self, [v, p, x, cc, m, pt, seq, ssrc, opt], \
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
            # Parse CSRC.
            nc = self.cc
            while nc > 0 and remaining >= 4:
                value = struct.unpack("!I", bytes[curr:curr+4])
                csrc = pcs.Field("csrc", 32, default=value)
                self.opt._options.append(csrc)
                curr += 4
                remaining -= 4
            # Parse Header Extension.
            if self.x == 1 and remaining >= 4:
                extlen = struct.unpack("!H", bytes[curr+2:curr+4])
                extlen <<= 2
                extlen = min(extlen, remaining)
                # Copy the entire chunk so we keep the type field.
                ext = pcs.StringField("ext", extlen * 8, \
                                      default=bytes[curr:extlen+4])
                self.opt._options.append(ext)
                curr += extlen
                remaining -= extlen
            # Heed padding byte.
            npad = 0
            if self.p == 1:
                npad = bytes[-1]
            self.data = payload.payload(bytes[curr:remaining-npad], \
                                        timestamp = timestamp)
        else:
            self.data = None

    #def next(self, bytes, timestamp):
    #    """Decapsulate RTP payload header according to payload type."""

class rtcp(pcs.Packet):
    """RFC 3550 Real Time Control Protocol header"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        v = pcs.Field("v", 2)
        p = pcs.Field("p", 1)
        rc = pcs.Field("rc", 5)
        pt = pcs.Field("pt", 8)
        length = pcs.Field("length", 16)
        ssrc = pcs.Field("ssrc", 32)

        pcs.Packet.__init__(self, [v, p, rc, pt, length, ssrc], \
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
            # XXX TODO look at pt and decapsulate next.
            self.data = payload.payload(bytes[curr:remaining], \
                                        timestamp = timestamp)
        else:
            self.data = None

class sender(pcs.Packet):
    """RFC 3550 Real Time Control Protocol sender message portion"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        ntpts = pcs.Field("ntpts", 64)
        rtpts = pcs.Field("rtpts", 32)
        spkts = pcs.Field("spkts", 32)
        sbytes = pcs.Field("sbytes", 32)
        opt = pcs.OptionListField("opt")

        pcs.Packet.__init__(self, [ntpts, rtpts, spkts, sbytes, opt],
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
            # XXX TODO decapsulate all the report counts.
            # to do this, we need to see the parent RC.
            self.data = payload.payload(bytes[curr:remaining], \
                                        timestamp = timestamp)
        else:
            self.data = None
