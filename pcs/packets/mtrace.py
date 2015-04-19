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
# Description: A class which describes MTRACE messages, as encapsulated
# inside the payload of an IGMP type 0x1F/0x1E message.
#
# MTRACE is defined in draft-ietf-idmr-traceroute-ipm-07.
# Typically a listener will join the 224.0.1.32 group and listen
# for responses, then begin sending queries to 224.0.0.2.
# Note that 224.0.1.32 is NOT a link-scope group, and
# a unicast address may be used instead.
#
# See also draft-ietf-mboned-mtrace-v2-00 which uses UDP (published
# 12 Nov 2007 and not yet widely implemented). SSMPING is a similar
# tool in intent and use.
#

import pcs
import struct
import time

from pcs.packets import payload
from socket import AF_INET, inet_ntop, inet_ntoa

class query(pcs.Packet):
    layout = pcs.Layout()

    def __init__(self, pdata = None, timestamp = None, **kv):
        """initialize the MTRACE query header."""
        # (G,S) tuple to query.
        group = pcs.Field("group", 32)
        source = pcs.Field("source", 32)
        # Who's asking.
        receiver = pcs.Field("receiver", 32)
        # Where to send the answer.
        response_addr = pcs.Field("response_addr", 32)
        response_hoplimit = pcs.Field("response_hoplimit", 8)
        # The ID of this query.
        query_id = pcs.Field("query_id", 24)

        pcs.Packet.__init__(self, [group, source, \
                                   receiver, response_addr, \
                                   response_hoplimit, query_id], pdata, **kv)

        self.description = "initialize the MTRACE query header."

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (pdata is not None):
            offset = self.sizeof()
            self.data = payload.payload(pdata[offset:len(pdata)])
        else:
            self.data = None

class reply(pcs.Packet):
    layout = pcs.Layout()

    def __init__(self, pdata = None, timestamp = None, **kv):
        """initialize the MTRACE response header."""
        # (G,S) tuple to query.
        group = pcs.Field("group", 32)
        source = pcs.Field("source", 32)
        # Who's asking.
        receiver = pcs.Field("receiver", 32)
        # Where to send the answer.
        response_addr = pcs.Field("response_addr", 32)
        response_hoplimit = pcs.Field("response_hoplimit", 8)
        # The ID of this query.
        query_id = pcs.Field("query_id", 24)

        #...hops?

        pcs.Packet.__init__(self, [group, source, \
                                   receiver, response_addr, \
                                   response_hoplimit, query_id], pdata, **kv)

        self.description = "initialize the MTRACE response header."

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (pdata is not None):
            offset = self.sizeof()
            self.data = payload.payload(pdata[offset:len(pdata)])
        else:
            self.data = None
