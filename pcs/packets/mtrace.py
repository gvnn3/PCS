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
# TODO: Add response description which requires a list field.
# Responses MUST Contain the mtrace header, and 0..N response tuples.
#

import pcs
import struct
import time

from pcs.packets import payload
from pcs.igmpv2 import *
from socket import AF_INET, inet_ntop, inet_ntoa

#
# IGMP message types which are used by MTRACE (pre-v2).
#
IGMP_MTRACE_REPLY = 0x1e
IGMP_MTRACE_QUERY = 0x1f

class mtrace_query(pcs.Packet):
    layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None):
        """initialize the MTRACE query/response header."""
	type = pcs.Field("type", 8)
        hops = pcs.Field("hops", 8)
        cksum = pcs.Field("checksum", 16)
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

	# TODO: Add List of 0 (if QUERY) or 1..N (if RESPONSE) tuples here.

        pcs.Packet.__init__(self, [type, hops, cksum, group, source, \
				   receiver, response_addr, \
				   response_hoplimit, query_id], bytes)

        self.description = "MTRACE"

        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (bytes != None):
            offset = type.width + hops.width + cksum.width + group.width + \
		     source.width + receiver.width + response_addr.width + \
		     response_hoplimit.width + query_id.width
            self.data = payload.payload(bytes[offset:len(bytes)])
        else:
            self.data = None
