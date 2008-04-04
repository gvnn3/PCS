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
# Description: A class which describes DVMRP messages, as encapsulated
# inside the payload of an IGMP type 0x13 message.
#

import inspect
import pcs
import struct
import time

from pcs.packets import payload
from pcs.packets.igmpv2 import *
from socket import AF_INET, inet_ntop, inet_ntoa

#
# DVMRP message types.
#
# The original DVMRP is specified in RFC 1075. The additional message
# types used for mtrace/mrinfo are described in draft-ietf-idmr-dvmrp-v3.
#
DVMRP_NULL = 0
DVMRP_PROBE = 1
DVMRP_REPORT = 2
DVMRP_ASK_NEIGHBORS = 3
DVMRP_NEIGHBORS = 4
DVMRP_ASK_NEIGHBORS2 = 5
DVMRP_NEIGHBORS2 = 6
DVMRP_PRUNE = 7
DVMRP_GRAFT = 8
DVMRP_GRAFT_ACK = 9
DVMRP_INFO_REQUEST = 10
DVMRP_INFO_REPLY = 11

DVMRP_CAP_LEAF		= 0x01	# This DVMRP peer is a leaf.
DVMRP_CAP_PRUNE		= 0x02	# This DVMRP peer understands pruning.
DVMRP_CAP_GENID		= 0x04	# This DVMRP peer sends Generation IDs.
DVMRP_CAP_MTRACE	= 0x08	# This DVMRP peer understands MTRACE.
DVMRP_CAP_SNMP		= 0x10	# This DVMRP peer supports the DVMRP MIB.

# Default mask advertised by the Xerox PARC mrouted code.
DVMRP_CAP_DEFAULT	= (DVMRP_CAP_PRUNE | \
			   DVMRP_CAP_GENID | \
			   DVMRP_CAP_MTRACE )

class dvmrp(pcs.Packet):
    """DVMRP message, as defined in RFC 1075."""

    layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None):
        """initialize a header very similar to that of IGMPv1/v2"""
	reserved00 = pcs.Field("reserved00", 8)
	capabilities = pcs.Field("capabilities", 8)
	minor = pcs.Field("minor", 8)
	major = pcs.Field("major", 8)
	options = pcs.OptionListField("options")
        pcs.Packet.__init__(self, [reserved00, capabilities,
				   minor, major, options], bytes)

        self.description = inspect.getdoc(self)

        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

	# XXX optional bytes not processed yet.

        if bytes != None:
            offset = self.sizeof()
            self.data = payload.payload(bytes[offset:len(bytes)])
        else:
            self.data = None
