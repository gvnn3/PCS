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
# Description: A class which describe IGMPv1/v2 messages.
#

import pcs
import struct
import time

from pcs.packets import payload
from socket import AF_INET, inet_ntop, inet_ntoa

#
# IGMP protocol defaults.
#
IGMP_MAX_HOST_REPORT_DELAY = 10

class igmpv2(pcs.Packet):
    """IGMPv1/v2 message."""

    layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize an IGMPv1/v2 header"""
        group = pcs.Field("group", 32)
        pcs.Packet.__init__(self, [group], bytes, **kv)
        self.description = "initialize an IGMPv1/v2 header"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            self.data = payload.payload(bytes[offset:len(bytes)])
        else:
            self.data = None

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        return "group %s\n" % inet_ntop(AF_INET, struct.pack('!L', self.group))
