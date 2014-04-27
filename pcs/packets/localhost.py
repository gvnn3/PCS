# Copyright (c) 2006, Neville-Neil Consulting
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
# File: $Id: localhost.py,v 1.1 2006/07/04 13:30:10 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A packet to handle localhost encoded tcpdump packets.

import socket
import pcs
from pcs.packets import ipv4
from pcs.packets import ipv6

from . import localhost_map

import time

class localhost(pcs.Packet):
    """Localhost"""
    _layout = pcs.Layout()
    _map = localhost_map.map

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize a localhost header, needed to read or write to lo0"""
        type = pcs.Field("type", 32, discriminator=True)
        lolen = 4

        pcs.Packet.__init__(self, [type], bytes = bytes, **kv)
        self.description = "Localhost"
        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (bytes is not None):
            self.data = self.next(bytes[lolen:len(bytes)],
                                  timestamp = timestamp)
        else:
            self.data = None

