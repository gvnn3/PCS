# Copyright (c) 2005, Neville-Neil Consulting
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
# File: $Id: ipsec.py,v 1.5 2006/06/27 14:45:43 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: This module contains classes which implement the IPSec
# protocols, both ESP and AH.

import pcs

class ah(pcs.Packet):
    """IP Authentication Header (AH), from RFC 2402"""

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize an AH packet header"""
        next = pcs.Field("next_header", 8)
        plen = pcs.Field("payload_len", 8)
        rsvrd = pcs.Field("reserved", 16)
        spi = pcs.Field("SPI", 32)
        seq = pcs.Field("sequence", 32)
        auth = pcs.Field("auth_data", 128)
        pcs.Packet.__init__(self,
                            [next, plen, rsvrd, spi, seq, auth],
                            bytes)
        self.description = "AH"
        
class esp(pcs.Packet):
    """IP Encapsulating Security Payload (ESP) Packet from RFC 2406"""

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize an ESP packet header"""
        spi = pcs.Field("spi", 32)
        seq = pcs.Field("sequence", 32)
        payload = pcs.Field("payload", 32)
        padding = pcs.Field("padding", 32)
        padlen = pcs.Field("pad_length", 8)
        next_header = ("next_header", 8)
        auth = pcs.Field("auth_data", 128)
        pcs.Packet.__init__(self,
                            [spi, seq, payload, padding, padlen, next_header,
                             auth],
                            bytes)
        self.description = "ESP"
