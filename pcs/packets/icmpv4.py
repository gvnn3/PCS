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
# File: $Id: icmpv4.py,v 1.7 2006/09/05 07:30:56 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class which describes an ICMPv4 packet

import pcs
from pcs.packets import payload

class icmpv4(pcs.Packet):
    """ICMPv4 Packet

    Internet Control Message Protocol (RFC 792) packet.  This is the
    most generic version and contains only a type, code, and checksum
    field.  It is not generally useful without other information.
    """

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a ICMPv4 packet"""
        type = pcs.Field("type", 8)
        code = pcs.Field("code", 8)
        cksum = pcs.Field("checksum", 16)
        pcs.Packet.__init__(self, [type, code, cksum], bytes)
        self.description = "ICMPv4"

        if (bytes != None):
            offset = type.width + code.width + cksum.width
            self.data = payload.payload(bytes[offset:len(bytes)])
        else:
            self.data = None


class icmpv4echo(pcs.Packet):
    """ICMPv4 Echo (aka ping) Packet

    This packet has sufficient fields to form an ICMPv4 echo packet
    also known as a 'ping' due to the name of the program that most
    often uses it.

    Echo packets contain all the fields of an ICMPv4 packet plus an id
    and sequence field.
    """

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize an ICMPv4 echo packet, used by ping(8) and others"""
        id = pcs.Field("id", 16)
        seq = pcs.Field("sequence", 16)
        pcs.Packet.__init__(self, [id, seq], bytes)
        self.description = "ICMPv4 Echo"

        if (bytes != None):
            offset = id.width + seq.width
            self.data = payload.payload(bytes[offset:len(bytes)])
        else:
            self.data = None

