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
# File: $Id: dhcpv4.py,v 1.4 2006/06/27 14:45:43 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description:  A class implementing a DHCPv4 packet
#

import pcs

class dhcpv4(pcs.Packet):

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a DHCPv4 packet"""
        op = pcs.Field("op", 8)
        htype = pcs.Field("htype", 8)
        hlen = pcs.Field("hlen", 8)
        hops = pcs.Field("hops", 8)
        xid = pcs.Field("xid", 32)
        secs = pcs.Field("secs", 16)
        flags = pcs.Field("flags", 16)
        ciaddr = pcs.Field("ciaddr", 32)
        yiaddr = pcs.Field("yiaddr", 32)
        siaddr = pcs.Field("siaddr", 32)
        giaddr = pcs.Field("giaddr", 32)
        chaddr = pcs.Field("chaddr", 16 * 8)
        sname = pcs.Field("sname", 64 * 8)
        file = pcs.Field("file", 128 * 8)
        options = pcs.Field("options", 128 * 8)
        pcs.Packet.__init__(self,
                            [op, htype, hlen, hops, xid, secs, flags,
                             ciaddr, yiaddr, siaddr, giaddr, sname, file,
                             options],
                            bytes)
        self.description = "DHCPv4"
            
        
