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
# File: $Id: dns.py,v 1.4 2006/09/01 07:45:56 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: DNS Packet Class

import pcs

class dnsheader(pcs.Packet):

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """Define the fields of a DNS (RFC 1035) header"""
        length = pcs.Field("length", 16)
        id = pcs.Field("id", 16)
        query = pcs.Field("query", 1)
        opcode = pcs.Field("opcode", 4)
        aa = pcs.Field("aa", 1)
        tc = pcs.Field("tc", 1)
        rd = pcs.Field("rd", 1)
        ra = pcs.Field("ra", 1)
        z = pcs.Field("z", 3, default = 0)
        rcode = pcs.Field("rcode", 4)
        qdcount = pcs.Field("qdcount", 16)
        ancount = pcs.Field("ancount", 16)
        nscount = pcs.Field("nscount", 16)
        arcount = pcs.Field("arcount", 16)
        
        pcs.Packet.__init__(self,
                            [length, id, query, opcode, aa, tc, rd, ra, z,
                             rcode, qdcount, ancount, nscount, arcount],
                            bytes = bytes)

        self.description = "DNS Header"

class dnslabel(pcs.Packet):
    """A DNS Label.""" 

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a DNS label, which is a component of a domain name"""
        name = pcs.LengthValueField("name", 8)
        pcs.Packet.__init__(self,
                            [name],
                            bytes = bytes)
        
        self.description = "DNS Label"

class dnsquery(pcs.Packet):
    """A DNS query class"""

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a DNS query packet, which is a query for information"""
        type = pcs.Field("type", 16)
        qclass = pcs.Field("query_class", 16)
        pcs.Packet.__init__(self,
                            [type, qclass],
                            bytes = bytes)
        
        self.description = "DNS Query"

class dnsrr(pcs.Packet):
    """A DNS Resource Record"""

    layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a DNS resource record, which encodes data returned from a query"""
        name = pcs.LengthValueField("name", 8)
        type = pcs.Field("type", 16)
        qclass = pcs.Field("query_class", 16)
        ttl = pcs.Field("ttl", 16)
        rdata = pcs.LengthValueField("rdata", 16)

        pcs.Packet.__init__(self,
                            [name, type, qclass, ttl, rdata],
                            bytes = bytes)
        
        self.description = "DNS Resource Record"
