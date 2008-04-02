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

import inspect
import time

class dnsheader(pcs.Packet):
    """DNS Header"""
    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, tcp = None):
        """Define the fields of a DNS (RFC 1035) header"""
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
        
        # DNS Headers on TCP require a length but when encoded in UDP do not.
        if (tcp != None):
            length = pcs.Field("length", 16)
            pcs.Packet.__init__(self,
                                [length, id, query, opcode, aa, tc, rd, ra, z,
                                 rcode, qdcount, ancount, nscount, arcount],
                                bytes = bytes)
        else:
            pcs.Packet.__init__(self,
                            [id, query, opcode, aa, tc, rd, ra, z,
                             rcode, qdcount, ancount, nscount, arcount],
                            bytes = bytes)

        self.description = inspect.getdoc(self)
        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

class dnslabel(pcs.Packet):
    """DNS Label""" 

    _layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a DNS label, which is a component of a domain name"""
        name = pcs.LengthValueField("name", 8)
        pcs.Packet.__init__(self,
                            [name],
                            bytes = bytes)
        
        self.description = inspect.getdoc(self)

class dnsquery(pcs.Packet):
    """DNS Query"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a DNS query packet, which is a query for information"""
        type = pcs.Field("type", 16)
        qclass = pcs.Field("query_class", 16)
        pcs.Packet.__init__(self,
                            [type, qclass],
                            bytes = bytes)
        
        self.description = inspect.getdoc(self)

#
# XXX 'name' should actually be a label-or-pointer-sequence.
# Of course there is no way of knowing unless we a) type DNS
# entities to use a different string field, and b) perform
# the compression when we come to encode.
# 'rdata' can contain arbitrary data depending on qclass,
# however, the valid total length of a UDP dns packet is 512 bytes.
#
# Below for now both field contents are limited to 32 bytes ( 2 ** 4 * 8),
# the length fields remain the same as per RFC 1035.
#
class dnsrr(pcs.Packet):
    """DNS Resource Record"""

    _layout = pcs.Layout()

    def __init__(self, bytes = None):
        """initialize a DNS resource record, which encodes data returned from a query"""
        #name = pcs.LengthValueField("name", pcs.Field("", 8),
        #                             pcs.StringField("", (2 ** 8) * 8))
        name = pcs.LengthValueField("name", pcs.Field("", 8),
                                     pcs.StringField("", 2 ** 4 * 8)) # XXX
        type = pcs.Field("type", 16)
        qclass = pcs.Field("query_class", 16)
        ttl = pcs.Field("ttl", 32)
        #rdata = pcs.LengthValueField("rdata", pcs.Field("", 16),
        #                             pcs.StringField("", (2 ** 16) * 8))
        rdata = pcs.LengthValueField("rdata", pcs.Field("", 16),
                                     pcs.StringField("", 2 ** 4 * 8)) # XXX

        pcs.Packet.__init__(self,
                            [name, type, qclass, ttl, rdata],
                            bytes = bytes)
        
        self.description = inspect.getdoc(self)
