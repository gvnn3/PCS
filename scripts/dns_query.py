#!/usr/bin/env python
# Copyright (c) 2006-2016, Neville-Neil Consulting
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
# File: $Id: dns_query.py,v 1.3 2006/09/01 07:45:56 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description:  A PCS demo script that performs a simple DNS lookup.

import pcs
from pcs import *
from pcs.packets.dns import *

def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-a", "--address",
                      dest="addr", default=None,
                      help="Address of the domain name server.")
    parser.add_option("-u", "--udp",
                      dest="udp", default=None,
                      help="Use UDP instead of TCP.")
    
    
    (options, args) = parser.parse_args()

    if options.udp is not None:
        conn = UDP4Connector(options.addr, 53)
    else:
        conn = TCP4Connector(options.addr, 53)

    if (options.udp is None):
        header = dnsheader(tcp = True)
    else:
        header = dnsheader()

    header.id = 1
    header.rd = 1
    header.qdcount = 1

    query = dnsquery()
    query.type = 1
    query.query_class = 1

    lab1 = dnslabel()
    lab1.name = "www"

    lab2 = dnslabel()
    lab2.name = "neville-neil"

    lab3 = dnslabel()
    lab3.name = "com"

    lab4 = dnslabel()
    lab4.name = ""

    packet = Chain([header, lab1, lab2, lab3, lab4, query])

    if options.udp is None:
        header.length = 38
        packet = Chain([header, lab1, lab2, lab3, lab4, query])

    print packet
    print packet.bytes
    print len(packet.bytes)

    conn.write(packet.bytes)

    retval = conn.read(1024)

    print len(retval)
    print dnsheader(retval)

    conn.close()
    
main()

