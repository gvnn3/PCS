#!/usr/bin/env python
# Copyright (c) 2013-2016, Neville-Neil Consulting
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
# File: $Id:$
#
# Author: Mike Karels
#
# Description: A simple re-implementation of the ping6(8) program in
# Python using the Packet Construction Set

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv6 import *
from pcs.packets.icmpv6 import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

def main():

    from optparse import OptionParser
    
    parser = OptionParser()
    parser.add_option("-c", "--count",
                      dest="count", default=1,
                      help="Stop after sending (and recieving) count ECHO_RESPONSE packets..")
    
    parser.add_option("-D", "--dont_fragment",
                      dest="df", default=False,
                      help="Set the Don't Fragment bit.")

    parser.add_option("-s", "--ip_source",
                      dest="ip_source", default=None,
                      help="The IP source address.")

    parser.add_option("-d", "--ip_dest",
                      dest="ip_dest", default=None,
                      help="The IP destination address.")

    parser.add_option("-I", "--ether_iface",
                      dest="ether_iface", default=None,
                      help="The name of the source interface.")

    parser.add_option("-e", "--ether_source",
                      dest="ether_source", default=None,
                      help="The host Ethernet source address.")

    parser.add_option("-g", "--ether_dest",
                      dest="ether_dest", default=None,
                      help="The gateway Ethernet destination address.")

    (options, args) = parser.parse_args()
 
    plen = 8 + 6	# 8 for ICMP header, 6 for foobar
    c = ethernet(src=ether_atob(options.ether_source),  \
                 dst=ether_atob(options.ether_dest)) /  \
        ipv6(hop=64, next_header = 58, length = plen, \
                     src=inet_pton(AF_INET6, options.ip_source),  \
                     dst=inet_pton(AF_INET6, options.ip_dest)) / \
        icmpv6(type=ICMP6_ECHO_REQUEST) / \
        icmpv6echo(id=12345) / \
        payload(payload="foobar")

    c.calc_lengths()

    #
    # Increment ICMP echo sequence number with each iteration.
    #
    output = PcapConnector(options.ether_iface)
    ip = c.packets[1]
    icmp = c.packets[2]
    icmpecho = c.packets[3]
    count = int(options.count)
    while (count > 0):
        #c.calc_checksums()
        #icmpecho.cksum = icmpv6.cksum(icmpecho, ip)
        icmp.calc_checksum()
        print icmp

        out = output.write(c.bytes, len(c.bytes))
#        packet = input.read()
#        print packet
        sleep(1)
        count -= 1
        icmpecho.sequence += 1
main()
