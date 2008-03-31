#!/usr/bin/env python
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
# File: $Id: ping.py,v 1.3 2006/09/05 07:30:56 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A simple re-implementatoin of the ping(8) program in
# Python using the Packet Construction Set

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.icmpv4 import *
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
    
    # Set up the vanilla packet
    ether = ethernet()
    ether.type = 0x0800
    ether.src = ether_atob(options.ether_source)
    ether.dst = ether_atob(options.ether_dest)

    ip = ipv4()
    ip.version = 4
    ip.hlen = 5
    ip.tos = 0
    ip.id = 0
    ip.flags = 0
    ip.offset = 0
    ip.ttl = 64
    ip.protocol = IPPROTO_ICMP
    ip.src = inet_atol(options.ip_source)
    ip.dst = inet_atol(options.ip_dest)
    
    icmp = icmpv4()
    icmp.type = 8
    icmp.code = 0
    
    echo = icmpv4echo()
    echo.id = 12345
    echo.sequence = 0
    
    data = payload("foobar")
    icmp_packet = Chain([icmp, echo, data])
    ip.length = len(ip.bytes) + len(icmp.bytes) + len(echo.bytes) + len(data.bytes) 

    packet = Chain([ether, ip, icmp, echo, data])
    
    output = PcapConnector(options.ether_iface)

    #input = PcapConnector(options.ether_iface)
    #input.setfilter("icmp")

    #
    # Increment ICMP echo sequence number with each iteration.
    #
    count = int(options.count)
    while (count > 0):
        icmp.checksum = icmp_packet.calc_checksum()
        ip.checksum = ip.calc_checksum()
        packet.encode()
        out = output.write(packet.bytes, len(packet.bytes))
#        packet = input.read()
#        print packet
        sleep(1)
        count -= 1
        ip.id += 1
        echo.sequence += 1
main()
