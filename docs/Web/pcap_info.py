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
# File: $Id: $
#
# Author: George V. Neville-Neil
#
# Description: Walk through an entire pcap dump file and give out
# information along the lines of netstat(1) on FreeBSD.

import pcs
from pcs.packets.udp import *
from pcs.packets.tcp import *
from pcs.packets.ipv4 import *
from pcs.packets.ethernet import *
from pcs.packets.arp import *
from socket import inet_ntoa
def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-f", "--file",
                      dest="file", default=None,
                      help="tcpdump file to read from")

    (options, args) = parser.parse_args()

    file = pcs.PcapConnector(options.file)

    srcmap = {}
    packets = 0
    ip_cnt = 0
    non_ip_cnt = 0
    tcp_cnt = 0
    udp_cnt = 0
    icmp_cnt = 0
    arp_cnt = 0

    done = False
    while not done:
        ip = None
        try:
            packet = file.read()
        except:
            done = True
        packets += 1
        ether = ethernet(packet[0:len(packet)])
        if type(ether.data) == pcs.packets.ipv4.ipv4:
            ip_cnt += 1
            ip = ether.data
        else:
            non_ip_cnt += 1
        if type(ether.data) == pcs.packets.arp.arp:
            arp_cnt += 1

        if ip != None:
            if type(ip.data) == pcs.packets.icmpv4.icmpv4:
                icmp_cnt += 1
            if type(ip.data) == pcs.packets.udp.udp:
                udp_cnt += 1
            if type(ip.data) == pcs.packets.tcp.tcp:
                tcp_cnt += 1

            if ip.src in srcmap:
                srcmap[ip.src] += 1
            else:
                srcmap[ip.src] = 1

    print "%d packets in dumpfile" % packets
    print "%d unique source IPs" % len(srcmap)
    print "%d ARP packets" % arp_cnt
    print "%d IPv4 packets" % ip_cnt
    print "%d ICMPv4 packets" % icmp_cnt
    print "%d UDP packets" % udp_cnt
    print "%d TCP packets" % tcp_cnt

    print "Top 10 source addresses were"
    hit_list = sorted(srcmap.itervalues(), reverse = True)
    for i in range(1,10):
        for addr in srcmap.items():
            if addr[1] == hit_list[i]:
                print "Address %s\t Count %s\t Percentage %f" % (inet_ntop(AF_INET, struct.pack('!L', addr[0])), addr[1], (float(addr[1]) / float(packets)) * float(100))

main()
