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
# File: $Id: $
#
# Author: George V. Neville-Neil
#
# Description: A program using PCS to analyze a tcpdump file and give
# data relateing to whether or not the file shows a DDOS.

import pcs
from pcs.packets.ipv4 import *
from socket import inet_ntoa, inet_aton, ntohl

def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-f", "--file",
                      dest="file", default=None,
                      help="tcpdump file to read from")

    parser.add_option("-m", "--max",
                      dest="max", default=10, type=int,
                      help="top N addresses to report")

    parser.add_option("-s", "--subnet-mask",
                      dest="mask", default=None,
                      help="subnetmask")

    parser.add_option("-n", "--network",
                      dest="network", default=None,
                      help="network we're looking at")


    (options, args) = parser.parse_args()

    file = pcs.PcapConnector(options.file)

    max = options.max
    
    mask = pcs.inet_atol(options.mask)
    
    network = pcs.inet_atol(options.network)
    done = False
    
    srcmap = {}
    packets = 0
    in_network = 0

    while not done:
        try:
            packet = file.read()
        except:
            done = True
        packets += 1
        ip = ipv4(packet[file.dloff:len(packet)])
        if (ip.src & mask) != network:
            if ip.src in srcmap:
                srcmap[ip.src] += 1
            else:
                srcmap[ip.src] = 1
        else:
            in_network +=1

    print "%d packets in dumpfile" % packets
    print "%d unique source IPs" % len(srcmap)
    print "%d packets in specified network" % in_network
    print "Top %d source addresses were" % max
    hit_list = sorted(srcmap.itervalues(), reverse = True)
    for i in range(1,max):
        for addr in srcmap.items():
            if addr[1] == hit_list[i]:
                print "Address %s\t Count %s\t Percentage %f" % (inet_ntop(AF_INET, struct.pack('!L', addr[0])), addr[1], (float(addr[1]) / float(packets)) * float(100))

main()
