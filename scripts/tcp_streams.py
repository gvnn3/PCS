#!/usr/bin/env python
# Copyright (c) 2011, Neville-Neil Consulting
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
# Author: George V. Neville-Neil
#
# Description: A program using PCS to analyze a tcpdump file and 
# list all the available TCP streams in it.

import pcs
from pcs.packets.ipv4 import *
from socket import inet_ntoa, inet_aton, ntohl,  IPPROTO_TCP

def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-f", "--file",
                      dest="file", default=None,
                      help="tcpdump file to read from")

    parser.add_option("-s", "--streams",
                      dest="streams", default=False,
                      help="print out streams in format easily consumed by other scripts")

    (options, args) = parser.parse_args()

    file = pcs.PcapConnector(options.file)

    done = False
    
    connection_map = []
    packets = 0
    in_network = 0

    win_prev = 0
    
    while not done:
        try:
            packet = file.readpkt()
        except:
            done = True
        packets += 1

        if (packet.type != 0x800):
            continue
        
        ip = packet.data
        if (ip.protocol != IPPROTO_TCP):
            continue

        tcp = ip.data
        quad = (inet_ntop(AF_INET, struct.pack('!L', ip.src)),
                inet_ntop(AF_INET, struct.pack('!L', ip.dst)),
                tcp.sport, tcp.dport)

        if (quad in connection_map):
            continue
        
        connection_map.append(quad)

    print "Analyzed %d packets, found %d connections:" % (packets,
                                                          len(connection_map))
    for connection in connection_map:
        if (options.streams):
            print "-s %s -S %d -d %s -D %d" % (connection[0],
                                               connection[2],
                                               connection[1],
                                               connection[3])
        else:
            print connection


# The canonical way to make a python module into a script.
# Remove if unnecessary.
 
if __name__ == "__main__":
    main()
