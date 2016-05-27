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
# Description: A program using PCS to analyze a tcpdump file and give
# data relateing to whether or not the file shows a DDOS.

import pcs
from pcs.packets.ipv4 import *
from socket import inet_ntoa
import array

def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-i", "--in",
                      dest="infile", default=None,
                      help="pcap file to read from")

    parser.add_option("-o", "--out",
                      dest="outfile", default=None,
                      help="pcap file to write to")

    parser.add_option("-f", "--first",
                      dest="first", default=0, type=int,
                      help="first packet to start at")

    parser.add_option("-l", "--last",
                      dest="last", default=None, type=int,
                      help="last packet to keep")

    (options, args) = parser.parse_args()

    infile = pcs.PcapConnector(options.infile)

    outfile = pcs.PcapDumpConnector(options.outfile, infile.dlink)

    first = options.first
    
    last = options.last

    done = False
    
    packets = 0
    written = 0
    while not done:
        try:
            packet = infile.read()
        except:
            done = True
        packets += 1
        if packets < first:
            continue
        if packets >= last:
            done = True

        outfile.write(packet)
        written +=1 

    print "%d packets copied from %s to %s" % (written,
                                               options.infile,
                                               options.outfile)

main()
