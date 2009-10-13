#!/usr/bin/env python
# Copyright (c) 2009, Neville-Neil Consulting
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
# Description: This program reads a set of N pcap files and attempts
# to correlate multicast ping packet arrival times as way of measuring
# inter machien clock offsets.  Since the kernel timestamps a packet
# relatively close to the hardware it should give us a reasonably
# accurate measurement.  This is ONLY valid on a single subnet.


import sys
import datetime

import pcs
from pcs.clock import TimeSpec
from pcs.packets.icmpv4 import ICMP_ECHO
from pcs.packets.icmpv4 import icmpv4
from pcs.packets.icmpv4 import icmpv4echo

def main():

    # Right now there are no command line arguments
    # we just open every file we're given
    # and read the packets from it.

    files = []
    for filename in sys.argv[1:]:
        pcap = pcs.PcapConnector(filename)
        
        trace = {}
        done = False
        while not done:
            try:
                packet = pcap.readpkt()
            except:
                done = True

            if packet.data == None:
                continue

            if packet.data.data == None:
                continue

            if type(packet.data.data) != icmpv4:
                continue

            icmp = packet.data.data
            
            if type(icmp.data) != icmpv4echo:
                continue

            if icmp.type != ICMP_ECHO:
                continue

            trace[icmp.data.sequence] = datetime.datetime.fromtimestamp(packet.timestamp)

        files.append(trace)

    for i in range(0,len(files[0])):
        try:
            if files[0][i] == files[1][i]:
                print "0:00:00.000000"
                continue
        except KeyError:
            print "missing packet %d" % i
            continue
        if files[0][i] < files[1][i]:
            print files[1][i] - files[0][i]
        else:
            print files[0][i] - files[1][i]
            

# The canonical way to make a python module into a script.
# Remove if unnecessary.
 
if __name__ == "__main__":
    main()
