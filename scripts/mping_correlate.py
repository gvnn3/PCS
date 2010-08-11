#!/usr/bin/env python2.6
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
# inter machine clock offsets.  Since the kernel timestamps a packet
# relatively close to the hardware it should give us a reasonably
# accurate measurement.  This is ONLY valid on a single subnet.


import sys
import datetime

from numpy import *

import Gnuplot, Gnuplot.funcutils

import pcs
from pcs.clock import TimeSpec
from pcs.packets.icmpv4 import ICMP_ECHO
from pcs.packets.icmpv4 import icmpv4
from pcs.packets.icmpv4 import icmpv4echo

def main():

    from optparse import OptionParser
    
    parser = OptionParser()
    parser.add_option("-y", "--ymin", dest="ymin", default="0",
                      help="minimum y value")
    parser.add_option("-Y", "--ymax", dest="ymax", default="10",
                      help="maximum y value")
    parser.add_option("-N", "--Names", dest="hosts", nargs=2, default=None,
                      help="host list for sync graph")
    parser.add_option("-s", "--start", dest="start", type="int", default=0,
                      help="starting sequence number")
    parser.add_option("-d", "--debug", dest="debug", type="int", default=0,
                      help="print debugging info (verbose)")
    (options, args) = parser.parse_args()
    
    files = []
    for filename in options.hosts:
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

            if ((icmp.data.sequence != 0) and
                (icmp.data.sequence < options.start)):
                continue
                
            trace[icmp.data.sequence] = datetime.datetime.fromtimestamp(packet.timestamp)

        files.append(trace)

    # Set up the plotter so that either the sync or the other types
    # of graphs can use it.
    plotter = Gnuplot.Gnuplot(debug=1)
#    plotter('set data style dots')
    plotter.set_range('yrange', [options.ymin, options.ymax])
    graph = []

    for i in range(options.start,options.start + len(files[0])):
        try:
            delta = abs(files[1][i] - files[0][i])
        except KeyError:
            print "9:99:99.000900"
            print "missing packet %d" % i
            continue
            
        if (options.debug != 0):
            print delta
        graph.append(delta.microseconds)

    plotter.plot(graph)

    raw_input('Press return to exit')

# The canonical way to make a python module into a script.
# Remove if unnecessary.
 
if __name__ == "__main__":
    main()
