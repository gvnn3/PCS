#!/usr/bin/env python2.6
# Copyright (c) 2009-2016, Neville-Neil Consulting
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
from pcs.packets.ethernet import ethernet
from pcs.packets.ipv4 import ipv4
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
    parser.add_option("-p", "--print", dest="png", default=None,
                      help="print the graph to a file")
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
            except StopIteration:
                done = True
            except:
                raise
                
            # We only handle pcap files with Ethernet or RAW IP
            if type(packet) == ethernet:
                if packet.data == None:
                    continue

                if packet.data.data == None:
                    continue

                if type(packet.data.data) != icmpv4:
                    continue

                icmp = packet.data.data
            
            elif type(packet) == ipv4:
                if type(packet.data) != icmpv4:
                    continue

                icmp = packet.data

            else:
                continue
            
            if type(icmp.data) != icmpv4echo:
                continue

            if icmp.type != ICMP_ECHO:
                continue

            if ((icmp.data.sequence != 0) and
                (icmp.data.sequence < options.start)):
                continue
                
            trace[icmp.data.sequence] = datetime.datetime.fromtimestamp(packet.timestamp)

        files.append(trace)

    sequences = []
    sequences.append(sorted(files[0].keys()))
    sequences.append(sorted(files[1].keys()))
    
    if ((min(sequences[0]) > max(sequences[1])) or
        (min(sequences[1]) > max(sequences[1]))):
        print "sequences do not overlap"
        sys.exit(1)
    
    # Trim the dictionaries of non overlapping elements

    index = 0
    if ((min(sequences[0]) < min(sequences[1]))):
        start = min(sequences[0])
        end = min(sequences[1])
        index = 0
    else:
        start = min(sequences[1])
        end = min(sequences[0])
        index = 1
        
    for i in range(start, end):
        del files[index][i]

    if ((max(sequences[0]) > max(sequences[1]))):
        start = max(sequences[1])
        end = max(sequences[0])
        index = 0
    else:
        start = max(sequences[0])
        end = max(sequences[1])
        index = 1
        
    for i in range(start, end):
        del files[index][i]

    if options.start == 0:
        options.start = min(files[0].keys())

    graph = []

    minimum = datetime.timedelta.max
    maximum = datetime.timedelta.min
    
    for i in range(options.start,options.start + len(files[0])):
        try:
            delta = abs(files[1][i] - files[0][i])
        except KeyError:
            print "9:99:99.000900"
            print "missing packet %d" % i
            continue
            
        if delta > maximum:
            maximum = delta
        if delta < minimum:
            minimum = delta

        if (options.debug != 0):
            print delta
        graph.append(delta.microseconds)

    print "min %s, max %s" % (minimum, maximum)

    if (minimum.seconds > 1):
        print "Time difference exceeded one second maximum, " \
              "cannot graph differences"
        sys.exit(1)
        
    plotter = Gnuplot.Gnuplot(debug=1)

    # if ((options.ymin != 0) or (options.ymax != 10)):
    #     plotter.set_range('yrange', [options.ymin, options.ymax])

    plotter.ylabel('Time Offset\\nMicroseconds')
    plotter.xlabel('Sample Number')
    plotter.plot(graph)

    if (options.png != None):
        plotter.hardcopy(options.png + ".png", terminal='png')
        raw_input('Press return to exit')
    else:
        raw_input('Press return to exit')

# The canonical way to make a python module into a script.
# Remove if unnecessary.
 
if __name__ == "__main__":
    main()
