#!/usr/bin/env python2.6
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
# Description: A program using PCS to analyze a tcpdump file and flag
# when the window size changes.

import pcs
from pcs.packets.ipv4 import *
from socket import inet_ntoa, inet_aton, ntohl,  IPPROTO_TCP

import tempfile
from numpy import *

import Gnuplot, Gnuplot.funcutils

def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-f", "--file",
                      dest="file", default=None,
                      help="tcpdump file to read from")

    parser.add_option("-m", "--max",
                      dest="max", default=10, type=int,
                      help="top N addresses to report")

    parser.add_option("-s", "--source",
                      dest="source", default=None, type=str,
                      help="source IP address")

    parser.add_option("-d", "--dest",
                      dest="dest", default=None, type=str,
                      help="destination IP address")

    parser.add_option("-S", "--sport",
                      dest="sport", default=None, type=int,
                      help="source TCP port")

    parser.add_option("-D", "--dport",
                      dest="dport", default=None, type=int,
                      help="destination TCP port")

    parser.add_option("-g", "--graph",
                      dest="graph", default="graph", 
                      help="graph the window size changes over time")

    parser.add_option("-B", "--batch",
                      dest="batch", default=False,
                      help="create PNG graphs but do not display them")

    parser.add_option("-G", "--debug",
                      dest="debug", default=0,
                      help="debug gnuplot")


    (options, args) = parser.parse_args()

    file = pcs.PcapConnector(options.file)

    max = options.max
    
    source = pcs.inet_atol(options.source)
    
    dest = pcs.inet_atol(options.dest)

    done = False
    packets = 0
    win_prev = 0
    

    if (options.graph != None):
        tmpfile = tempfile.NamedTemporaryFile()
        plotter = Gnuplot.Gnuplot(debug=options.debug)
        
        plotter.xlabel('Packet #')
        plotter.ylabel('Window Size')
        

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
        if (ip.src != source):
            continue
        if (ip.dst != dest):
            continue

        tcp = ip.data
        if (tcp.sport != options.sport):
            continue
        if (tcp.dport != options.dport):
            continue
        
        if (win_prev == 0):
            win_prev = tcp.window
        elif (win_prev != tcp.window):
            if (options.graph):
                tmpfile.write("%s %s\n" % (packets, tcp.window))
            else:
                print "Window size changed to %d at %d" % (tcp.window, packets)

            win_prev = tcp.window

    if (options.graph != None):
        
        if (options.batch != False):
            plotter('set terminal png')
            plotter('set output "' + options.graph + ".png")
            
        tmpfile.flush()

        plotter.plot(Gnuplot.File(tmpfile.name))

        if (options.batch == False):
            raw_input('Press return to exit')
        else:
            time.sleep(1)
        
# The canonical way to make a python module into a script.
# Remove if unnecessary.
 
if __name__ == "__main__":
    main()
