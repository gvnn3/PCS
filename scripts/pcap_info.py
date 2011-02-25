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
# Description: Walk through an entire pcap dump file and give out
# information along the lines of netstat(1) on FreeBSD.
#
# This is also used for performance tests on PCS itself by
# using the profiler options.

import cProfile
import time
import datetime
from socket import inet_ntoa

import sys

do_profiling = False


def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-p", "--per-second",
                      dest="ps", default=None,
                      help="generate a graph of packets and bytes per second")
    parser.add_option("-m", "--per-millisecond",
                      dest="ppm", default=None,
                      help="generate a graph of packets and bytes per millisecond")
    parser.add_option("-u", "--per-microsecond",
                      dest="ppu", default=None,
                      help="generate a graph of packets and bytes per microsecond")
    parser.add_option("-P", "--profile",
                      dest="profile", default=False,
                      help="run the code profiler")
    
    (options, args) = parser.parse_args()

    # Files are specified as the remaining arguments.
    for dump_file in args:
        file = pcs.PcapConnector(dump_file)

        srcmap = {}
        packets_per = {}
        packets = 0
        ip_cnt = 0
        non_ip_cnt = 0
        tcp_cnt = 0
        udp_cnt = 0
        icmp_cnt = 0
        arp_cnt = 0
        
        done = False
        while not done:
            try:
                packet = file.readpkt()
            except:
                raise
                done = True

            packets += 1

            network = packet.data

            try:
                transport = network.data
            except:
                pass

            if type(network) == ipv4:
                ip_cnt += 1
                ip = network
            else:
                non_ip_cnt += 1
            if type(packet) == arp:
                arp_cnt += 1

            if type(transport) == icmpv4:
                icmp_cnt += 1
            if type(transport) == udp:
                udp_cnt += 1
            if type(transport) == tcp:
                tcp_cnt += 1

            try:
                srcmap[ip.src] += 1
            except KeyError:
                srcmap[ip.src] = 1

            if options.ps is not None:
                second = int(packet.timestamp)
                try:
                    (count, length) = packets_per[second]
                    count += 1
                    length += len(packet.bytes)
                    packets_per[second] = (count, length)
                except KeyError:
                    packets_per[second] = (1, len(packet.bytes))
            elif options.ppm is not None:
                ts = datetime.datetime.fromtimestamp(packet.timestamp)
                ms = ts.microsecond / 1000
                msecond = ts.strftime("%H:%M:%S")
                msecond += (".%d") % ms
                while (len(msecond) < 12):
                    msecond += '0'
                try:
                    (count, length) = packets_per[msecond]
                    count += 1
                    length += len(packet.bytes)
                    packets_per[msecond] = (count, length)
                except KeyError:
                    packets_per[msecond] = (1, len(packet.bytes))
            elif options.ppu is not None:
                try:
                    (count, length) = packets_per[packet.timestamp]
                    count += 1
                    length += len(packet.bytes)
                    packets_per[packet.timestamp] = (count, length)
                except KeyError:
                    packets_per[packet.timestamp] = (1, len(packet.bytes))
                    

        print "%d packets in dumpfile" % packets
        print "%d unique source IPs" % len(srcmap)
        print "%d ARP packets" % arp_cnt
        print "%d IPv4 packets" % ip_cnt
        print "%d ICMPv4 packets" % icmp_cnt
        print "%d UDP packets" % udp_cnt
        print "%d TCP packets" % tcp_cnt

        print "Top source addresses were"
        hit_list = sorted(srcmap.itervalues(), reverse = True)
        length = len(hit_list)
        for i in xrange(length):
            for addr in srcmap.items():
                if addr[1] == hit_list[i]:
                    print "Address %s\t Count %s\t Percentage %f" % (inet_ntop(AF_INET, struct.pack('!L', addr[0])), addr[1], (float(addr[1]) / float(packets)) * float(100))

        if options.ps is not None:
            try:
                file = open(options.ps, "w")
            except:
                print "Could not open file %s for writing." % options.ps
                        
            for seconds in sorted(packets_per.keys()):
                hms = time.strftime("%H:%M:%S",time.localtime(seconds))
                data = ("%s, %d, %d\n" % (hms, packets_per[seconds][0], packets_per[seconds][1]))
                file.write(data)
        elif options.ppm is not None:
            try:
                file = open(options.ppm, "w")
            except:
                print "Could not open file %s for writing." % options.ppm
                        
            for mseconds in sorted(packets_per.keys()):
                data = ("%s, %d, %d\n" % (mseconds,
                                          packets_per[mseconds][0],
                                          packets_per[mseconds][1]))
                file.write(data)
        elif options.ppu is not None:
            try:
                file = open(options.ppu, "w")
            except:
                print "Could not open file %s for writing." % options.ppu
                        
            for useconds in sorted(packets_per.keys()):
                dt = datetime.datetime.fromtimestamp(useconds)
                data = ("%s, %d, %d\n" % (dt.strftime("%H:%M:%S.%f"),
                                          packets_per[useconds][0],
                                          packets_per[useconds][1]))
                file.write(data)
            
        if do_profiling == True:
            import pstats
            p = pstats.Stats('pcap_info.prof')
            p.sort_stats('name')
            p.print_stats()

            p.sort_stats('cumulative').print_stats(10)

            p.sort_stats('time').print_stats(10)


if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.
    import pcs
    from pcs import PcapConnector
    from pcs.packets.udp import *
    from pcs.packets.tcp import *
    from pcs.packets.ipv4 import *
    from pcs.packets.icmpv4 import *
    from pcs.packets.ethernet import *
    from pcs.packets.arp import *

    # Are we profiling?
    if "-P" in sys.argv:
        sys.argv.remove("-P") 
        do_profiling = True
        cProfile.run('main()', "pcap_info.prof")
    else:
        main()
