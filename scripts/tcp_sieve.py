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
# Description: A program using PCS to analyze a pcap file and 
# split out all TCP conversations into their own file.

"""
tcp_sieve.py

A program using PCS to analyze a pcap file and split out all TCP
conversations into their own files.

-f, --file: pcap file to read from

Each conversation is broken out into a separate file, named with the
IP source and destination address as well as the source and
destination port.

Example

Using this command on our test file:

./tcp_sieve.py  -f 10000packets.out

generates the following separate files:

tcp-192.168.1.119-49707-119.31.250.52-80.pcap
tcp-93.184.216.229-80-192.168.1.119-49706.pcap
tcp-192.168.1.119-49706-93.184.216.229-80.pcap
tcp-72.14.204.103-80-192.168.1.119-49705.pcap
tcp-66.102.13.100-80-192.168.1.119-49704.pcap
tcp-192.168.1.119-49705-72.14.204.103-80.pcap
tcp-72.14.204.104-80-192.168.1.119-49703.pcap
tcp-192.168.1.119-49704-66.102.13.100-80.pcap
tcp-192.168.1.119-49703-72.14.204.104-80.pcap

etc.

See Also
PCS, tcp_streams.py

"""
import pcs
from pcs.packets.ipv4 import *
from socket import inet_ntoa, inet_aton, ntohl,  IPPROTO_TCP
import signal

def progress(signum, frame):
    """A signal handler so we can see how far we've gotten
    through the file."""
    global packets
    print "Processed %d packets" % packets
    
def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-f", "--file",
                      dest="file", default=None,
                      help="pcap file to read from")

    (options, args) = parser.parse_args()

    file = pcs.PcapConnector(options.file)

    done = False
    data = None
    timestamp = None

    connection_map = {}
    in_network = 0

    win_prev = 0
    
    # Set up our signal handler
    global packets
    packets = 0
    signal.signal(signal.SIGINFO, progress)
    
    while not done:
        try:
            (timestamp, data) = file.next()
        except:
            done = True

        packet = file.unpack(data, file.dlink, file.dloff, timestamp)
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

        if (quad not in connection_map):
            outfile = 'tcp-' + quad[0] + '-' + repr(quad[2]) + '-' +\
                      quad[1] + '-' + repr(quad[3]) + '.pcap'
            connection_map[quad] = pcs.PcapDumpConnector(outfile, file.dlink)

        connection_map[quad].write(data)

# The canonical way to make a python module into a script.
# Remove if unnecessary.
 
if __name__ == "__main__":
    main()
