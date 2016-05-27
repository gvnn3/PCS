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
# File: $Id: arpwhohas.py,v 1.1 2006/09/08 07:15:26 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A simple program to send ARP requests and replies.

import sys
sys.path.insert(0, "..") # Look locally first

import pcs
from pcs import *
from pcs.packets.arp import *
from pcs.packets.ethernet import *

def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-i", "--interface",
                      dest="interface", default=None,
                      help="Network interface to send on.")

    parser.add_option("-t", "--target",
                      dest="target", default=None,
                      help="IPv4 target address to lookup.")
    
    parser.add_option("-e", "--ether_source",
                      dest="ether_source", default=None,
                      help="Ethernet source address to use.")
    
    parser.add_option("-p", "--ip_source",
                      dest="ip_source", default=None,
                      help="IPv4 source address to use.")
    
    (options, args) = parser.parse_args()

    arppkt = arp()
    arppkt.op = 1
    arppkt.sha = ether_atob(options.ether_source)
    arppkt.spa = inet_atol(options.ip_source)
    arppkt.tha = "\x00\x00\x00\00\x00\x00"
    arppkt.tpa = inet_atol(options.target)

    ether = ethernet()
    ether.src = ether_atob(options.ether_source)
    ether.dst = "\xff\xff\xff\xff\xff\xff"
    ether.type = 0x806

    packet = Chain([ether, arppkt])
    
    output = PcapConnector(options.interface)

    out = output.write(packet.bytes, len(packet.bytes))

    reply = output.read()
    reply = output.read()

    packet = ethernet(reply)
    print packet
    print packet.data

main()
