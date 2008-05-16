#!/usr/bin/env python
# Copyright (c) 2008, Bruce M. Simpson.
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
# Neither the names of the authors nor the names of contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
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
# Author: Bruce M. Simpson
#
# Description: Simple demo of network-level "expect" functionality.

import pcs
from pcs.packets.udp import *
from pcs.packets.tcp import *
from pcs.packets.ipv4 import *
from pcs.packets.ethernet import *
from pcs.packets.arp import *
import pcs.packets.ethernet as ethernet
import pcs.packets.arp as arp

import sys

def main():

    file = pcs.PcapConnector("fxp0")

    # Construct a filter chain. we are only interested in 3 fields.
    # The new scapy style syntax makes this easy.
    # If a field in a packet is not explicitly initialized by the user,
    # and that packet is later used as a match filter by expect,
    # it will be ignored. Otherwise the default filtering behaviour is
    # to make an exact match, unless you install a different comparison
    # function.
    # Comparison functions are specified on a per-field basis. They are
    # passed the packet(s) being compared so that back-references
    # to fields are possible e.g. for figuring out that an ARP packet
    # is gratuitous ARP for example. The lambda operator will let you
    # do all this in one statement.

    a = ethernet.ethernet(type=0x806) / arp.arp(pro=0x0800, op=1)

    # Old-style syntax.
    #a.wildcard_mask()
    #a.packets[0].wildcard_mask(["type"], False)
    #a.packets[1].wildcard_mask(["pro", "op"], False)
    #a.packets[1].pro = 0x0800	# ETHERTYPE_IP (default)
    #a.packets[1].op = 1		# ARPOP_REQUEST

    print "Waiting 10 seconds to see an ARP query."
    try:
        file.expect([a], 10)
    except pcs.TimeoutError:
        print "Timed out."
        sys.exit(1)

    print "And the matching packet chain is:"
    print file.match
    sys.exit(0)

    #  TODO: Add the ability to match more complex filters
    #        e.g. ar_spa == ar_tpa which is gratuitous arp.

main()
