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
# Description: Another demo of network-level "expect" functionality.

import pcs
import pcs.packets.ethernet as ethernet
from pcs.packets.ipv4 import *
import pcs.packets.ipv4 as ipv4
from pcs.packets.igmp import *
from pcs.packets.igmpv2 import *
import pcs.packets.igmp as igmp
import pcs.packets.igmpv2 as igmpv2

import sys

def main():

    file = pcs.PcapConnector("fxp0")

    # First, build a chain and use it as a filter to match any IGMPv2 joins
    # seen on the network.
    m = ethernet.ethernet() / ipv4.ipv4() / \
        igmp.igmp(type=IGMP_v2_HOST_MEMBERSHIP_REPORT) / igmpv2.igmpv2()
    t = 50
    print "Waiting %d seconds to see an IGMPv2 report." % t
    try:
        file.expect([m], t)
    except pcs.TimeoutError:
        print "Timed out."
        sys.exit(1)

    # Now try it with a "contains" filter.
    # This will match any packet chain containing an IGMPv2 message.
    c = igmpv2.igmpv2()
    t = 50
    print "Waiting %d seconds to see an IGMPv2 report using 'contains'." % t
    try:
        file.expect([c], t)
    except pcs.TimeoutError:
        print "Timed out."
        sys.exit(1)

    print "And the matching packet chain is:"
    print file.match

    # Define a match function to apply to a field.
    # We could really use some syntactic sugar for this...
    def contains_router_alert(lp, lf, rp, rf):
        for i in rf._options:
            if isinstance(i, pcs.TypeLengthValueField) and \
               i.type.value == IPOPT_RA:
                return True
        return False

    # Create a "contains" filter consisting of a single IPv4 datagram
    # with a "Router Alert" option in the header. Strictly speaking the
    # option isn't needed, as above we define a function which is used
    # as a compare function for the option list field.
    c = ipv4.ipv4(options=[ipv4opt(IPOPT_RA)])
    c.options.compare = contains_router_alert
    t = 50
    print "Waiting %d seconds to see any IP packet containing a Router Alert option." % t
    try:
        file.expect([c], t)
    except pcs.TimeoutError:
        print "Timed out."
        sys.exit(1)

    print "And the matching packet chain is:"
    print file.match

    sys.exit(0)

main()
