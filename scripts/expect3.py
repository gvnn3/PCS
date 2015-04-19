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

import sys

def main():
    from pcs import PcapConnector, TimeoutError, LimitReachedError
    from pcs.packets.ethernet import ethernet
    from pcs.packets.ipv4 import ipv4
    from pcs.packets.icmpv4 import icmpv4
    from pcs.packets.icmpv4 import icmpv4echo
    from pcs.packets.icmpv4 import ICMP_ECHO
    #from pcs.packets.icmpv4 import ICMP_ECHOREPLY

    fxp0 = PcapConnector("fxp0")
    filter = ethernet() / ipv4() / icmpv4(type=ICMP_ECHO) / icmpv4echo()

    #from pcs.bpf import program
    #bp = fxp0.make_bpf_program(filter)
    #for lp in bp.disassemble():
    #    print lp

    #fxp0.setfilter('icmp')
    #fxp0.set_bpf_program(bp)

    print("Expecting at least 1 ICMP echo request within 10 seconds.")
    try:
        fxp0.expect([filter], 10)
    except LimitReachedError:
        print("Limit reached.")
        sys.exit(1)
    except TimeoutError:
        print("Timed out.")
        sys.exit(1)

    nmatches = 0
    if fxp0.matches is not None:
        nmatches = len(fxp0.matches)
    print("Matched", nmatches, "chain(s).")

    sys.exit(0)

main()
