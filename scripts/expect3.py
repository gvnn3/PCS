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

    fxp0 = PcapConnector("fxp0")
    #filter = ethernet() / ipv4() / icmpv4(type=ICMP_ECHO) / icmpv4echo()
    # XXX Single packet matches are OK, partial chain matches
    # seem to be broken.

    fxp0.setfilter('icmp')

    print "Waiting 10 seconds to see an ICMP echo request out of 10 packets."
    try:
        fxp0.expect([icmpv4(type=ICMP_ECHO)], 10)
    except LimitReachedError:
        print "Limit reached."
        sys.exit(1)
    except TimeoutError:
        print "Timed out."
        sys.exit(1)

    assert isinstance(fxp0.matches, list), "oops!"

    print "There were %d matches from live capture." % len(fxp0.matches)
    print "And the first matching packet chain is:"
    print fxp0.matches[0]
    sys.exit(0)

main()
