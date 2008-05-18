# Copyright (c) 2008, Bruce M. Simpson
#
# All rights reserved.
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
# File: $Id$
#
# Author: Bruce M. Simpson
#
# Description: IPv4 Segmentation and Reassembly (SAR) module

import pcs
import payload

class ipv4frag(pcs.packets.payload):
    """A fragment of an IPv4 datagram awaiting reassembly."""

class ipv4sar(object):
    """An IPv4 reassembler."""

    def __init__(self):
        """Construct an ipv4sar object."""
        self.flows = {}

    def reassemble(self, chain, index = None):
        """Attempt to reassemble an IP datagram.

           chain - an IPv4 datagram which may need reassembly.
           index - a hint to the location of the IPv4 header in the chain,
                   otherwise this method looks for the first IPv4 header.

           This method accepts datagrams which don't need reassembly,
           to make it easy to use the reassembler in an expect() loop.
           In that case we just return the datagram.

           Returns a tuple of (chain, num, flushed).
           chain - the reassembled chain, or None if no reassembly done.
           num - the number of fragments used to produce chain
           flushed - the number of fragments garbage collected this pass."""

        # Perform garbage collection pass.
        gc = self.garbage_collect()

        # Locate the IPv4 header in the chain.
        ip = None
        if index is not None:
            ip = chain.packets[index]
            assert isinstance(ip, pcs.packets.ipv4), \
                   "No IPv4 header present in chain."
        else:
            ip = chain.find_first_of(pcs.packets.ipv4)
            assert ip != None, "No IPv4 header present in chain."

        # If packet is DF or no more fragments expected, don't do anything.
        if (ip.ip_flags & IP_DF):
            return (None, 0, gc)
        if not (ip.ip_flags & IP_MF) and ip.ip_off == 0:
            return (None, 0, gc)

        # Look for this datagram in reassembly queue.
        # If not found, create a new ipv4frag from the payload
        # and create a new queue for this datagram.
        # XXX need to keep old IP header around.
        flowtuple = (ip.id, ip.protocol, ip.src, ip.dst)
        if not flowtuple in self.flows:
            payload = chain.collate_following(ip)
            self.flows[flowtuple] = [ ipv4frag(payload) ]
            return (None, 0, gc)

        # We need to walk the reassembly queue and check we have
        # enough fragments.
        # XXX ordered collections?

        assert False, "Unfinished code."
        return (None, 0, gc)

    def garbage_collect(self):
        """Garbage collect any old entries in the reassembly queue.
           Return the number of fragments """
        return 0

    def ipopt_copied(optno):
        """Given an IPv4 option number, return True if it should be copied
           into any fragments beyond the first fragment of a datagram."""
        return (optno & 0x80) != 0

    def make_fragment_header(ip):
        """Given an IPv4 header possibly with options, return a copy of the
           header which should be used for subsequent fragments."""
        from copy import deepcopy
        # We work on the object representation, NOT the bytes themselves here.
        oldopts = ip.options._options
        newopts = []
        optlen = 0         # in bits
        for opt in nip.options._options:
            # Skip EOLs and NOPs.
            # XXX May break legacy multicast tunnel LSRR alignment.
            if isinstance(opt, pcs.Field):
                continue
            assert isinstance(opt, pcs.TypeLengthValueField)
            if ipopt_copied(opt.type.value):
                newopts.append(opt)
            optlen += opt.width
        # Align options to 32 bits.
        assert optlen <= 44, "IPv4 option space cannot exceed 44 bytes."
        remaining = optlen % 32
        while remaining > 0:
            newopts.append(pcs.Field("eol", 8, default=IPOPT_EOL))
        nip = deepcopy(ip)
        nip.options._options = newopts
        nip.encode()
        assert len(nip.getbytes()) <= 64, "IPv4 header cannot exceed 64 bytes."
        return nip

    def fragment(chain, mtu, index = None):
        """Static method to: fragment a Chain containing an IPv4 header
           and payload to fit into the given MTU.
           It is assumed the caller already accounted for any outer
           encapsulation. The ip_off and flags in chain are ignored.
           Length fields and checksums are NOT calculated.

           index - points to IPv4 header in chain (optional)
           return: a list of Chains containing the fragments, or
                   None if ip had the DF bit set."""

        # Locate the IPv4 header in the chain.
        ip = None
        if index is not None:
            ip = chain.packets[index]
            assert isinstance(ip, pcs.packets.ipv4), \
                   "No IPv4 header present in chain."
        else:
            ip = chain.find_first_of(pcs.packets.ipv4)
            assert ip != None, "No IPv4 header present in chain."

        # If DF is set, game over.
        if ip.ip_flags & IP_DF:
            return None

        # Collate the payload to be fragmented and calculate its length.
        tmpbytes = chain.collate_following(ip)
        remaining = len(tmpbytes)

        # If existing IP header and payload fit within MTU, no need to
        # do any further work. Otherwise we must fragment it. This
        # doesn't take the headers in front into account, so we'll
        # assume the caller did.
        if mtu >= len(ip.getbytes()) + remaining:
            return [chain]

        # Take a deep copy of the IP header, and construct the
        # fragmentation headers.
        from copy import deepcopy
        fip = deepcopy(ip)		# first IP fragment header
        fip.ip_flags = IP_MF
        assert (len(fip.getbytes()) % 4) == 0, \
               "First IPv4 fragment header not on 4-byte boundary."

        sip = make_fragment_header(fip)	# template IP fragment header
        sip.ip_flags = IP_MF
        assert (len(fip.getbytes()) % 4) == 0, \
               "Subsequent IPv4 fragment header not on 4-byte boundary."

        result = []			# The fragments w/o other headers.

        # The first fragment needs to be calculated separately as it
        # may have a different set of IP options.
        off = 0
        rmtu = mtu - len(fip.getbytes())
        assert rmtu >= 8, "Insufficient MTU for first IPv4 fragment."
        rmtu -= rmtu % 8

        fip.ip_off = 0
        result.append(Chain([fip, ipv4frag(bytes=tmpbytes[:rmtu])]))
        off += rmtu
        remaining -= rmtu

        # Subsequent fragments use a template header. The minimum length
        # of a fragment's payload is 8 bytes. ip_off measures 64-bit words,
        # so each fragment must be on an 8-byte boundary.
        rmtu = mtu - len(sip.getbytes())
        assert rmtu >= 8, "Insufficient MTU for subsequent IPv4 fragments."
        rmtu -= rmtu % 8
        while remaining >= rmtu:
            sip.ip_off = off >> 3
            result.append(Chain([deepcopy(sip), \
                                 ipv4frag(bytes=tmpbytes[off:rmtu])]))
            off += rmtu
            remaining -= rmtu

        # If MF is set in the original packet, then MF is set in all
        # the fragments.
        # If MF is not set in the original packet, then MF is set in
        # every fragment except the last.
        if remaining > 0:
            sip.ip_off = off >> 3
            if not (ip.ip_flags & IP_MF):
                sip.ip_flags = 0
            result.append(Chain([deepcopy(sip), \
                                 ipv4frag(bytes=tmpbytes[off:remaining])]))
            off += remaining
            remaining -= remaining
        assert off == len(tmpbytes), "Did not fragment entire payload."
        assert remaining == 0, "Did not fragment entire payload."

        return result

    ipopt_copied = staticmethod(ipopt_copied)
    make_fragment_header = staticmethod(make_fragment_header)
    fragment = staticmethod(fragment)
