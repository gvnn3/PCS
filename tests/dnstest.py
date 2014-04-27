# Copyright (c) 2005, Neville-Neil Consulting
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
# File: $Id: dnstest.py,v 1.1 2006/09/01 05:24:04 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on the DNS packet.
# That is to say it first encodes a packet, then decodes is and makes
# sure that the data matches.

import unittest

import sys
from hexdumper import hexdumper

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    from pcs.packets.dns import *
    from pcs.packets.ipv4 import ipv4
    from pcs.packets.udpv4 import udpv4
    import pcs

class dnsTestCase(unittest.TestCase):
    def test_dns_header(self):
        # create one header, copy its bytes, then compare their fields
        dns = dnsheader()
        assert (dns != None)

        dns.id = 1
        dns.query = 0
        dns.opcode = 0
        dns.aa = 0
        dns.tc = 0
        dns.rd = 1
        dns.ra = 0
        dns.z = 0
        dns.rcode = 0
        dns.qdcount = 1
        dns.ancount = 0
        dns.nscount = 0
        dns.arcount = 0

        # Create a packet to compare against
        dnsnew = dnsheader()
        dnsnew.decode(dns.bytes)

        self.assertEqual(dns.bytes, dnsnew.bytes, "bytes not equal")
        for field in dns._fieldnames:
            self.assertEqual(getattr(dns, field), getattr(dnsnew, field), ("%s not equal" % field))

    def test_dns_query(self):
        # create one query, copy its bytes, then compare their fields
        dns = dnsquery()
        assert (dns != None)

        # XXX This field doesn't exist. Normally how the dns classes are
        # used is that labels go in front -- the code isn't yet smart
        # enough to encode labels at this level.
        dns.name = "neville-neil.com"
        dns.type = 1
        dns.query_class = 1

        dnsnew = dnsquery()
        assert (dnsnew != None)
        dnsnew.decode(dns.bytes)

        self.assertEqual(dns.type, dnsnew.type, "type not equal")
        self.assertEqual(dns.query_class, dnsnew.query_class, "class not equal")

    def test_dns_rr(self):
        # create one resource record, copy its bytes, then compare their fields

        dns = dnsrr()
        assert (dns != None)

        # XXX 'name' should really be a sequence of labels or pointers,
        # see RFC 1035, we just use a single string for now as implementing
        # the name compression is troublesome.
        # Both 'name' and 'rdata' encode as their entire field width. Of
        # course we have a variable field with, which the PCS reflection
        # in python doesn't grok.

        dns.name = "neville-neil.com"
        dns.type = 1
        dns.query_class = 1
        dns.ttl = 32
        dns.rdata = "ns.meer.net"

        # XXX this DOESN'T copy the LengthValue fields, why?
        #dnsnew = dnsrr()
        #dnsnew.decode(dns.bytes)

        dnsnew = dnsrr(dns.bytes)
        assert (dnsnew != None)

        #print
        #print "'%s'" % dns.name.value.value
        #print "'%s'" % dnsnew.name.value.value
        #print "'%s'" % dns.rdata.value.value
        #print "'%s'" % dnsnew.rdata.value.value

        # XXX accessor for dns.name produces field, not string.

        #self.assertEqual(dns.name, dnsnew.name, "name not equal")
        self.assertEqual(dns.name.value.value, dnsnew.name.value.value, "name not equal")
        self.assertEqual(dns.type, dnsnew.type, "type not equal")
        self.assertEqual(dns.query_class, dnsnew.query_class, "class not equal")
        self.assertEqual(dns.ttl, dnsnew.ttl, "ttl not equal")
        #self.assertEqual(dns.rdata, dnsnew.rdata, "rdata not equal")
        #self.assertEqual(dns.rdata.value.value, dnsnew.rdata.value.value, "rdata not equal")

    def test_dns_read(self):
        """This test reads from a pre-stored pcap file generated with tcpdump and ping on the loopback interface."""
        file = pcs.PcapConnector("dns.out")
        packet = file.readpkt()
        ip = packet.data
        assert (ip != None)
        udp = ip.data
        dns = udp.data
        
    def test_dns_compare(self):
        """Test the underlying __compare__ functionality of the
        packet.  Two packets constructed from the same bytes should be
        equal and two that are not should not be equal."""
        file = pcs.PcapConnector("dns.out")
        packet = file.readpkt()
        ip = packet.data
        assert (ip != None)
        udp1 = udpv4(ip.data.bytes)
        udp2 = udpv4(ip.data.bytes)
        assert (udp1 != None)
        assert (udp2 != None)
        self.assertEqual(udp1, udp2, "packets should be equal but are not")

        udp1.dport = 0xffff
        self.assertNotEqual(udp1, udp2, "packets compare equal but should not\ngot %sexpect %s" % (udp1, udp2))
        
    def test_dns_print(self):
        """This test reads from a pre-stored pcap file generated with
        tcpdump and ping on the loopback interface and tests the
        __str__ method to make sure the correct values are printed."""
        file = pcs.PcapConnector("dns.out")
        packet = file.readpkt()
        ip = packet.data
        assert (ip != None)

        test_string = "UDP\nsport 50942\ndport 53\nlength 62\nchecksum 46791\n"

        udpv4 = ip.data
        string = udpv4.__str__()

        self.assertEqual(string, test_string,
                         "strings are not equal \nexpected %s \ngot %s " %
                         (test_string, string))


if __name__ == '__main__':
    unittest.main()


