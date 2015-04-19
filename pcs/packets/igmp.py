# Copyright (c) 2014, Neville-Neil Consulting
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
# File: $Id:$
#
# Author: Bruce M. Simpson
#
# Description: IGMP Packet Class

import pcs
from socket import AF_INET, inet_ntop

import struct
import time

import pcs.packets.ipv4
import pcs.packets.igmpv2 as igmpv2
import pcs.packets.igmpv3 as igmpv3
#import pcs.packets.dvmrp
#import pcs.packets.mtrace

IGMP_HOST_MEMBERSHIP_QUERY = 0x11
IGMP_v1_HOST_MEMBERSHIP_REPORT = 0x12
IGMP_DVMRP = 0x13
IGMP_v2_HOST_MEMBERSHIP_REPORT = 0x16
IGMP_HOST_LEAVE_MESSAGE = 0x17
IGMP_v3_HOST_MEMBERSHIP_REPORT = 0x22
IGMP_MTRACE_REPLY = 0x1e
IGMP_MTRACE_QUERY = 0x1f

igmp_map = {
        IGMP_HOST_MEMBERSHIP_QUERY:     igmpv2.igmpv2,
        IGMP_v1_HOST_MEMBERSHIP_REPORT: igmpv2.igmpv2,
        #IGMP_DVMRP:                    dvmrp.dvmrp,
        IGMP_v2_HOST_MEMBERSHIP_REPORT: igmpv2.igmpv2,
        IGMP_HOST_LEAVE_MESSAGE:        igmpv2.igmpv2,
        #IGMP_MTRACE_REPLY:             mtrace.reply,
        #IGMP_MTRACE_QUERY:             mtrace.query,
        IGMP_v3_HOST_MEMBERSHIP_REPORT: igmpv3.report
}

descr = {
        IGMP_HOST_MEMBERSHIP_QUERY:     "IGMPv2 Query",
        IGMP_v1_HOST_MEMBERSHIP_REPORT: "IGMPv1 Report",
        IGMP_DVMRP:                     "DVMRP",
        IGMP_v2_HOST_MEMBERSHIP_REPORT: "IGMPv2 Report",
        IGMP_HOST_LEAVE_MESSAGE:        "IGMPv2 Leave",
        IGMP_MTRACE_REPLY:              "MTRACE Reply",
        IGMP_MTRACE_QUERY:              "MTRACE Query",
        IGMP_v3_HOST_MEMBERSHIP_REPORT: "IGMPv3 Report"
}

class igmp(pcs.Packet):
    """IGMP"""

    _layout = pcs.Layout()
    _map = igmp_map
    _descr = descr

    def __init__(self, pdata = None, timestamp = None, **kv):
        """ Define the common IGMP encapsulation; see RFC 2236. """
        type = pcs.Field("type", 8, discriminator=True)
        code = pcs.Field("code", 8)
        checksum = pcs.Field("checksum", 16)
        pcs.Packet.__init__(self, [type, code, checksum], pdata = pdata, **kv)
        self.description = "IGMP"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if pdata is not None:
            offset = self.sizeof()
            if self.type == IGMP_HOST_MEMBERSHIP_QUERY and \
               len(pdata) >= igmpv3.IGMP_V3_QUERY_MINLEN:
                    self.data = igmpv3.query(pdata[offset:len(pdata)],
                                             timestamp = timestamp)
            else:
                # XXX Workaround Packet.next() -- it only returns something
                # if it can discriminate.
                self.data = self.next(pdata[offset:len(pdata)],
                                      timestamp = timestamp)
                if self.data is None:
                    self.data = payload.payload(pdata[offset:len(pdata)])
        else:
            self.data = None

    def rdiscriminate(self, packet, discfieldname = None, map = igmp_map):
        """Reverse-map an encapsulated packet back to a discriminator
           field value. Like next() only the first match is used."""
        #print "reverse discriminating %s" % type(packet)
        return pcs.Packet.rdiscriminate(self, packet, "type", map)

    def calc_checksum(self):
        """Calculate and store the checksum for this IGMP header.
           IGMP checksums are computed over payloads too."""
        from pcs.packets.ipv4 import ipv4
        self.checksum = 0
        tmppdata = self.pdata
        if not self._head is None:
            tmppdata += self._head.collate_following(self)
        self.checksum = ipv4.ipv4_cksum(tmppdata)

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        retval = self._descr[self.type] + "\n"
        for field in self._layout:
            retval += "%s %s\n" % (field.name, field.value)
        return retval
