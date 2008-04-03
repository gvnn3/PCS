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
# Neither the name of the author nor the names of other
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
# File: $Id$
#
# Author: Bruce M. Simpson
#
# Description: Classes which describe IGMPv3 messages.
#

# TODO teach IP decoder further down in stack to grok how IGMPv3 differs
# and use the correct IGMP decoder.

import pcs
import struct
import time

from pcs.packets import payload
from pcs.packets.igmpv2 import *
from socket import AF_INET, inet_ntop, inet_ntoa

#
# IGMP message types which are part of IGMPv3 itself.
#
IGMP_v3_HOST_MEMBERSHIP_REPORT = 0x22

#
# IGMPv3 group record types.
#
IGMP_MODE_IS_INCLUDE = 1
IGMP_MODE_IS_EXCLUDE = 2
IGMP_CHANGE_TO_INCLUDE = 3
IGMP_CHANGE_TO_EXCLUDE = 4
IGMP_ALLOW_NEW_SOURCES = 5
IGMP_BLOCK_OLD_SOURCES = 6

#
# IGMPv3 protocol defaults.
#

# XXX not yet debugged
# TODO: __str__ method, assignment sugar, etc.
# TODO: support the fixed point for maxresp and qqic in assignment.

class igmpv3_query(pcs.Packet):
    """IGMPv3 query message.
    v3 of the protocol (RFC 2236) has a broadly extended query format.
    General IGMPv3 queries are always multicast to link scope group
    224.0.0.22. It needs careful handling to differentiate it from
    older protocol versions in its group specific flavour.
    The optional payload, if provided, is a list of sources
    (IPv4, network-endian, as 32-bit-wide long integers) to be queried.
    """

    layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None):
        """initialize an IGMPv3 query"""
        type = pcs.Field("type", 8)
        # 3-bit exp/4 bit mantissa packed fixed point.
        maxresp = pcs.Field("maxresp", 8)
        cksum = pcs.Field("checksum", 16)
	group = pcs.Field("group", 32)
	reserved00 = pcs.Field("reserved00", 4)
	sbit = pcs.Field("sbit", 1)
	qrv = pcs.Field("qrv", 3)
	qqic = pcs.Field("qqic", 8)
	# XXX User needs to count and stash source count.
	nsrc = pcs.Field("nsrc", 16)
	sources = pcs.OptionListField("sources")

        pcs.Packet.__init__(self, [type, maxresp, cksum, group,
			           reserved00, sbit, qrv, qqic,
				   nsrc, sources], bytes = bytes)

        self.description = "IGMPv3"
	self.type = IGMP_HOST_MEMBERSHIP_QUERY
	self.reserved00 = 0

        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # Decode source list if provided.
	if bytes != None:
	    sources_len = self.nsrc * 4
            query_len = self.sizeof() + sources_len

            if query_len > len(bytes):
                raise FieldBoundsError, \
                      "IGMPv3 query is larger than input (%d > %d)" % \
                      (query_len, len(bytes))

            rem = sources_len
            while rem > 4:
                src = struct.unpack('I', bytes[curr])[0]
                sources.append(pcs.Field("", 32, default = src))
                rem -= 4
            if rem > 0:
                print "WARNING: %d unaligned bytes in payload." % rem

            self.nsrc = len(sources)

            # IGMPv3 queries SHOULD NOT contain ancillary data. If we
            # do find any, we'll append it to the data member.
            self.data = payload.payload(bytes[querylen:len(bytes)])

        else:
	    self.nsrc = 0
            self.data = None

# XXX not yet debugged
# TODO: __str__ method, assignment sugar, etc.
class igmpv3_report(pcs.Packet):
    """IGMPv3 report message.
    v3 of the protocol (RFC 2236) has a broadly extended query format.
    General IGMPv3 queries are always multicast to link scope group 224.0.0.22.
    It needs careful handling to differentiate it from older protocol versions in its
    group specific flavour.
    The optional payload, if provided, is a list of group reports.
    """

    layout = pcs.Layout()

    def __init__(self, records = None):
        """initialize an IGMPv3 report header"""
        type = pcs.Field("type", 8)
	reserved00 = pcs.Field("reserved00", 8)
        cksum = pcs.Field("checksum", 16)
	reserved01 = pcs.Field("reserved01", 16)
	nrec = pcs.Field("nrec", 16)

        pcs.Packet.__init__(self, [type, reserved00, cksum, reserved01, nrec], bytes)
        self.description = "IGMPv3_Query"

	self.reserved01 = self.reserved00 = 0
	#self.records = records

	# If a payload is specified, treat it as a list of sources.
        if (records != None):
            offset = type.width + reserved00.width + cksum.width + \
		     reserved01.width + nrec.width
            self.data = payload.payload(bytes[offset:len(bytes)])
	    # TODO: No sugar for you, set nrec correctly yourself, user!
        else:
	    self.nrec = 0
            self.data = None



# XXX not yet debugged
# TODO: __str__ method, assignment sugar, etc.
class igmpv3_group_record(pcs.Packet):
    """IGMPv3 group record.
    The optional payload, if provided, is a list of sources to be contained
    in the report. Currently, auxiliary data is not supported.
    """

    layout = pcs.Layout()

    def __init__(self, sources = None):
        """initialize an IGMPv3 report header"""
        type = pcs.Field("type", 8)
	auxlen = pcs.Field("auxlen", 8)
	nsrc = pcs.Field("nsrc", 16)
	group = pcs.Field("group", 32)

        pcs.Packet.__init__(self, [type, auxlen, nsrc, group], bytes)
        self.description = "GroupRecord"

	self.auxlen = 0

	# If a payload is specified, treat it as a list of sources.
        if (records != None):
            offset = type.width + auxlen.width + nsrc.width + group.width
	    self.nsrc = len(bytes) >> 2
            self.data = payload.payload(bytes[offset:len(bytes)])
        else:
	    self.nsrc = 0
            self.data = None

	self.encode()		# XXX?

    def __len__(self):
        """Return the count of the number of bytes in the group record."""
        return len(self.bytes)
