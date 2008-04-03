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

# TODO: Support the 8-bit fixed point format for maxresp and qqic
# when assigning.

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

	self.description = inspect.getdoc(self)
	self.type = IGMP_HOST_MEMBERSHIP_QUERY	# XXX

        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # Decode source list if provided.
	if bytes != None:
	    sources_len = self.nsrc * 4
            query_len = self.sizeof() + sources_len

            if query_len > len(bytes):
                raise UnpackError, \
                      "IGMPv3 query is larger than input (%d > %d)" % \
                      (query_len, len(bytes))

            rem = sources_len
            while rem > 4:
                src = struct.unpack('I', bytes[curr])[0]
                sources.append(pcs.Field("", 32, default = src))
                rem -= 4
            if rem > 0:
                print "WARNING: %d trailing bytes in query." % rem

            self.nsrc = len(sources)

            # IGMPv3 queries SHOULD NOT contain ancillary data. If we
            # do find any, we'll append it to the data member.
            self.data = payload.payload(bytes[querylen:len(bytes)])

        else:
	    self.nsrc = 0
            self.data = None

class GroupRecordField(object):
    """An IGMPv3 group record contains report information about
       a single IGMPv3 group."""

    def __init__(self, name):
        self.packet = None
        self.name = name

        self.type = pcs.Field("type", 8)
        self.auxdatalen = pcs.Field("auxdatalen", 8)
        self.nsources = pcs.Field("nsources", 16)
        self.group = pcs.Field("group", 32)
        self.sources = pcs.OptionListField("sources")
        self.auxdata = pcs.OptionListField("auxdata")

        # XXX I actually have variable width when I am being encoded.
        self.width = type.width + auxdatalen.width + nsources.width +
                     group.width + sources.width + auxdata.width

    def __repr__(self):
        return "<igmpv3.GroupRecordField type %s, auxdatalen %s, " \
               "nsources %s, group %s, sources %s, auxdata %s>" \
                % (self.type, self.auxdatalen, self.nsources,
                   self.group, self.sources, self.auxdata)

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if self.packet != None:
            self.packet.__needencode = True

    def decode(self, bytes, curr, byteBR):
        [self.type.value, curr, byteBR] = self.type.decode(bytes,
                                                           curr, byteBR)
        [self.auxdatalen.value, curr, byteBR] = self.auxdatalen.decode(bytes,
                                                           curr, byteBR)
        [self.nsources.value, curr, byteBR] = self.nsources.decode(bytes,
                                                           curr, byteBR)
        [self.group.value, curr, byteBR] = self.group.decode(bytes,
                                                           curr, byteBR)

        # XXX OptionList decode is funny. If you don't have the packet
        # contents reflected in Python objects already, then it will
        # not produce anything -- the OptionLists are empty.
        # This is why the TCP and IP option list
        # decoders have to act on the backing store provided. Similarly
        # we have to do the same here.

        print "total %d, curr %d, remaining %d" % \
              (len(bytes), curr, len(bytes) - curr)
        [self.sources.value, curr, byteBR] = self.sources.decode(bytes,
                                                           curr, byteBR)

        print "total %d, curr %d, remaining %d" % \
              (len(bytes), curr, len(bytes) - curr)
        [self.auxdata.value, curr, byteBR] = self.auxdata.decode(bytes,
                                                           curr, byteBR)

        # XXX Update my width, or other stuff won't work.

        return [value, curr, byteBR]

    def encode(self, bytearray, value, byte, byteBR):
        """Encode an IGMPv3 group record."""
	#
	# Just encode what we're told, don't try to bounds check the payload,
	# but do print warnings if protocol invariants were violated.
	#
	if self.nsources.value != (len(self.nsources.value) >> 2):
	    print "WARNING: nsources field is %d, should be %d.",
	if self.auxdatalen.value != len(self.auxdata.value):
	    print "WARNING: auxdatalen field is %d, should be %d.",

        [byte, byteBR] = self.type.encode(bytearray, self.type.value,
                                          byte, byteBR)
        [byte, byteBR] = self.auxdatalen.encode(bytearray,
                                                self.auxdatalen.value,
                                                byte, byteBR)
        [byte, byteBR] = self.nsources.encode(bytearray, self.nsources.value,
                                              byte, byteBR)
        [byte, byteBR] = self.group.encode(bytearray, self.group.value,
                                           byte, byteBR)
        [byte, byteBR] = self.sources.encode(bytearray, self.sources.value,
                                             byte, byteBR)
        [byte, byteBR] = self.auxdata.encode(bytearray, self.auxdata.value,
                                             byte, byteBR)

        return [byte, byteBR]

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    # PCS codes field widths for bits, IGMPv3 codes auxdata for bytes,
    # and nsources for 32 bit IPv4 addresses.
    def bounds(self, value):
        """Check the bounds of this field."""
	minwidth = self.type.width + self.auxdatalen.width +
                   self.nsources.width + self.group.width
	maxwidth = minwidth + ((2 ** auxdatalen.width) * 8) +
                              ((2 ** nsources.width << 2) * 8)
	if self.width < minwidth or self.width > maxwidth
            raise FieldBoundsError, "GroupRecordField must be between %d "
                                    "and %d bytes wide" % (minwidth, maxwidth)

class igmpv3_report(pcs.Packet):
    """IGMPv3 report message.
    IGMPv3 report messages are always multicast to link scope group
    224.0.0.22 (INADDR_ALLRPTS_GROUP), with IGMP type 0x22
    (IGMP_v3_HOST_MEMBERSHIP_REPORT), making them easy to identify.
    At least one group record SHOULD exist in the variable-length
    section at the end of each datagram.
    """

    layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None):
        """initialize an IGMPv3 report header"""
        type = pcs.Field("type", 8)
	reserved00 = pcs.Field("reserved00", 8)
        cksum = pcs.Field("checksum", 16)
	reserved01 = pcs.Field("reserved01", 16)
	nrecords = pcs.Field("nrecords", 16)
	records = pcs.OptionListField("records")

        pcs.Packet.__init__(self, [type, reserved00, cksum, reserved00,
                                   nrecords, records], bytes)
        self.description = "IGMPv3_Report"

	self.type = IGMP_v3_HOST_MEMBERSHIP_REPORT	# XXX

        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # Decode additional bytes into group records, if provided.
        # Group records are variable length structures, so we
        # have no way of bounds checking upfront, we have to
        # attempt to parse the payload.
        # This is where things get interesting, OptionListField
        # is a variable length Field... and we need a list of those.
	if bytes != None:
            curr = self.sizeof()

            #remaining = len(bytes) - self.sizeof()
            #rem = sources_len
            #while rem > 4:
            #    src = struct.unpack('I', bytes[curr])[0]
            #    sources.append(pcs.Field("", 32, default = src))
            #    rem -= 4
            #if rem > 0:
            #    print "WARNING: %d trailing bytes in query." % rem

            #records = []
            #self.nrecords = len(records)

            # IGMPv3 reports SHOULD NOT contain ancillary data beyond
            # the last group report. If we do find any, we'll append it
            # it to the 'data' member as a Payload.
            self.data = payload.payload(bytes[curr:len(bytes)])

        else:
	    self.nrecords = 0
            self.data = None
