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

import inspect
import pcs
import struct
import time

from pcs.packets import payload
from pcs.packets.igmpv2 import *
from socket import AF_INET, inet_ntop, inet_ntoa

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
# Minimum length of an IGMPv3 query.
#
IGMP_V3_QUERY_MINLEN = 12

# TODO: Add keyword initializer support to GroupRecordField.
# TODO: Reflect any auxiliary data in GroupRecordField.

class query(pcs.Packet):
    """IGMPv3 query message."""

    layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize an IGMPv3 query"""
	group = pcs.Field("group", 32)
	reserved00 = pcs.Field("reserved00", 4)
	sbit = pcs.Field("sbit", 1)
	qrv = pcs.Field("qrv", 3)
	qqic = pcs.Field("qqic", 8)
	nsrc = pcs.Field("nsrc", 16)
	sources = pcs.OptionListField("sources")

        pcs.Packet.__init__(self, [group, reserved00, sbit, qrv, qqic,
				   nsrc, sources], bytes = bytes, **kv)

	self.description = inspect.getdoc(self)

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
            curr = self.sizeof()
            while rem >= 4:
                src = struct.unpack('I', bytes[curr:curr+4])[0]
                sources.append(pcs.Field("", 32, default = src))
                curr += 4
                rem -= 4
            if rem > 0:
                print "WARNING: %d trailing bytes in query." % rem

            # IGMPv3 queries SHOULD NOT contain ancillary data. If we
            # do find any, we'll append it to the data member.
            self.data = payload.payload(bytes[query_len:len(bytes)])
        else:
            self.data = None

    def calc_length(self):
        """Calculate and store the length field(s) for this packet.
           An IGMPv3 query has no auxiliary data; the query counts
           only the number of sources being queried, which may be 0."""
        #self.nsrc = len(self._fieldnames['sources'])
        # OptionListFields are returned as themselves when accessed as
        # attributes of the enclosing Packet.
        self.nsrc = len(self.sources)

class GroupRecordField(pcs.CompoundField):
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
        self.width = self.type.width + self.auxdatalen.width + \
		     self.nsources.width + self.group.width + \
		     self.sources.width + self.auxdata.width

    def __repr__(self):
        return "<igmpv3.GroupRecordField type %s, auxdatalen %s, " \
               "nsources %s, group %s, sources %s, auxdata %s>" \
                % (self.type, self.auxdatalen, self.nsources, \
                   self.group, self.sources, self.auxdata)

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if self.packet != None:
            self.packet.__needencode = True

    # XXX OptionList decode is funny. If you don't have the packet
    # contents reflected in the PCS representation already, then it will
    # not produce anything -- the OptionLists are empty.
    # This is why the TCP and IP option list decoders have to act on
    # the backing store provided. Similarly we have to do the same here.
    def decode(self, bytes, curr, byteBR):
	start = curr
        [self.type.value, curr, byteBR] = self.type.decode(bytes,
                                                           curr, byteBR)
        [self.auxdatalen.value, curr, byteBR] = self.auxdatalen.decode(bytes,
                                                           curr, byteBR)
        [self.nsources.value, curr, byteBR] = self.nsources.decode(bytes,
                                                           curr, byteBR)
        [self.group.value, curr, byteBR] = self.group.decode(bytes,
                                                           curr, byteBR)

	# The sources[] array is a variable length field. We need to
	# parse it ourselves.
	srcendp = curr + (self.nsources.value * 4)
	while curr < srcendp:
	    src = pcs.Field("", 32)
	    [src.value, curr, byteBR] = src.decode(bytes, curr, byteBR)
	    self.sources.append(src)

	# Attempt to consume any auxiliary data. TODO: Reflect it.
	curr += (self.auxdatalen.value * 4)

	delta = curr - start
	self.width = 8 * delta
	#print "consumed %d bytes" % delta

        return [None, curr, byteBR]

    def encode(self, bytearray, value, byte, byteBR):
        """Encode an IGMPv3 group record."""
	#
	# Just encode what we're told, don't try to bounds check the payload,
	# but do print warnings if protocol invariants were violated.
	#
	#if self.nsources.value != (len(self.sources) >> 2):
	#    print "WARNING: nsources field is %d, should be %d." % \
        #          (self.nsources.value, len(self.sources) >> 2)
	#if self.auxdatalen.value != (len(self.auxdata) >> 2):
	#    print "WARNING: auxdatalen field is %d, should be %d." % \
        #          (self.auxdata.value, len(self.auxdata) >> 2)

        [byte, byteBR] = self.type.encode(bytearray, self.type.value,
                                          byte, byteBR)
        [byte, byteBR] = self.auxdatalen.encode(bytearray,
                                                self.auxdatalen.value,
                                                byte, byteBR)
        [byte, byteBR] = self.nsources.encode(bytearray, self.nsources.value,
                                              byte, byteBR)
        [byte, byteBR] = self.group.encode(bytearray, self.group.value,
                                           byte, byteBR)
        [byte, byteBR] = self.sources.encode(bytearray, None,
                                             byte, byteBR)
        [byte, byteBR] = self.auxdata.encode(bytearray, None,
                                             byte, byteBR)

        return [byte, byteBR]

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    # PCS codes field widths for bits.
    # Both length fields in an individual IGMPv3 group record code for
    # 32 bit words. Calculate if the field's overall width lies within
    # the bounds of a valid GroupRecordField.
    def bounds(self, value):
        """Check the bounds of this field."""
	minwidth = self.type.width + self.auxdatalen.width + \
                   self.nsources.width + self.group.width
	maxwidth = minwidth + (((2 ** auxdatalen.width) << 2) * 8) + \
                              (((2 ** nsources.width) << 2) * 8)
	if self.width < minwidth or self.width > maxwidth:
            raise FieldBoundsError, "GroupRecordField must be between %d " \
                                    "and %d bytes wide" % (minwidth, maxwidth)

class report(pcs.Packet):
    """IGMPv3 Report"""
    #IGMPv3 report messages are always multicast to link scope group
    #224.0.0.22 (INADDR_ALLRPTS_GROUP), with IGMP type 0x22
    #(IGMP_v3_HOST_MEMBERSHIP_REPORT), making them easy to identify.
    #At least one group record SHOULD exist in the variable-length
    #section at the end of each datagram.

    layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize an IGMPv3 report header"""
	reserved00 = pcs.Field("reserved00", 16)
	nrecords = pcs.Field("nrecords", 16)
	records = pcs.OptionListField("records")

        pcs.Packet.__init__(self, [reserved00, nrecords, records], bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp == None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # Decode additional bytes into group records, if provided.
        # Group records are variable length structures, so we
        # have no way of bounds checking upfront -- we have to
        # attempt to parse the entire payload. This gets interesting.
	if bytes != None:
            curr = self.sizeof()
            byteBR = 8
            while curr < len(bytes):
		rec = GroupRecordField("")
                [dummy, curr, byteBR] = rec.decode(bytes, curr, byteBR)
		self.records.append(rec)
	    self.data = payload.payload(bytes[curr:len(bytes)])
        else:
            self.data = None

    def calc_length(self):
        """Calculate and store the length field(s) for this packet.
           An IGMPv3 report itself has no auxiliary data; the report header
           counts only the number of records it contains."""
        # OptionListFields are returned as themselves when accessed as
        # attributes of the enclosing Packet.
        self.nrecords = len(self.records)
