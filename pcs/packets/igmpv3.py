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

class query(pcs.Packet):
    """IGMPv3 query message."""

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize an IGMPv3 query"""
        group = pcs.Field("group", 32)
        reserved00 = pcs.Field("reserved00", 4)
        sbit = pcs.Field("sbit", 1)
        qrv = pcs.Field("qrv", 3)
        qqic = pcs.Field("qqic", 8)
        nsrc = pcs.Field("nsrc", 16)
        srcs = pcs.OptionListField("sources")

        # If keyword initializers are present, deal with the syntactic sugar.
        # query's constructor accepts a list of IP addresses. These need
        # to be turned into Fields for encoding to work, as they are going
        # to be stashed into the "sources" OptionListField defined above.
        if kv is not None:
            for kw in kv.items():
                if kw[0] == 'sources':
                    assert isinstance(kw[1], list)
                    for src in kw[1]:
                        assert isinstance(src, int)
                        srcs.append(pcs.Field("", 32, default=src))
            kv.pop('sources')

        pcs.Packet.__init__(self, [group, reserved00, sbit, qrv, qqic,
                                   nsrc, srcs], bytes = bytes, **kv)

        self.description = "initialize an IGMPv3 query"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # Decode source list if provided.
        if bytes is not None:
            sources_len = self.nsrc * 4
            query_len = self.sizeof() + sources_len

            if query_len > len(bytes):
                raise UnpackError("IGMPv3 query is larger than input (%d > %d)" % \
                      (query_len, len(bytes)))

            rem = sources_len
            curr = self.sizeof()
            while rem >= 4:
                src = struct.unpack('I', bytes[curr:curr+4])[0]
                sources.append(pcs.Field("", 32, default = src))
                curr += 4
                rem -= 4
            if rem > 0:
                print("WARNING: %d trailing bytes in query." % rem)

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

    def __init__(self, name, **kv):
        self.packet = None
        self.name = name

        self.type = pcs.Field("type", 8)
        self.auxdatalen = pcs.Field("auxdatalen", 8)
        self.nsources = pcs.Field("nsources", 16)
        self.group = pcs.Field("group", 32)
        self.sources = pcs.OptionListField("sources")
        self.auxdata = pcs.OptionListField("auxdata")

        # XXX I actually have variable width when I am being encoded,
        # OptionList deals with this.
        self.width = self.type.width + self.auxdatalen.width + \
                     self.nsources.width + self.group.width + \
                     self.sources.width + self.auxdata.width

        # If keyword initializers are present, deal with the syntactic sugar.
        if kv is not None:
            for kw in kv.items():
                if kw[0] in self.__dict__:
                    if kw[0] == 'auxdata':
                        if not isinstance(kw[1], str):
                            if __debug__:
                                print("argument is not a string")
                            continue
                        self.auxdata.append([pcs.StringField("",             \
                                                             len(kv[1]) * 8, \
                                                             default=kv[1])])
                    elif kw[0] == 'sources':
                        if not isinstance(kw[1], list):
                            if __debug__:
                                print("argument is not a list")
                            continue
                        for src in kw[1]:
                            if not isinstance(src, int):
                                if __debug__:
                                    print("source is not an IPv4 address")
                                continue
                            self.sources.append(pcs.Field("", 32, default=src))
                    else:
                        self.__dict__[kw[0]].value = kw[1]

    def __repr__(self):
        return "<igmpv3.GroupRecordField type %s, auxdatalen %s, " \
               "nsources %s, group %s, sources %s, auxdata %s>" \
                % (self.type, self.auxdatalen, self.nsources, \
                   self.group, self.sources, self.auxdata)

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields."""
        retval = " GroupRecord\n"
        retval += "Type %d\n" % self.type.value
        retval += "Auxdatalen %d\n" % self.auxdatalen.value
        retval += "Nsources %d\n" % self.nsources.value
        gs = inet_ntop(AF_INET, struct.pack('!L', self.group.value))
        retval += "Group %s\n" % gs
        retval += "Sources "
        i = False
        for s in self.sources._options:
            if i is False:
                retval += ", "
            ss = inet_ntop(AF_INET, struct.pack('!L', s.value))
            retval += ss
            i = True
        return retval

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if self.packet is not None:
            self.packet.__needencode = True

    # OptionList decode is funny. If you don't have the packet
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

        srclen = self.nsources.value << 2
        if srclen != 0:
            srclen = min(srclen, len(bytes))
            endp = curr + srclen
            while curr < endp:
                src = pcs.Field("", 32)
                [src.value, curr, byteBR] = src.decode(bytes, curr, byteBR)
                self.sources.append(src)

        auxdatalen = self.auxdatalen.value << 2
        if auxdatalen != 0:
            auxdatalen = min(auxdatalen, len(bytes))
            self.auxdata.append(pcs.StringField("", auxdatalen*8, \
                                default=bytes[curr:curr+auxdatalen]))
            curr += auxdatalen

        delta = curr - start
        self.width = 8 * delta
        #print "consumed %d bytes" % delta

        return [bytes, curr, byteBR]

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
            raise FieldBoundsError("GroupRecordField must be between %d " \
                                    "and %d bytes wide" % (minwidth, maxwidth))
    def __eq__(self, other):
        """Test two group records lists for equality."""
        if other is None:
            return False
        if self.type.value == other.type.value and \
           self.auxdatalen.value == other.auxdatalen.value and \
           self.nsources.value == other.nsources.value and \
           self.group.value == other.group.value:
            # TODO: Do a dictionary style comparison, sources shouldn't
            # need to appear in same order.
            #print "other fields compare ok, trying to match sources"
            for i in range(len(self.sources)):
                if self.sources[i].value != other.sources[i].value:
                    #print "no match"
                    return False
            #print "match"
            return True
        #print "no match"
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def default_compare(lp, lf, rp, rf):
        """Default comparison method.
           Compare all fields except auxdata. Source list must match
           exactly -- we can't treat it as a dictionary, yet."""
        return lf.__eq__(rf)

    default_compare = staticmethod(default_compare)

class report(pcs.Packet):
    """IGMPv3 Report"""
    #IGMPv3 report messages are always multicast to link scope group
    #224.0.0.22 (INADDR_ALLRPTS_GROUP), with IGMP type 0x22
    #(IGMP_v3_HOST_MEMBERSHIP_REPORT), making them easy to identify.
    #At least one group record SHOULD exist in the variable-length
    #section at the end of each datagram.

    _layout = pcs.Layout()

    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize an IGMPv3 report header"""
        reserved00 = pcs.Field("reserved00", 16)
        nrecords = pcs.Field("nrecords", 16)
        records = pcs.OptionListField("records")

        pcs.Packet.__init__(self, [reserved00, nrecords, records], bytes, **kv)
        self.description = "initialize an IGMPv3 report header"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # Decode additional bytes into group records, if provided.
        # Group records are variable length structures.
        # Some IGMPv3 implementations re-use the same buffers which
        # may contain junk, so don't try to parse the entire packet
        # as a set of group record fields.
        if bytes is not None:
            curr = self.sizeof()
            byteBR = 8
            found = 0
            expected = self._fieldnames['nrecords'].value
            while len(self.records) < expected and curr < len(bytes):
                rec = GroupRecordField("")
                oldcurr = curr
                [dummy, curr, byteBR] = rec.decode(bytes, curr, byteBR)
                self.records.append(rec)
            #print len(self.records), "records parsed"
            self.data = payload.payload(bytes[curr:len(bytes)])
        else:
            self.data = None

    def calc_length(self):
        """Calculate and store the length field(s) for this packet.
           An IGMPv3 report itself has no auxiliary data; the report header
           counts only the number of records it contains."""
        # For each record I contain, set nsources to the number of source
        # entries, and set auxdatalen to the size of the auxiliary data
        # in 32-bit words. auxdata is an OptionListField of StringFields.
        record_list = self._fieldnames['records']._options
        for rec in record_list:
            rec.nsources.value = len(rec.sources)
            auxdatalen = 0
            for aux in rec.auxdata._options:
                auxdatalen += aux.width / 8
            rec.auxdatalen.value = auxdatalen >> 2
        self.nrecords = len(record_list)
