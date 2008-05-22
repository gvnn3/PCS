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
# Description: Classes which describe RFC 3549 Netlink socket messages
#              for the NETLINK_ROUTE group.
#

import inspect
import struct
import time

import pcs
import payload

# TODO: Add a LengthTypeValue field to model the general TLV format.
# TODO: Test all this.
# TODO: Cacheinfo, VLAN TLVs.
# TODO: IPv6 neighbor discovery.
# TODO: Queueing/traffic control/filtering.

#
# rtnetlink group IDs (as bit numbers from 1-32).
#
RTNLGRP_NONE = 0
RTNLGRP_LINK = 1
RTNLGRP_NOTIFY = 2
RTNLGRP_NEIGH = 3
RTNLGRP_TC = 4
RTNLGRP_IPV4_IFADDR = 5
RTNLGRP_IPV4_MROUTE = 6
RTNLGRP_IPV4_ROUTE = 7
RTNLGRP_IPV4_RULE = 8
RTNLGRP_IPV6_IFADDR = 9
RTNLGRP_IPV6_MROUTE = 10
RTNLGRP_IPV6_ROUTE = 11
RTNLGRP_IPV6_IFINFO = 12
RTNLGRP_IPV6_PREFIX = 18
RTNLGRP_IPV6_RULE = 19
RTNLGRP_ND_USEROPT = 20

#
# Userland backwards compatibility for rtnetlink group IDs.
#
RTMGRP_LINK		= (1 << (RTNLGRP_LINK - 1))
RTMGRP_NOTIFY		= (1 << (RTNLGRP_NOTIFY - 1))
RTMGRP_NEIGH		= (1 << (RTNLGRP_NEIGH - 1))
RTMGRP_TC		= (1 << (RTNLGRP_TC - 1))
RTMGRP_IPV4_IFADDR	= (1 << (RTNLGRP_IPV4_IFADDR - 1))
RTMGRP_IPV4_MROUTE	= (1 << (RTNLGRP_IPV4_MROUTE - 1))
RTMGRP_IPV4_ROUTE	= (1 << (RTNLGRP_IPV4_ROUTE - 1))
RTMGRP_IPV4_RULE	= (1 << (RTNLGRP_IPV4_RULE - 1))
RTMGRP_IPV6_IFADDR	= (1 << (RTNLGRP_IPV6_IFADDR - 1))
RTMGRP_IPV6_MROUTE	= (1 << (RTNLGRP_IPV6_MROUTE - 1))
RTMGRP_IPV6_ROUTE	= (1 << (RTNLGRP_IPV6_ROUTE - 1))
RTMGRP_IPV6_IFINFO	= (1 << (RTNLGRP_IPV6_IFINFO - 1))
RTMGRP_IPV6_PREFIX	= (1 << (RTNLGRP_IPV6_PREFIX - 1))

#
# rtnetlink message types
#
# struct ifinfomsg
RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_GETLINK = 18
RTM_SETLINK = 19
# struct ifaddrmsg
RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_GETADDR = 22
# struct rtmsg
RTM_NEWROUTE = 24
RTM_DELROUTE = 23
RTM_GETROUTE = 24

#
# Embedded RTnetlink TLVs are normally encoded (len, type, payload)
# where len and type are uint16_t.
#

#
# rtmsg.type values
#
RTN_UNSPEC = 0
RTN_UNICAST = 1
RTN_LOCAL = 2
RTN_BROADCAST = 3
RTN_ANYCAST = 4
RTN_MULTICAST = 5
RTN_BLACKHOLE = 6
RTN_UNREACHABLE = 7
RTN_PROHIBIT = 8
RTN_THROW = 9
RTN_NAT = 10
RTN_XRESOLVE = 11

#
# rtmsg.protocol origin IDs
#
RTPROT_UNSPEC = 0
RTPROT_REDIRECT = 1
RTPROT_KERNEL = 2
RTPROT_BOOT = 3
RTPROT_STATIC = 4
RTPROT_GATED = 8
RTPROT_RA = 9
RTPROT_MRT = 10
RTPROT_ZEBRA = 11
RTPROT_BIRD = 12
RTPROT_DNROUTED = 13
RTPROT_XORP = 14
RTPROT_NTK = 15

#
# rtmsg.scope IDs.
#
RT_SCOPE_UNIVERSE = 0
RT_SCOPE_SITE = 200
RT_SCOPE_LINK = 253
RT_SCOPE_HOST = 254
RT_SCOPE_NOWHERE = 255

#
# rtmsg.flags
#
RTM_F_NOTIFY = 0x100
RTM_F_CLONED = 0x200
RTM_F_EQUALIZE = 0x400
RTM_F_PREFIX = 0x800

#
# rtmsg.table IDs.
#
RT_TABLE_UNSPEC = 0
RT_TABLE_DEFAULT = 253
RT_TABLE_MAIN = 254
RT_TABLE_LOCAL = 255
RT_TABLE_MAX = 0xFFFFFFFF

#
# rtmsg TLVs [0..N following rtmsg]
#
RTA_UNSPEC = 0
RTA_DST = 1
RTA_SRC = 2
RTA_IIF = 3
RTA_OIF = 4
RTA_GATEWAY = 5
RTA_PRIORITY = 6
RTA_PREFSRC = 7
RTA_METRICS = 8
RTA_MULTIPATH = 9		# Contains 0..N NexthopFields
RTA_PROTOINFO = 10
RTA_FLOW = 11			# TODO
RTA_CACHEINFO = 12		# TODO
RTA_SESSION = 13		# TODO
RTA_TABLE = 15

#
# Flags for a NexthopField.
#
RTNH_F_DEAD = 1
RTNH_F_PERVASIVE = 2
RTNH_F_ONLINK = 4

#
# RTA_METRICS TLV [0..13 of metrics for this prefix]
#
RTAX_UNSPEC = 0
RTAX_LOCK = 1
RTAX_MTU = 2
RTAX_WINDOW = 3
RTAX_RTT = 4
RTAX_RTTVAR = 5
RTAX_SSTHRESH = 6
RTAX_CWND = 7
RTAX_ADVMSS = 8
RTAX_REORDERING = 9
RTAX_HOPLIMIT = 10
RTAX_INITCWND = 11
RTAX_FEATURES = 12
RTAX_RTO_MIN = 13

RTAX_FEATURE_ECN	= 0x00000001
RTAX_FEATURE_SACK	= 0x00000002
RTAX_FEATURE_TIMESTAMP	= 0x00000004
RTAX_FEATURE_ALLFRAG	= 0x00000008

#
# IFA TLV IDs.
#
IFA_UNSPEC = 0
IFA_ADDRESS = 1
IFA_LOCAL = 2
IFA_LABEL = 3
IFA_BROADCAST = 4
IFA_ANYCAST = 5
IFA_CACHEINFO = 6
IFA_MULTICAST = 7

#
# ifa_flags
#
IFA_F_SECONDARY = 0x01
IFA_F_TEMPORARY = IFA_F_SECONDARY
IFA_F_NODAD = 0x02
IFA_F_OPTIMISTIC = 0x04
IFA_F_HOMEADDRESS = 0x10
IFA_F_DEPRECATED = 0x20
IFA_F_TENTATIVE = 0x40
IFA_F_PERMANENT = 0x80

#
# Interface flags in the RTnetlink namespace.
# [Scope IDs are as for route messages.]
#
IFF_UP = 0x1
IFF_BROADCAST = 0x2
IFF_DEBUG = 0x4
IFF_LOOPBACK = 0x8
IFF_POINTOPOINT = 0x10
IFF_NOTRAILERS = 0x20
IFF_RUNNING = 0x40
IFF_NOARP = 0x80
IFF_PROMISC = 0x100
IFF_ALLMULTI = 0x200
IFF_MASTER = 0x400
IFF_SLAVE = 0x800
IFF_MULTICAST = 0x1000
IFF_PORTSEL = 0x2000
IFF_AUTOMEDIA = 0x4000
IFF_DYNAMIC = 0x8000
IFF_LOWER_UP = 0x10000
IFF_DORMANT = 0x20000
IFF_ECHO = 0x40000

#
# Interface info TLV IDs.
#
IFLA_UNSPEC = 0
IFLA_ADDRESS = 1
IFLA_BROADCAST = 2
IFLA_IFNAME = 3
IFLA_MTU = 4
IFLA_LINK = 5
IFLA_QDISC = 6
IFLA_STATS = 7
IFLA_COST = 8
IFLA_PRIORITY = 9
IFLA_MASTER = 10
IFLA_WIRELESS = 11
IFLA_PROTINFO = 12
IFLA_TXQLEN = 13
IFLA_MAP = 14			# Bus specific, we can do without.
IFLA_WEIGHT = 15
IFLA_OPERSTATE = 16
IFLA_LINKMODE = 17
IFLA_LINKINFO = 18
IFLA_NET_NS_PID = 19

#
# PROTINFO sub TLV IDs.
#
IFLA_INET6_UNSPEC = 0
IFLA_INET6_FLAGS = 1
IFLA_INET6_CONF = 2
IFLA_INET6_STATS = 3
IFLA_INET6_MCAST = 4
IFLA_INET6_CACHEINFO = 5
IFLA_INET6_ICMP6STATS = 6

#
# PREFIX TLV IDs.
#
PREFIX_UNSPEC = 0		# Unused.
PREFIX_ADDRESS = 1		# The address prefix itself.
PREFIX_CACHEINFO = 2		# (uint32_t,uint32_t) preferred, valid times.

#
# IPv6 prefix message flags.
#
IF_PREFIX_ONLINK = 0x01
IF_PREFIX_AUTOCONF = 0x02


class NexthopField(pcs.CompoundField):
    """An RTnetlink nexthop field contains information about each
       candidate next-hop known to the forwarding plane for a given prefix."""

    _flag_bits = "\x01DEAD\x02PERVASIVE\x03ONLINK"

    def __init__(self, name, **kv):
        self.packet = None
        self.name = name

        self.len = pcs.Field("len", 16)
        self.flags = pcs.Field("flags", 8)
        self.hops = pcs.Field("hops", 8)
        self.ifindex = pcs.Field("ifindex", 32)
        self.tlvs = pcs.OptionListField("tlvs")

        # XXX I actually have variable width when I am being encoded,
        # OptionList deals with this.
        self.width = self.len.width + self.flags.width + \
                     self.hops.width + self.ifindex.width + \
                     self.tlvs.width

        # If keyword initializers are present, deal with the syntactic sugar.
        # TODO: Figure out how to initialize the TLVs inside our TLV...
        if kv is not None:
            for kw in kv.iteritems():
                if kw[0] in self.__dict__:
                    if kw[0] == 'tlvs':
                        if not isinstance(kw[1], list):
                            if __debug__:
                                print "argument is not a list"
                            continue
                        #for src in kw[1]:
                        #    if not isinstance(src, int):
                        #        if __debug__:
                        #            print "source is not an IPv4 address"
                        #        continue
                        #    self.sources.append(pcs.Field("", 32, default=src))
                    else:
                        self.__dict__[kw[0]].value = kw[1]

    def __repr__(self):
        return "<rtnetlink.NexthopField len %s, flags %s, " \
               "hops %s, ifindex %s, tlvs %s>" \
                % (self.len, self.flags, self.hops, \
                   self.ifindex, self.tlvs)

    def __str__(self):
        """Walk the entire field and pretty print the values of the fields."""
        retval = " Nexthop\n"
        retval += "Len %d\n" % self.len.value
        retval += "Flags %s\n" % bsprintf(self.flags.value, self._flag_bits)
        retval += "Hops %d\n" % self.hops.value
        retval += "Ifindex %s\n" % self.ifindex.value
        retval += "TLVs "
        i = False
        for s in self.tlvs._options:
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

    def decode(self, bytes, curr, byteBR):
        start = curr

        [self.len.value, curr, byteBR] = self.len.decode(bytes,
                                                           curr, byteBR)
        [self.flags.value, curr, byteBR] = self.flags.decode(bytes,
                                                           curr, byteBR)
        [self.hops.value, curr, byteBR] = self.hops.decode(bytes,
                                                           curr, byteBR)
        [self.ifindex.value, curr, byteBR] = self.ifindex.decode(bytes,
                                                           curr, byteBR)
        # TODO Parse TLVs.
        #endp = curr + (self.nsources.value * 4)
        #remaining = len(bytes) - curr
        #endp = min(endp, remaining)
        #while curr < endp:
        #    src = pcs.Field("", 32)
        #    [src.value, curr, byteBR] = src.decode(bytes, curr, byteBR)
        #    self.sources.append(src)
        #curr += auxdatalen

        #delta = curr - start
        #self.width = 8 * delta

        return [bytes, curr, byteBR]

    def encode(self, bytearray, value, byte, byteBR):
        """Encode a NexthopField."""
        [byte, byteBR] = self.len.encode(bytearray, self.len.value,
                                         byte, byteBR)
        [byte, byteBR] = self.flags.encode(bytearray,
                                           self.flags.value,
                                           byte, byteBR)
        [byte, byteBR] = self.hops.encode(bytearray, self.hops.value,
                                          byte, byteBR)
        [byte, byteBR] = self.ifindex.encode(bytearray, self.ifindex.value,
                                             byte, byteBR)
        # XXX TODO encode the TLVs.
        return [byte, byteBR]

    def bounds(self, value):
        """Check the bounds of this field."""
        # XXX assume maxwidth is inclusive
	minwidth = self.len.width + self.flags.width + \
                   self.hops.width + self.ifindex.width
	maxwidth = (2 ** self.len.width) * 8
	if self.width < minwidth or self.width > maxwidth:
            raise FieldBoundsError, "NexthopField must be between %d " \
                                    "and %d bytes wide" % (minwidth, maxwidth)

    def __eq__(self, other):
        """Test two NexthopFields for equality."""
        if other is None:
            return False
        if self.len.value == other.type.value and \
           self.flags.value == other.auxdatalen.value and \
           self.hops.value == other.nsources.value and \
           self.ifindex.value == other.group.value:
            # TODO Also compare sub TLVs.
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def default_compare(lp, lf, rp, rf):
        """Default comparison method."""
        return lf.__eq__(rf)

    default_compare = staticmethod(default_compare)


class ifaddrmsg(pcs.Packet):
    """RFC 3549 interface address message."""

    _layout = pcs.Layout()
    _map = None
    _descr = None
    _flag_bits = "\x01SECONDARY\x02NODAD\x03OPTIMISTIC"\
                 "\x05HOMEADDRESS\x06DEPRECATED"\
                 "\x07TENTATIVE\x08PERMANENT"

    def __init__(self, bytes = None, timestamp = None, **kv):
        family = pcs.Field("family", 8)
        prefixlen = pcs.Field("pad00", 8)
        flags = pcs.Field("flags", 8)
        scope = pcs.Field("scope", 8)
        index = pcs.Field("index", 32)
        #tlvs = pcs.OptionListField("tlvs")

        pcs.Packet.__init__(self, [family, prefixlen, flags, scope, index],\
                            bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            remaining = len(bytes) - offset
            # TODO demux TLVs.
            if self.data is None:
                self.data = payload.payload(bytes[offset:remaining], \
                                            timestamp=timestamp)
        else:
            self.data = None

# TODO: Parse my embedded TLVs.
# XXX To decapsulate I need to know my type and address family.
class ifinfomsg(pcs.Packet):
    """RFC 3549 interface information message."""

    _layout = pcs.Layout()
    _map = None
    _descr = None
    _flag_bits = \
    "\x01UP\x02BROADCAST\x03DEBUG\x04LOOPBACK"\
    "\x05POINTOPOINT\x06NOTRAILERS\x07RUNNING"\
    "\x08NOARP\x09PROMISC\x0aALLMULTI"\
    "\x0bMASTER\x0cSLAVE\x0dMULTICAST"\
    "\x0ePORTSEL\x0fAUTOMEDIA\x10DYNAMIC"\
    "\x11LOWER_UP\x12DORMANT\x13ECHO"

    def __init__(self, bytes = None, timestamp = None, **kv):
        family = pcs.Field("family", 8)
        pad00 = pcs.Field("pad00", 8)
        type = pcs.Field("type", 16)
        index = pcs.Field("index", 32)
        flags = pcs.Field("flags", 32)
        change = pcs.Field("change", 32)
        #tlvs = pcs.OptionListField("tlvs")

        pcs.Packet.__init__(self, [family, pad00, type, index, flags, change],\
                            bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            remaining = len(bytes) - offset
            # TODO demux TLVs.
            if self.data is None:
                self.data = payload.payload(bytes[offset:remaining], \
                                            timestamp=timestamp)
        else:
            self.data = None


class prefixmsg(pcs.Packet):
    """RTnetlink prefix information message. Not in RFC."""

    _layout = pcs.Layout()
    _map = None
    _descr = None
    _flagbits = "\x01ONLINK\x02AUTOCONF"

    def __init__(self, bytes = None, timestamp = None, **kv):
        """ Define the common RTNetlink message header."""
        family = pcs.Field("family", 8)
        pad1 = pcs.Field("pad1", 8)
        pad2 = pcs.Field("pad2", 16)
        ifindex = pcs.Field("ifindex", 32)
        type = pcs.Field("type", 8)
        len = pcs.Field("len", 8)
        flags = pcs.Field("flags", 8)
        pad3 = pcs.Field("pad3", 8)
        #tlvs = pcs.OptionListField("tlvs")

        pcs.Packet.__init__(self, [family, pad1, pad2, ifindex, type, \
                                   len, flags, pad3], \
                            bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            remaining = len(bytes) - offset
            if self.data is None:
                self.data = payload.payload(bytes[offset:remaining], \
                                            timestamp=timestamp)
        else:
            self.data = None


# TODO: Parse my embedded TLVs.
# XXX To decapsulate I need to know my type and address family.
class rtmsg(pcs.Packet):
    """RFC 3549 routing message."""

    _layout = pcs.Layout()
    _map = None
    _descr = None
    _flag_bits = "\x09NOTIFY\x0aCLONED\x0bEQUALIZE\x0cPREFIX"

    def __init__(self, bytes = None, timestamp = None, **kv):
        """ Define the common RTNetlink message header."""
        family = pcs.Field("family", 8)
        dst_len = pcs.Field("dst_len", 8)
        src_len = pcs.Field("src_len", 8)
        tos = pcs.Field("tos", 8)
        table = pcs.Field("table", 8)
        protocol = pcs.Field("protocol", 8)
        scope = pcs.Field("scope", 8)
        type = pcs.Field("type", 8)
        flags = pcs.Field("flags", 32)
        #tlvs = pcs.OptionListField("tlvs")

        pcs.Packet.__init__(self, [family, dst_len, src_len, tos, table, \
                                   protocol, scope, type, flags], \
                            bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()
            remaining = len(bytes) - offset
            # TODO demux TLVs.
            if self.data is None:
                self.data = payload.payload(bytes[offset:remaining], \
                                            timestamp=timestamp)
        else:
            self.data = None

    def next(self, bytes, timestamp):
        """Decode next layer of encapsulation."""
        #if (self.dport in udp_map.map):
        #    return udp_map.map[self.dport](bytes, timestamp = timestamp)
        #if (self.sport in udp_map.map):
        #    return udp_map.map[self.sport](bytes, timestamp = timestamp)
        return None

    def rdiscriminate(self, packet, discfieldname=None, map = nlmsg_map):
        """Reverse-map an encapsulated packet back to a discriminator
           field value. Like next() only the first match is used."""
        return pcs.Packet.rdiscriminate(self, packet, "type", map)

    def __str__(self):
        """Pretty-print fields."""
        s = "RTNetlink\n"
        #s = "Netlink " + self._descr[self._fieldnames['type']] + "\n"
        for fn in self._layout:
            f = self._fieldnames[fn.name]
            if fn.name == "flags":
                value = bsprintf(f.value, self._flag_bits)
                s += "%s %s\n" % (fn.name, value)
            else:
                s += "%s %s\n" % (fn.name, f.value)
        return s

    #def calc_lengths(self):
