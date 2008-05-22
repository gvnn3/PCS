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
# Description: Classes which describe RFC 3549 Netlink socket messages.
#

import inspect
import struct
import time

import pcs
import payload

# TODO: Test all this.

# TODO: add AF_NETLINK, PF_NETLINK and struct sockaddr_nl where needed.
# Socket options; not yet needed.
#NETLINK_ADD_MEMBERSHIP = 1
#NETLINK_DROP_MEMBERSHIP = 2
#NETLINK_PKTINFO = 3		# returns a uint32_t (group)

#
# Netlink link types.
#
# Netlink is a full-blown socket address family, so the subsystem(s)
# which send messages will have a sockaddr filled out.
# Currently this module only supports the routing messages.
#
NETLINK_ROUTE = 0

# nlmsg_type
NLMSG_NOOP = 0x1
NLMSG_ERROR = 0x2
NLMSG_DONE = 0x3	# end of multipart.
NLMSG_OVERRUN = 0x4	# unused?

# nlmsg_flags
NLM_F_REQUEST = 1
NLM_F_MULTI = 2
NLM_F_ACK = 4
NLM_F_ECHO = 8
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = 0x300	# or'd
NLM_F_ATOMIC = 0x400
NLM_F_REPLACE = 0x100
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLM_F_APPEND = 0x800

# TODO: nlattr tlvs.
NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000

class nlmsg_error(pcs.Packet):
    """If type is NLMSG_ERROR, original message generating error
       is returned as payload with error code prepended, just like ICMP."""

    _layout = pcs.Layout()
    _map = None
    _descr = None

    def __init__(self, bytes = None, timestamp = None, **kv):
        error = pcs.Field("error", 32)

        pcs.Packet.__init__(self, [error], bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # XXX To avoid introducing a circular dependency in this module,
        # the caller is responsible for trying to decode the payload
        # as an nlmsghdr chain.
        if bytes is not None:
            self.data = payload.payload(bytes[offset:len(bytes)])
        else:
            self.data = None

# XXX Move these to a separate file. The map needs to live outside
# to avoid circular dependencies, and to make it easier to
# introduce parsers for dealing with subsystems e.g. rtnetlink.
nlmsg_map = {
	NLMSG_NOOP:	payload.payload,
	NLMSG_ERROR:	nlmsg_error
}

descr = {
	NLMSG_NOOP:	"Noop",
	NLMSG_ERROR:	"Error"
}

# XXX Can't fully discriminate without knowing which subsystem
# the message was sent from.
class nlmsghdr(pcs.Packet):
    """RFC 3549 Netlink socket message header."""

    _layout = pcs.Layout()
    #_map = nlmsg_map
    #_descr = descr
    _map = nlmsg_map
    _descr = descr

    # Python string literals for bsprintf() need to contain hex
    # embedded characters.
    _flag_bits = "\x01REQUEST\x02MULTI\x03ACK\x04ECHO"\
                 "\x09ROOT\x0aMATCH\x0bATOMIC"\
                 "\x0dREPLACE\x0eEXCL\x0fCREATE"\
                 "\x10APPEND"

    def __init__(self, bytes = None, timestamp = None, **kv):
        """ Define the common Netlink message header."""
        len = pcs.Field("len", 32)
        type = pcs.Field("type", 16, discriminator=True)
        flags = pcs.Field("flags", 16)
        seq = pcs.Field("seq", 32)
        pid = pcs.Field("pid", 32)	# Port ID

        pcs.Packet.__init__(self, [len, type, flags, seq, pid], \
                            bytes = bytes, **kv)
        self.description = inspect.getdoc(self)

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if bytes is not None:
            offset = self.sizeof()

            # XXX Check and use the length field.
            remaining = min(len(bytes), self.len) - offset
            if remaining < 0:
                remaining = len(bytes)

            # Only use the external map to look up the payload type
            # if it isn't of a type we know about.
            if self._fieldnames['type'].value == NLMSG_ERROR:
                self.data = nlmsg_error(bytes[offset:remaining], \
                                        timestamp=timestamp)
            elif (self._fieldnames['type'].value != NLMSG_NOOP) and
                 (self._fieldnames['type'].value != NLMSG_DONE):
                self.data = self.next(bytes[offset:remaining], \
                                      timestamp=timestamp)

            # If we failed to look up a payload type, assume that
            # the payload is opaque.
            if self.data is None:
                self.data = payload.payload(bytes[offset:remaining], \
                                            timestamp=timestamp)
        else:
            self.data = None

    # XXX TODO: fit rtnetlink in here.
    def next(self, bytes, timestamp):
        """Decode next layer of encapsulation."""
        #if (self.dport in udp_map.map):
        #    return udp_map.map[self.dport](bytes, timestamp = timestamp)
        #if (self.sport in udp_map.map):
        #    return udp_map.map[self.sport](bytes, timestamp = timestamp)
        return None

    # XXX TODO: fit rtnetlink in here.
    def rdiscriminate(self, packet, discfieldname=None, map = nlmsg_map):
        """Reverse-map an encapsulated packet back to a discriminator
           field value. Like next() only the first match is used."""
        # XXX The type field MAY have meaning which is specific to
        # the group where this Netlink format message came from.
        return pcs.Packet.rdiscriminate(self, packet, "type", map)

    def __str__(self):
        """Pretty-print fields."""
        s = "Netlink\n"
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

