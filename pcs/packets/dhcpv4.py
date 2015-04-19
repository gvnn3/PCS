# Copyright (c) 2008, Bruce M. Simpson
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
# Neither the name of the authors nor the names of contributors may be
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
# File: $Id: dhcpv4.py,v 1.4 2006/06/27 14:45:43 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A class implementing a DHCPv4 packet (RFC 951, RFC 2132).
#

import sys
sys.path.append("../src")

import pcs
import struct
import time

from socket import inet_ntop
#from pcs.packets.ethernet import ether_btoa
from pcs.packets import payload

from . import dhcpv4_options

# BOOTP opcodes.
BOOTREQUEST = 1
BOOTREPLY = 2

# BOOTP flags.
BOOTP_BROADCAST = 0x8000

# Hardware address types.
HTYPE_ETHER = 1
HTYPE_IEEE802 = 2
HTYPE_FDDI = 8

# MUST be present if BOOTP vendor options or DHCP is in use.
DHCP_OPTIONS_COOKIE = 0x63825363

# DHCP 'special' options, used to pad or mark end of options.
DHO_PAD = 0
DHO_END = 255

class dhcpv4(pcs.Packet):

    _layout = pcs.Layout()

    def __init__(self, pdata = None, timestamp = None, **kv):
        """Initialize a DHCPv4 packet. """

        op = pcs.Field("op", 8)
        htype = pcs.Field("htype", 8)
        hlen = pcs.Field("hlen", 8)
        hops = pcs.Field("hops", 8)
        xid = pcs.Field("xid", 32)
        secs = pcs.Field("secs", 16)
        flags = pcs.Field("flags", 16)

        ciaddr = pcs.Field("ciaddr", 32)
        yiaddr = pcs.Field("yiaddr", 32)
        siaddr = pcs.Field("siaddr", 32)
        giaddr = pcs.Field("giaddr", 32)

        chaddr = pcs.StringField("chaddr", 16*8)
        sname = pcs.StringField("sname", 64*8)
        file = pcs.StringField("file", 128*8)

        options = pcs.OptionListField("options")

        pcs.Packet.__init__(self, [op, htype, hlen, hops, xid, \
                                   secs, flags, \
                                   ciaddr, yiaddr, siaddr, giaddr, \
                                   chaddr, sname, file, options], \
                            pdata = pdata, **kv)
        self.description = "Initialize a DHCPv4 packet. "

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        # Always point beyond the static payload so that we take the
        # correct slice as a vanilla payload iff no options are parsed.
        curr = self.sizeof()
        #print "self.sizeof() %d\n" % curr
        if pdata is not None:
            opts_off = curr
            end = len(pdata)
            if (end - curr) > 4:
                # If the DHCP cookie is present, we append it to the
                # options list so it will be reflected if we re-encode.
                # If it is not present, we set the remaining counter to 0
                # so that the options list loop will not execute.
                cval = struct.unpack('!L', pdata[curr:curr+4])[0]
                if cval == DHCP_OPTIONS_COOKIE:
                    options.append(pcs.Field("cookie", 32, default = cval))
                    curr += 4
                else:
                    end = 0

                while curr < end:
                    option = struct.unpack('!B', pdata[curr])[0]

                    # Special-case options which have only a type field
                    # and no data or length field.
                    if option == DHO_PAD:               # pad
                        # Chew adjacent pdata into a single field.
                        ps = curr
                        pc = ps
                        while pc < end:
                            pb = struct.unpack('!B', pdata[pc])[0]
                            if pb != 0:
                                break
                            pc += 1
                        padlen = pc - ps
                        #print "got %d pad pdata\n" % (padlen)
                        options.append(pcs.Field("pad", padlen * 8))
                        curr += padlen
                        continue
                    elif option == DHO_END:             # end
                        options.append(pcs.Field("end", 8, default = option))
                        curr += 1
                        continue

                    # All DHCP options have a type byte, a length byte,
                    # and a payload. The length byte does NOT include
                    # the length of the other fields.
                    curr += 1
                    optlen = struct.unpack('!B', pdata[curr:curr+1])[0]
                    if (optlen < 1 or ((curr + optlen) > end)):
                        raise UnpackError("Bad length %d for DHCPv4 option %d" % \
                              (optlen, option))

                    # Attempt to parse this DHCP option.
                    # Note well: unlike TCP and IP options, the length field
                    # in a DHCP option field does not include the length
                    # and type pdata.
                    # The map contains functions which take the option
                    # list and byte array as parameters, and return a
                    # reference to a class which wraps that option. All
                    # are derived from a base class containing the generic
                    # option parsing logic.
                    # TODO: Use this technique for IGMP, IP and TCP options.
                    curr += 1
                    optinst = None
                    if option in dhcpv4_options.map:
                        optinst = \
                            dhcpv4_options.map[option](option, \
                                                       pdata[curr:curr+optlen])
                    else:
                        optinst = \
                            dhcpv4_options.tlv_option(option, \
                                                      pdata[curr:curr+optlen])

                    options.append(optinst.field())
                    curr += optlen

        if pdata is not None and curr < len(pdata):
            self.data = payload.payload(pdata[curr:len(pdata)])
        else:
            self.data = None

    def __str__(self):
        """Walk the entire packet and pretty print the values of the fields.  Addresses are printed if and only if they are set and not 0."""
        retval = "DHCP\n"
        for field in self._layout:
            retval += "%s %s\n" % (field.name, field.value)
        return retval

    def pretty(self, attr):
        """Pretty print address fields. """
        if attr == "ciaddr" or attr == "yiaddr" or \
           attr == "siaddr" or attr == "giaddr":
                return inet_ntop(AF_INET,
                                 struct.pack('!L', getattr(self,attr)))
        #elif attr == "chaddr" and self.htype == HTYPE_ETHER:
        #    return ether_btoa(getattr(self, attr))
