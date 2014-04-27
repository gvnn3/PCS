# Copyright (c) 2008, Bruce M. Simpson
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
# File: $Id$
#
# Author: Bruce M. Simpson
#
# Description: A dictionary driven DHCPv4 option parser.

import pcs
import struct

DHCP_OPTIONS_COOKIE = 0x63825363

DHO_PAD = 0
DHO_END = 255

DHO_SUBNET_MASK = 1
DHO_TIME_OFFSET = 2
DHO_ROUTERS = 3
DHO_TIME_SERVERS = 4
DHO_NAME_SERVERS = 5
DHO_DOMAIN_NAME_SERVERS = 6
DHO_LOG_SERVERS = 7
DHO_COOKIE_SERVERS = 8
DHO_LPR_SERVERS = 9
DHO_IMPRESS_SERVERS = 10
DHO_RESOURCE_LOCATION_SERVERS = 11
DHO_HOST_NAME = 12
DHO_BOOT_SIZE = 13
DHO_MERIT_DUMP = 14
DHO_DOMAIN_NAME = 15
DHO_SWAP_SERVER = 16
DHO_ROOT_PATH = 17
DHO_EXTENSIONS_PATH = 18
DHO_IP_FORWARDING = 19
DHO_NON_LOCAL_SOURCE_ROUTING = 20
DHO_POLICY_FILTER = 21
DHO_MAX_DGRAM_REASSEMBLY = 22
DHO_DEFAULT_IP_TTL = 23
DHO_PATH_MTU_AGING_TIMEOUT = 24
DHO_PATH_MTU_PLATEAU_TABLE = 25
DHO_INTERFACE_MTU = 26
DHO_ALL_SUBNETS_LOCAL = 27
DHO_BROADCAST_ADDRESS = 28
DHO_PERFORM_MASK_DISCOVERY = 29
DHO_MASK_SUPPLIER = 30
DHO_ROUTER_DISCOVERY = 31
DHO_ROUTER_SOLICITATION_ADDRESS = 32
DHO_STATIC_ROUTES = 33
DHO_TRAILER_ENCAPSULATION = 34
DHO_ARP_CACHE_TIMEOUT = 35
DHO_IEEE802_3_ENCAPSULATION = 36
DHO_DEFAULT_TCP_TTL = 37
DHO_TCP_KEEPALIVE_INTERVAL = 38
DHO_TCP_KEEPALIVE_GARBAGE = 39
DHO_NIS_DOMAIN = 40
DHO_NIS_SERVERS = 41
DHO_NTP_SERVERS = 42
DHO_VENDOR_ENCAPSULATED_OPTIONS = 43
DHO_NETBIOS_NAME_SERVERS = 44
DHO_NETBIOS_DD_SERVER = 45
DHO_NETBIOS_NODE_TYPE = 46
DHO_NETBIOS_SCOPE = 47
DHO_FONT_SERVERS = 48
DHO_X_DISPLAY_MANAGER = 49
DHO_DHCP_REQUESTED_ADDRESS = 50
DHO_DHCP_LEASE_TIME = 51
DHO_DHCP_OPTION_OVERLOAD = 52
DHO_DHCP_MESSAGE_TYPE = 53
DHO_DHCP_SERVER_IDENTIFIER = 54
DHO_DHCP_PARAMETER_REQUEST_LIST = 55
DHO_DHCP_MESSAGE = 56
DHO_DHCP_MAX_MESSAGE_SIZE = 57
DHO_DHCP_RENEWAL_TIME = 58
DHO_DHCP_REBINDING_TIME = 59
DHO_DHCP_CLASS_IDENTIFIER = 60
DHO_DHCP_CLIENT_IDENTIFIER = 61
DHO_SMTP_SERVER = 69
DHO_POP_SERVER = 70
DHO_NNTP_SERVER = 71
DHO_WWW_SERVER = 72
DHO_FINGER_SERVER = 73
DHO_IRC_SERVER = 74
DHO_DHCP_USER_CLASS_ID = 77
DHO_CLASSLESS_ROUTES = 121


# TODO: Rototile these so they can inherit from Field, that way
# the syntax for users can become simpler.

class dhcp_option(object):
    def __init__(self, optno, bytes):
        raise foo("Abstract base class")

    def fieldname(self):
        raise foo("Abstract base class")

    def shortname(self):
        raise foo("Abstract base class")

    def datafield(self):
        raise foo("Abstract base class")

    def field(self):
        raise foo("Abstract base class")


class cookie(dhcp_option):
    def __init__(self, optno = 0x63, bytes = None):
        self.optno = optno

    def fieldname(self):
        return "cookie"

    def shortname(self):
        return "CK"

    def datafield(self):
        return pcs.Field("v", 32, default = DHCP_OPTIONS_COOKIE)

    def field(self):
        """ Return the complete field value as it should be appended to
            the DHCPv4 options payload. """
        return self.datafield()


class end(dhcp_option):
    """ Return a DHCP end marker as a field. There is no TLV. """

    def __init__(self, optno = DHO_END, bytes = None):
        self.optno = optno

    def fieldname(self):
        return "end"

    def shortname(self):
        return "END"

    def datafield(self):
        return pcs.Field("v", 8, default = DHO_END)

    def field(self):
        """ Return the complete field value as it should be appended to
            the DHCPv4 options payload. """
        return self.datafield()


class pad(dhcp_option):
    """ Return a variable length DHCP pad field, which is zero-filled.
        Zero itself is the code. There is no TLV. """

    def __init__(self, len = 1):
        self.len = len

    def fieldname(self):
        return "pad"

    def shortname(self):
        return "PAD"

    def datafield(self):
        return pcs.Field("v", (self.len * 8))

    def field(self):
        """ Return the complete field value as it should be appended to
            the DHCPv4 options payload. """
        return self.datafield()


class tlv_option(dhcp_option):
    """ Base class for a DHCP option in a TLV field. """

    def __init__(self, optno, bytes = None):
        self.optno = optno
        if bytes is not None:
            self.bytes = bytes
        else:
            self.bytes = "\0"

    def __setattr__(self, name, value):
        if name == "value":
           self.bytes = struct.pack("!B", value)
        else:
           object.__setattr__(self, name, value)

    def fieldname(self):
        return "opt-%d" % self.optno

    def shortname(self):
        return "%d" % self.optno

    def datafield(self):
        #return pcs.Field("v", len(self.bytes) * 8, \
        #                 default = struct.unpack("!B", self.bytes)[0])
        return pcs.StringField("v", len(self.bytes) * 8, default = self.bytes)

    def field(self):
        """ Return the complete field value as it should be appended to
            the DHCPv4 options payload. """
        return pcs.TypeLengthValueField( \
            self.fieldname(), \
            pcs.Field("t", 8, default = self.optno), \
            pcs.Field("l", 8, default = len(self.bytes)), \
            self.datafield(), \
            inclusive = False, \
            bytewise = True)


class subnet_mask(tlv_option):

    def __init__(self, optno = DHO_SUBNET_MASK, bytes = None):
        tlv_option.__init__(self, optno, bytes)

    def __setattr__(self, name, value):
        if name == "value":
           self.bytes = struct.pack("!L", value)
        else:
           object.__setattr__(self, name, value)

    def fieldname(self):
        return "netmask"

    def shortname(self):
        return "SM"

    def datafield(self):
        return pcs.Field("", 32, \
                         default = struct.unpack("!L", self.bytes[:4])[0])


class routers(tlv_option):

    def __init__(self, optno = DHO_ROUTERS, bytes = None):
        tlv_option.__init__(self, optno, bytes)

    def __setattr__(self, name, value):
        # XXX Currently only a single gateway is accepted.
        if name == "value":
           self.bytes = struct.pack("!L", value)
        else:
           object.__setattr__(self, name, value)

    def fieldname(self):
        return "routers"

    def shortname(self):
        return "DG"

    def datafield(self):
        return pcs.Field("", 32, \
                         default = struct.unpack("!L", self.bytes[:4])[0])
        #gwlist = []
        #curr = 0
        #while curr < len(self.bytes):
        #    gwlist.append(pcs.Field("", 32, \
        #                 default = struct.unpack("!L", \
        #                                         self.bytes[curr:curr+4])[0]))
        #    curr += 4
        #return gwlist


# The DHCP message type option MUST appear before any other
# options in a BOOTP encapsulated DHCP message.

DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

class dhcp_message_type(tlv_option):

    def __init__(self, optno = DHO_DHCP_MESSAGE_TYPE, bytes = None):
        tlv_option.__init__(self, optno, bytes)

    def fieldname(self):
        return "dhcp-message-type"

    def shortname(self):
        return "DHCP"

    def datafield(self):
        return pcs.Field("", 8, \
                         default = struct.unpack("!B", self.bytes[0])[0])


class dhcp_max_message_size(tlv_option):

    def __init__(self, optno = DHO_DHCP_MAX_MESSAGE_SIZE, bytes = None):
        tlv_option.__init__(self, optno, bytes)

    def __setattr__(self, name, value):
        if name == "value":
           self.bytes = struct.pack("!H", value)
        else:
           object.__setattr__(self, name, value)

    def fieldname(self):
        return "dhcp-max-message-size"

    def shortname(self):
        return "MSZ"

    def datafield(self):
        return pcs.Field("", 16, \
                         default = struct.unpack("!H", self.bytes[:2])[0])


class dhcp_class_identifier(tlv_option):

    def __init__(self, optno = DHO_DHCP_CLASS_IDENTIFIER, bytes = None):
        tlv_option.__init__(self, optno, bytes)

    def __setattr__(self, name, value):
        if name == "value":
           self.bytes = value
        else:
           object.__setattr__(self, name, value)

    def fieldname(self):
        return "dhcp-class-identifier"

    def shortname(self):
        return "VC"

    def datafield(self):
        return pcs.StringField("", 8 * len(self.bytes), default = self.bytes)


# XXX Can't cleanly capture this (yet);
# TypeLengthValueField gets upset if it contains anything other
# than Field or StringField.
class dhcp_client_identifier(tlv_option):

    def __init__(self, optno = DHO_DHCP_CLIENT_IDENTIFIER, bytes = None):
        tlv_option.__init__(self, optno, bytes)

    def __setattr__(self, name, value):
        if name == "type":
            self.bytes[0] = value
        elif name == "value":
            self.bytes[1:] = value
        else:
            object.__setattr__(self, name, value)

    def fieldname(self):
        return "dhcp-client-identifier"

    def shortname(self):
        return "CID"

    def datafield(self):
        return pcs.TypeValueField("", \
                                  pcs.Field("", 8, \
                                    default = \
                                      struct.unpack("!B", self.bytes[0])[0]), \
                                  pcs.StringField("", 8 * len(self.bytes[1:]), \
                                                      default = self.bytes[1:]))


class dhcp_parameter_req_list(tlv_option):

    def __init__(self, optno = DHO_DHCP_PARAMETER_REQUEST_LIST, bytes = None):
        tlv_option.__init__(self, optno, bytes)

    def __setattr__(self, name, value):
        if name == "value":
           self.bytes = value
        else:
           object.__setattr__(self, name, value)

    def fieldname(self):
        return "dhcp-parameter-req-list"

    def shortname(self):
        return "PR"

    def datafield(self):
        return pcs.StringField("", 8 * len(self.bytes), default = self.bytes)


class dhcp_server_identifier(tlv_option):

    def __init__(self, optno = DHO_DHCP_SERVER_IDENTIFIER, bytes = None):
        tlv_option.__init__(self, optno, bytes)

    def __setattr__(self, name, value):
        if name == "value":
           self.bytes = struct.pack("!L", value)
        else:
           object.__setattr__(self, name, value)

    def fieldname(self):
        return "dhcp-server-identifier"

    def shortname(self):
        return "SID"

    def datafield(self):
        return pcs.Field("", 32, \
                         default = struct.unpack("!L", self.bytes[:4])[0])


# FreeBSD's kernel BOOTP client sends only MSZ, VC, DHCP options.
#  ...but it always expects a SID.
# Busybox udhcp sends CID, PR, VC, DHCP.
# 

map = {
   # option ID                  class name              tcpdump mnemonic
   DHO_SUBNET_MASK:             subnet_mask,            # SM
   DHO_ROUTERS:                 routers,                # DG
   DHO_DHCP_MESSAGE_TYPE:       dhcp_message_type,      # DHCP
   DHO_DHCP_MAX_MESSAGE_SIZE:   dhcp_max_message_size,  # MSZ
   DHO_DHCP_SERVER_IDENTIFIER:  dhcp_server_identifier, # SID
   DHO_DHCP_PARAMETER_REQUEST_LIST: dhcp_parameter_req_list, # PR
   DHO_DHCP_CLASS_IDENTIFIER:   dhcp_class_identifier,  # VC
   #DHO_DHCP_CLIENT_IDENTIFIER: dhcp_client_identifier  # CID
}

