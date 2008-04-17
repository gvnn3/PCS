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

class dhcpv4_option(object):

    def __init__(self, option, bytes):
	self.option = option
	self.bytes = bytes

    def fieldname(self):
	return "opt-%d" % option

    def datafield(self):
	return pcs.Field("v", len(self.bytes) * 8, \
			 default = struct.unpack("!B", self.bytes)[0])

    def tlvfield(self):
	return pcs.TypeLengthValueField( \
	    self.fieldname,
	    pcs.Field("t", 8, default = option), \
	    pcs.Field("l", 8, default = len(self.bytes)), \
	    self.datafield)

class subnet_mask(dhcpv4_option):

    def __init__(self, option, bytes):
	dhcp_option.__init__(self, option, bytes)

    def fieldname(self):
	return "netmask"

    def datafield(self):
	return pcs.Field("", 32, \
		         default = struct.unpack("!L", self.bytes[:4])[0])

class routers(dhcpv4_option):

    def __init__(self, option, bytes):
	dhcp_option.__init__(self, option, bytes)

    def fieldname(self):
	return "gw"

    def datafield(self):
	gwlist = []
	curr = 0
	while curr < len(self.bytes):
	    gwlist.append(pcs.Field("", 32, \
		          default = struct.unpack("!L", \
						  self.bytes[curr:curr+4])[0]))
	    curr += 4
	return gwlist

map = {
   DHO_SUBNET_MASK:		subnet_mask,
   DHO_ROUTERS:			routers
}

