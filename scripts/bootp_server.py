#!/usr/bin/env python

# Not useful with Busybox udhcpc, which does not accept BOOTP replies.
#
# Also, for this to work properly with tap interfaces and PCAP, your
# QEMU instances really need to be in sync with the addresses
# assigned to the tap interfaces -- otherwise the outgoing traffic
# will just get dropped, unless you source the traffic from a bridge
# interface.

import random

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.udpv4 import *
from pcs.packets.dhcpv4 import *
from pcs import *
from time import sleep

# This hack by: Raymond Hettinger
class hexdumper:
    """Given a byte array, turn it into a string. hex bytes to stdout."""
    def __init__(self):
	self.FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' \
						    for x in range(256)])

    def dump(self, src, length=8):
	result=[]
	for i in xrange(0, len(src), length):
	    s = src[i:i+length]
	    hexa = ' '.join(["%02X"%ord(x) for x in s])
	    printable = s.translate(self.FILTER)
	    result.append("%04X   %-*s   %s\n" % \
			  (i, length*3, hexa, printable))
	return ''.join(result)

gw = "10.1.1.17"
subnet = "255.255.255.0"

# note: leading zeroes must be trimmed.
map = {
	"52:54:0:12:34:56":	"192.168.0.2"
}

def main():

    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option("-d", "--devname",
                      dest="devname", default=None,
                      help="The name of the tap device to open.")

    parser.add_option("-i", "--ifname",
                      dest="ifname", default=None,
                      help="The name of the interface to listen on.")

    parser.add_option("-g", "--group",
                      dest="group", default=None,
                      help="The IPv4 group to use for UML-style multicasts.")

    parser.add_option("-p", "--port",
                      dest="port", default=None,
                      help="The IPv4 port to use for UML-style multicasts.")

    parser.add_option("-a", "--ifaddr",
                      dest="ifaddr", default=None,
                      help="The IP address to listen on.")

    parser.add_option("-S", "--ether_source",
                      dest="ether_source", default=None,
                      help="The Ethernet address to listen on.")

    (options, args) = parser.parse_args()


    if options.devname is not None:
        input = TapConnector(options.devname)
        output = input
    elif options.group is not None:
        if options.port is None:
	    print "Non-optional argument missing."
	    return
        # XXX Currently, UmlMcast4Connector has to use the same broken
        # semantics as QEMU does, to see its traffic -- apps SHOULD be
        # joining groups on specific interfaces.
        # Note that we'll also end up seeing our own traffic.
        #input = UmlMcast4Connector(options.group, options.port, options.ifaddr)
        input = UmlMcast4Connector(options.group, options.port, "0.0.0.0")
        output = input
    elif options.ifname is not None:
        input = PcapConnector(options.ifname)
        output = PcapConnector(options.ifname)
        input.setfilter("udp port 67 or udp port 68")

    if options.ifaddr is None or \
       options.ether_source is None:
	print "Non-optional argument missing."
	return

    ifaddr = inet_atol(options.ifaddr)
    ether_source = ether_atob(options.ether_source)

    ip_id = int(random.random() * 32768)

    # XXX Should really have an API for extracting our
    # local ethernet address.

    running = True
    while running is True:
        packet = input.readpkt()
	chain = packet.chain()

	# Must have: ether + ip + udp + dhcp.
	# UDP checksum ignored. Assume pcap filter above did its job.
	if len(chain.packets) < 4 or \
	   not isinstance(chain.packets[3], dhcpv4):
	    continue

	i_ether = chain.packets[0]
	i_ip = chain.packets[1]
	i_udp = chain.packets[2]
	i_dhcp = chain.packets[3]

	# check dhcp htype is ethernet.
	# check if dhcp.cid in map.

	if i_dhcp.op != pcs.packets.dhcpv4.BOOTREQUEST or \
	   i_dhcp.htype != pcs.packets.dhcpv4.HTYPE_ETHER or \
	   i_dhcp.hlen != 6:
	    continue

	#print i_dhcp

	chaddr_s = ether_btoa(i_dhcp.chaddr[:i_dhcp.hlen])
	if not chaddr_s in map:
	    print "%s not in map" % chaddr_s
	    continue

	ciaddr = inet_atol(map[chaddr_s])	# from map

	dhcp = dhcpv4()
	dhcp.op = pcs.packets.dhcpv4.BOOTREPLY
	dhcp.htype = pcs.packets.dhcpv4.HTYPE_ETHER
	dhcp.hlen = 6
	dhcp.hops = 0
	dhcp.xid = i_dhcp.xid
	dhcp.flags = 0

	#dhcp.ciaddr = ciaddr
	dhcp.siaddr = ifaddr

	# XXX should only fill out if i_dhcp.ciaddr was 0.0.0.0
	dhcp.yiaddr = ciaddr

	dhcp.chaddr = i_dhcp.chaddr
	#dhcp.sname = "myhost"
	#dhcp.file = "/vmunix"

	#dhcp.options.append(dhcpv4_options.cookie().field())

	# server ID.
	# XXX Weeiiird!
	#sid = dhcpv4_options.dhcp_server_identifier()
	#sid.value = ifaddr
	#sid.value = inet_atol("0.0.0.0")
	#dhcp.options.append(sid.field())

	# Subnet mask.
	#sm = dhcpv4_options.subnet_mask()
	#sm.value = inet_atol("255.255.255.0")
	#dhcp.options.append(sm.field())

	# Default gateway.
	#dg = dhcpv4_options.routers()
	#dg.value = ifaddr
	#dhcp.options.append(dg.field())

	# Add end marker.
	#end = dhcpv4_options.end()
	#dhcp.options.append(end.field())

	# Pad BOOTP payload to 32-bit width.
	# XXX BOOTP is problematic because the field which contains
	# the options needs to be clamped to 64 bytes in total. This
	# means we need to know the encoded length of each option.
	# For now, guess it... total length of an RFC-951 payload
	# is always 300 bytes.
	# this shuts up wireshark.
	#padlen = 300 - (len(dhcp.bytes) % 4)
	#padlen = 50 - (len(dhcp.bytes) % 4)
	#padlen = 4
	#pad = dhcpv4_options.pad(padlen)
	#dhcp.options.append(pad.field())

	# Encapsulate ethernet.
	ether = ethernet()
	ether.type = 0x0800
	ether.src = ether_source
	ether.dst = i_dhcp.chaddr[:i_dhcp.hlen]

	# Encapsulate IPv4.
	ip = ipv4()
	ip.version = 4
	ip.hlen = 5
	ip.tos = 0
	ip.id = ip_id
	ip.flags = 0x00
	ip.offset = 0
	ip.ttl = 1
	ip.protocol = IPPROTO_UDP
	ip.src = ifaddr
	ip.dst = ciaddr

	ip_id += 1

	# Encapsulate UDPv4.
	udp = udpv4()
	udp.sport = 67
	udp.dport = 68
	udp.length = len(dhcp.bytes)
	udp.checksum = udp.cksum(ip, dhcp.bytes)

	# Compute header checksums.
	ip.length = len(ip.bytes) + len(udp.bytes) + len(dhcp.bytes)
	ip.checksum = ip.cksum()

	# Send the lot.
	packet = Chain([ether, ip, udp, dhcp])
	packet.encode()
	out = output.write(packet.bytes, len(packet.bytes))
	print out

main()
