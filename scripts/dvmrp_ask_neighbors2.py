#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmpv2 import *
from pcs.packets.dvmrp import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

#
# Send a DVMRP "ask neighbors" query (basically, clone the mrinfo tool).
#

def main():

    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option("-I", "--ether_iface",
                      dest="ether_iface", default=None,
                      help="The name of the source interface.")

    parser.add_option("-e", "--ether_source",
                      dest="ether_source", default=None,
                      help="The host Ethernet source address.")

    parser.add_option("-G", "--ether_dest",
                      dest="ether_dest", default=None,
                      help="The gateway Ethernet destination address.")

    parser.add_option("-s", "--ip_source",
                      dest="ip_source", default=None,
                      help="The IP source address.")

    parser.add_option("-d", "--ip_dest",
                      dest="ip_dest", default=None,
                      help="The IP destination address.")

    parser.add_option("-c", "--count",
                      dest="count", default=None,
                      help="Stop after receiving at least count responses.")

    (options, args) = parser.parse_args()

    if options.ether_iface is None or \
       options.ether_source is None or \
       options.ether_dest is None or \
       options.ip_source is None or \
       options.count is None:
        print "Non-optional argument missing."
        return

    # Set up the vanilla packet
    ether = ethernet()
    ether.type = 0x0800
    ether.src = ether_atob(options.ether_source)
    ether.dst = ether_atob(options.ether_dest)

    ip = ipv4()
    ip.version = 4
    ip.hlen = 5
    ip.tos = 0
    ip.id = 0
    ip.flags = 0x02		# DF (yes, it's byte swapped here).
    ip.offset = 0
    ip.ttl = 1
    ip.protocol = IPPROTO_IGMP
    ip.src = inet_atol(options.ip_source)

    if options.ip_dest is None:
        ip.dst = INADDR_DVMRP_GROUP
    else:
        ip.dst = inet_atol(options.ip_dest)


    #
    # DVMRP "ask neighbors" does not contain the Router Alert option,
    # because DVMRP traffic is usually tunneled, and we don't need to
    # wake up every router on the path.
    #
    # The Ask_neighbors2 payload is: reserved, caps, minor, major:
    # 0x00, 0E, 0xFF, 0x03 is how mrinfo fills this out (DVMRPv3 compliant).
    #
    # PIM itself knows nothing about these messages, however, a DVMRP router
    # which handles these messages MAY tell you if it's peering with other
    # PIM routers (I believe only Ciscos do this).
    #
    # TODO: Hook dvmrp up to the base igmp header somehow.

    d = dvmrp()
    d.version = 1
    d.type = 3
    d.subtype = DVMRP_ASK_NEIGHBORS2

    d.capabilities = DVMRP_CAP_DEFAULT
    d.minor = 0xFF
    d.major = 3

    d_p = Chain([d])
    d.checksum = d_p.calc_checksum()

    ip.length = len(ip.bytes) + len(d.bytes)
    ip.checksum = ip.cksum()

    packet = Chain([ether, ip, d])
    packet.encode()
    
    input = PcapConnector(options.ether_iface)
    input.setfilter("igmp")

    output = PcapConnector(options.ether_iface)
    out = output.write(packet.bytes, len(packet.bytes))

    #
    # Wait for up to 'count' responses to the query to arrive and print them.
    #
    count = int(options.count)
    while count > 0:
        packet = input.readpkt()
        chain = packet.chain()
	if chain.packets[2].type == IGMP_DVMRP:
	    print chain.packets[2].println()
	    #print "%s is in %s" % \
	    #    (inet_ntop(AF_INET, struct.pack('!L', chain.packets[1].src)), \
	    #     inet_ntop(AF_INET, struct.pack('!L', chain.packets[2].group)))
	    count -= 1

main()
