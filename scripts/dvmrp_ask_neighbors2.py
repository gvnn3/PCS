#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmp import *
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

    if options.ip_dest is None:
        idst = INADDR_DVMRP_GROUP
    else:
        idst = inet_atol(options.ip_dest)

    c = ethernet(src=ether_atob(options.ether_source), \
                 dst=ether_atob(options.ether_dest)) / \
        ipv4(ttl=1, src=inet_atol(options.ip_source), dst=idst) / \
        igmp(type=IGMP_DVMRP, code=DVMRP_ASK_NEIGHBORS2) / \
        dvmrp(capabilities=DVMRP_CAP_DEFAULT, minor=0xFF, major=3)

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

    c.calc_lengths()
    c.calc_checksums()
    c.encode()

    input = PcapConnector(options.ether_iface)
    input.setfilter("igmp")

    output = PcapConnector(options.ether_iface)
    out = output.write(c.bytes, len(c.bytes))

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
