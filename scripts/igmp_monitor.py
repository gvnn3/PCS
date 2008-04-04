#!/usr/bin/env python

from pcs.packets.localhost import *
from pcs.packets.ethernet import *
from pcs.packets.ipv4 import *
from pcs.packets.igmp import *
from pcs.packets.igmpv2 import *
from pcs.packets.payload import *
from pcs import *
from time import sleep

def main():

    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option("-I", "--ether_iface",
                      dest="ether_iface", default=None,
                      help="The name of the source interface.")

    #parser.add_option("-c", "--count",
    #                  dest="count", default=None,
    #                  help="Stop after receiving at least count responses.")

    (options, args) = parser.parse_args()

    if options.ether_iface is None:
        print "Non-optional argument missing."
        return

    input = PcapConnector(options.ether_iface)
    input.setfilter("igmp")

    #
    # Wait for up to 'count' responses to the query to arrive and print them.
    #
    quit = False
    while not quit:
        packet = input.readpkt()
        chain = packet.chain()
        print chain
	#if chain.packets[2].type == IGMP_v2_HOST_MEMBERSHIP_REPORT:
	#    #print chain.packets[2].println()
	#    print "%s is in %s" % \
	#        (inet_ntop(AF_INET, struct.pack('!L', chain.packets[1].src)), \
	#         inet_ntop(AF_INET, struct.pack('!L', chain.packets[3].group)))
	#    count -= 1

main()
