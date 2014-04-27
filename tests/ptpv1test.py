# Copyright (c) 2012, Neville-Neil Consulting
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
# Neither the name of Neville-Neil Consulting nor the names of its 
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
# Author: George V. Neville-Neil
#
# Description: This module performs a self test on the PTPv1 packet.
# That is to say it first encodes a packet, then decodes is and makes
# sure that the data matches.

import unittest

import sys
from hexdumper import hexdumper

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    from pcs.packets.ptpv1 import *
    from pcs.packets.ptpv1_common import Common
    from pcs.packets.ipv4 import ipv4
    from pcs.packets.udpv4 import udpv4
    import pcs

class ptpTestCase(unittest.TestCase):
    def test_ptp_header(self):
        # create one header, copy its bytes, then compare their fields
        ptp = CommonV1()
        assert (ptp != None)

        ptp.versionPTP = 1
        ptp.versionNetwork = 1
        ptp.subdomain = "_DFLT           "
        ptp.messageType = 1
        ptp.sourceCommunicationTechnology = 1
        ptp.sourceUuid = "\x00\x0e\xfe\x00\x0f\xa2"
        ptp.sourcePortId = 1
        ptp.sequenceId = 40828
        ptp.control = 0

        # Create a packet to compare against
        ptpnew = Common()
        ptpnew.decode(ptp.bytes)

        self.assertEqual(ptp.bytes, ptpnew.bytes, "bytes not equal")
        for field in ptp._fieldnames:
            self.assertEqual(getattr(ptp, field), getattr(ptpnew, field), ("%s not equal" % field))

    def test_ptp_sync(self):
        # create one header, copy its bytes, then compare their fields
        ptp = SyncV1()
        assert (ptp != None)

        ptp.originTimestampSeconds = 1253718841
        ptp.originTimestampNanoseconds = 263836000
        ptp.epochNumber = 0
        ptp.currentUTCOffset = 0
        ptp.grandmasterCommunicationTechnology = 1
        ptp.grandmasterClockUuid = "\x00\x0e\xfe\x00\x05\xa2"
        ptp.grandmasterPortId = 0
        grandmasterSequenceId = 40828
        ptp.grandmasterClockStratum = 4 
        ptp.grandmasterClockIdentifier = "DFLT"
        ptp.grandmasterClockVariance = 4000
        ptp.grandmasterPreferred = 1
        ptp.grandmasterIsBoundaryClock = 0
        ptp.syncInterval = 1
        ptp.localClockVariance = 4000
        ptp.localStepsRemoved = 0
        ptp.localClockStratum = 4
        ptp.localClockIdentifer = "DFLT"
        ptp.parentCommunicationTechnology = 1
        ptp.parentUuid = "\x00\x0e\xfe\x00\x05\xa2"
        ptp.parentPortField = 0
        ptp.estimatedMasterVariance = 0
        ptp.estimatedMasterDrift = 0
        ptp.utcReasonable = 0

        # Create a packet to compare against
        ptpnew = Sync()
        ptpnew.decode(ptp.bytes)

        self.assertEqual(ptp.bytes, ptpnew.bytes, "bytes not equal")
        for field in ptp._fieldnames:
            self.assertEqual(getattr(ptp, field), getattr(ptpnew, field), ("%s not equal" % field))

    
    def test_ptp_followup(self):
        # create one header, copy its bytes, then compare their fields
        ptp = FollowupV1()
        assert (ptp != None)

        ptp.associatedSequenceId = 40828
        ptp.preciseTimestampSeconds = 1253718841
        ptp.preciseTimestampNanoseconds = 2264042000

        # Create a packet to compare against
        ptpnew = Followup()
        ptpnew.decode(ptp.bytes)

        self.assertEqual(ptp.bytes, ptpnew.bytes, "bytes not equal")
        for field in ptp._fieldnames:
            self.assertEqual(getattr(ptp, field), getattr(ptpnew, field), ("%s not equal" % field))

    def test_ptp_delay_response(self):
        # create one header, copy its bytes, then compare their fields
        ptp = DelayResponseV1()
        assert (ptp != None)

        ptp.delayReceiptTimestampSeconds = 1253718841
        ptp.delayReceiptTimestampNanoseconds = 264431000
        ptp.requestingSourceCommunicationTechnology = 1
        ptp.requestingSourceUuid = "\x00\x30\x48\x66\x68\xae"
        ptp.requestingSourcePortId = 1
        ptp.requestingSourceSequenceId = 62134

        # Create a packet to compare against
        ptpnew = DelayResponse()
        ptpnew.decode(ptp.bytes)

        self.assertEqual(ptp.bytes, ptpnew.bytes, "bytes not equal")
        for field in ptp._fieldnames:
            self.assertEqual(getattr(ptp, field), getattr(ptpnew, field), ("%s not equal" % field))

    def test_ptp_read(self):
        # read a ptp packet from a pcap capture file
        file = pcs.PcapConnector("ptp.out")
        packet = file.readpkt()
        
        print("Common")
        print(packet.data.data.data)
        
        print("Sync")
        print(packet.data.data.data.data)
    
        packet = file.readpkt()

        print("Delay Request")
        print(packet.data.data.data)
        print(packet.data.data.data.data)

        for i in range(0,51):
            packet = file.readpkt()

        print("Follow Up")
        print(packet.data.data.data)
        print(packet.data.data.data.data)

if __name__ == '__main__':
    unittest.main()


