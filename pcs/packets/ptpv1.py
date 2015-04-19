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
# Description: An encoding for the Precision Time Protocol (IEEE-1588)
# aka PTPv1, which is to be deprecated.

import pcs
import time

PTP_SUBDOMAIN_NAME_LENGTH = 16
PTP_CODE_STRING_LENGTH = 4
PTP_UUID_LENGTH = 6

class SyncV1(pcs.Packet):
    """PTPv1 Sync"""
    _layout = pcs.Layout()
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        originTimestampSeconds = pcs.Field("originTimestampSeconds", 32)
        originTimestampNanoseconds = pcs.Field("originTimestampNanoseconds", 32)
        epochNumber = pcs.Field("epochNumber", 16)
        currentUTCOffset = pcs.Field("currentUTCOffset", 16)
        zero1 = pcs.Field("zero1", 8, default = 0)
        grandmasterCommunicationTechnology = pcs.Field(
            "grandmasterCommunicationTechnology", 8)
        grandmasterClockUuid = pcs.StringField("grandmasterClockUuid",
                                         PTP_UUID_LENGTH * 8)
        grandmasterPortId = pcs.Field("grandmasterPortId", 16)
        grandmasterSequenceId = pcs.Field("grandmasterSequenceId", 16)
        zero2 = pcs.Field("zero2", 24, default = 0)
        grandmasterClockStratum = pcs.Field("grandmasterClockStratum", 8)
        grandmasterClockIdentifier = pcs.StringField(
            "grandmasterClockIdentifier", PTP_CODE_STRING_LENGTH * 8 )
        zero3 = pcs.Field("zero3", 16, default = 0)
        grandmasterClockVariance = pcs.Field("grandmasterClockVariance", 16)
        zero4 = pcs.Field("zero4", 8, default = 0)
        grandmasterPreferred = pcs.Field("grandmasterPreferred", 8)
        zero5 = pcs.Field("zero5", 8, default = 0)
        grandmasterIsBoundaryClock = pcs.Field("grandmasterIsBoundaryClock", 8)
        zero6 = pcs.Field("zero6", 24, default = 0)
        syncInterval = pcs.Field("syncInterval", 8)
        zero7 = pcs.Field("zero7", 16, default = 0)
        localClockVariance = pcs.Field("localClockVariance", 16)
        zero8 = pcs.Field("zero8", 16, default = 0)
        localStepsRemoved = pcs.Field("localStepsRemoved", 16)
        zero9 = pcs.Field("zero9", 24, default = 0)
        localClockStratum = pcs.Field("localClockStratum", 8)
        localClockIdentifer = pcs.StringField("localClockIdentifer",
                                        PTP_CODE_STRING_LENGTH * 8)
        zero10 = pcs.Field("zero10", 8, default = 0)
        parentCommunicationTechnology = pcs.Field(
            "parentCommunicationTechnology", 8)
        parentUuid = pcs.StringField("parentUuid", PTP_UUID_LENGTH * 8)
        zero11 = pcs.Field("zero11", 16, default = 0)
        parentPortField = pcs.Field("parentPortField", 16)
        zero12 = pcs.Field("zero12", 16, default = 0)
        estimatedMasterVariance = pcs.Field("estimatedMasterVariance", 16)
        estimatedMasterDrift = pcs.Field("estimatedMasterDrift", 32)
        zero13 = pcs.Field("zero13", 24, default = 0)
        utcReasonable = pcs.Field("utcReasonable", 8)

                                
        pcs.Packet.__init__(self, [originTimestampSeconds,
                                   originTimestampNanoseconds,
                                   epochNumber,
                                   currentUTCOffset,
                                   zero1,
                                   grandmasterCommunicationTechnology,
                                   grandmasterClockUuid,
                                   grandmasterPortId, grandmasterSequenceId,
                                   zero2,
                                   grandmasterClockStratum,
                                   grandmasterClockIdentifier,
                                   zero3,
                                   grandmasterClockVariance,
                                   zero4,
                                   grandmasterPreferred,
                                   zero5,
                                   grandmasterIsBoundaryClock,
                                   zero6,
                                   syncInterval,
                                   zero7,
                                   localClockVariance,
                                   zero8,
                                   localStepsRemoved,
                                   zero9,
                                   localClockStratum,
                                   localClockIdentifer,
                                   zero10,
                                   parentCommunicationTechnology,
                                   parentUuid,
                                   zero11,
                                   parentPortField,
                                   zero12,
                                   estimatedMasterVariance,
                                   estimatedMasterDrift,
                                   zero13,
                                   utcReasonable], pdata = pdata, **kv)

        self.description = "PTP Sync"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (pdata is not None):
            self.data = self.next(pdata[self.sizeof():len(pdata)],
                                  timestamp = timestamp)
        else:
            self.data = None

#
# NOTE: Sync and Delay Request messages have the same format, BUT
# it is far easier to write scripts that differentiate between
# these two messages.  Keep this class and the Sync class in Sync
# or you will have significant problems with your code.

class DelayRequestV1(pcs.Packet):
    """PTPv1 DelayRequest"""
    _layout = pcs.Layout()
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        originTimestampSeconds = pcs.Field("originTimestampSeconds", 32)
        originTimestampNanoseconds = pcs.Field("originTimestampNanoseconds", 32)
        epochNumber = pcs.Field("epochNumber", 16)
        currentUTCOffset = pcs.Field("currentUTCOffset", 16)
        zero1 = pcs.Field("zero1", 8, default = 0)
        grandmasterCommunicationTechnology = pcs.Field(
            "grandmasterCommunicationTechnology", 8)
        grandmasterClockUuid = pcs.StringField("grandmasterClockUuid",
                                         PTP_UUID_LENGTH * 8)
        grandmasterPortId = pcs.Field("grandmasterPortId", 16)
        grandmasterSequenceId = pcs.Field("grandmasterSequenceId", 16)
        zero2 = pcs.Field("zero2", 24, default = 0)
        grandmasterClockStratum = pcs.Field("grandmasterClockStratum", 8)
        grandmasterClockIdentifier = pcs.StringField(
            "grandmasterClockIdentifier", PTP_CODE_STRING_LENGTH * 8 )
        zero3 = pcs.Field("zero3", 16, default = 0)
        grandmasterClockVariance = pcs.Field("grandmasterClockVariance", 16)
        zero4 = pcs.Field("zero4", 8, default = 0)
        grandmasterPreferred = pcs.Field("grandmasterPreferred", 8)
        zero5 = pcs.Field("zero5", 8, default = 0)
        grandmasterIsBoundaryClock = pcs.Field("grandmasterIsBoundaryClock", 8)
        zero6 = pcs.Field("zero6", 24, default = 0)
        syncInterval = pcs.Field("syncInterval", 8)
        zero7 = pcs.Field("zero7", 16, default = 0)
        localClockVariance = pcs.Field("localClockVariance", 16)
        zero8 = pcs.Field("zero8", 16, default = 0)
        localStepsRemoved = pcs.Field("localStepsRemoved", 16)
        zero9 = pcs.Field("zero9", 24, default = 0)
        localClockStratum = pcs.Field("localClockStratum", 8)
        localClockIdentifer = pcs.StringField("localClockIdentifer",
                                        PTP_CODE_STRING_LENGTH * 8)
        zero10 = pcs.Field("zero10", 8, default = 0)
        parentCommunicationTechnology = pcs.Field(
            "parentCommunicationTechnology", 8)
        parentUuid = pcs.StringField("parentUuid", PTP_UUID_LENGTH * 8)
        zero11 = pcs.Field("zero11", 16, default = 0)
        parentPortField = pcs.Field("parentPortField", 16)
        zero12 = pcs.Field("zero12", 16, default = 0)
        estimatedMasterVariance = pcs.Field("estimatedMasterVariance", 16)
        estimatedMasterDrift = pcs.Field("estimatedMasterDrift", 32)
        zero13 = pcs.Field("zero13", 24, default = 0)
        utcReasonable = pcs.Field("utcReasonable", 8)

                                
        pcs.Packet.__init__(self, [originTimestampSeconds,
                                   originTimestampNanoseconds,
                                   epochNumber,
                                   currentUTCOffset,
                                   zero1,
                                   grandmasterCommunicationTechnology,
                                   grandmasterClockUuid,
                                   grandmasterPortId, grandmasterSequenceId,
                                   zero2,
                                   grandmasterClockStratum,
                                   grandmasterClockIdentifier,
                                   zero3,
                                   grandmasterClockVariance,
                                   zero4,
                                   grandmasterPreferred,
                                   zero5,
                                   grandmasterIsBoundaryClock,
                                   zero6,
                                   syncInterval,
                                   zero7,
                                   localClockVariance,
                                   zero8,
                                   localStepsRemoved,
                                   zero9,
                                   localClockStratum,
                                   localClockIdentifer,
                                   zero10,
                                   parentCommunicationTechnology,
                                   parentUuid,
                                   zero11,
                                   parentPortField,
                                   zero12,
                                   estimatedMasterVariance,
                                   estimatedMasterDrift,
                                   zero13,
                                   utcReasonable], pdata = pdata, **kv)

        self.description = "PTP DelayRequest"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (pdata is not None):
            self.data = self.next(pdata[self.sizeof():len(pdata)],
                                  timestamp = timestamp)
        else:
            self.data = None



#
# All followup messages have an associated common header.
# See ptpCommon() at the head of this file.

class FollowupV1(pcs.Packet):
    """PTPv1 Followup"""
    _layout = pcs.Layout()
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        """Followup Header """
        zero1 = pcs.Field("zero1", 16, default = 0)
        associatedSequenceId = pcs.Field("associatedSequenceId", 16)
        preciseTimestampSeconds = pcs.Field("preciseTimestampSeconds", 32)
        preciseTimestampNanoseconds = pcs.Field("preciseTimestampNanoseconds",
                                                32)

        pcs.Packet.__init__(self, [zero1,
                                   associatedSequenceId,
                                   preciseTimestampSeconds,
                                   preciseTimestampNanoseconds],
                            pdata = pdata, **kv)

        self.description = "Followup Header "

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (pdata is not None):
            self.data = self.next(pdata[self.sizeof():len(pdata)],
                                  timestamp = timestamp)
        else:
            self.data = None


#
# All delay response messages have an associated common header.  See
# ptpCommon() at the head of this file.

class DelayResponseV1(pcs.Packet):
    """PTPv1 Delay Response"""
    _layout = pcs.Layout()
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        """Followup Header """
        delayReceiptTimestampSeconds = pcs.Field(
            "delayReceiptTimestampSeconds", 32)
        delayReceiptTimestampNanoseconds = pcs.Field(
            "delayReceiptTimestampNanoseconds", 32)
        zero1 = pcs.Field("zero1", 8, default = 0)
        requestingSourceCommunicationTechnology = pcs.Field(
            "requestingSourceCommunicationTechnology", 8)
        requestingSourceUuid = pcs.StringField("requestingSourceUuid",
                                               PTP_UUID_LENGTH * 8)
        requestingSourcePortId = pcs.Field("requestingSourcePortId", 16)
        requestingSourceSequenceId = pcs.Field("requestingSourceSequenceId", 16)

        pcs.Packet.__init__(self, [delayReceiptTimestampSeconds,
                                   delayReceiptTimestampNanoseconds,
                                   zero1,
                                   requestingSourceCommunicationTechnology,
                                   requestingSourceUuid,
                                   requestingSourcePortId,
                                   requestingSourceSequenceId],
                            pdata = pdata, **kv)

        self.description = "Followup Header "

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (pdata is not None):
            self.data = self.next(pdata[self.sizeof():len(pdata)],
                                  timestamp = timestamp)
        else:
            self.data = None

