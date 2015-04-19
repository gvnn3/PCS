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
# Description: An encoding for the Precision Time Protocol (IEEE-1588-2008)
# aka PTPv2.

import pcs
import time

PTP_SUBDOMAIN_NAME_LENGTH = 16
PTP_CODE_STRING_LENGTH = 4
PTP_UUID_LENGTH = 6

class Announce(pcs.Packet):
    """PTP Announce"""
    _layout = pcs.Layout()
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        originTimestampSeconds = pcs.Field("originTimestampSeconds", 48)
        originTimestampNanoSeconds = pcs.Field("originTimestampNanoSeconds", 32)
        currentUTCOffset = pcs.Field("currentUTCOffset", 16)
        reserved0 = pcs.Field("reserved0", 8, default = 0)
        grandmasterPriority1 = pcs.Field("grandmasterPriority1", 8)
        grandmasterClockQuality = pcs.Field("grandmasterClockQuality", 32)
        grandmasterPriority2 = pcs.Field("grandmasterPriority2", 8)
        grandmasterClockIdentity = pcs.StringField("grandmasterClockIdentity", 8)
        stepsRemoved = pcs.Field("stepsRemoved", 16)
        timeSource = pcs.Field("timeSource", 8)
        
        pcs.Packet.__init__(self, [originTimestampSeconds,
                                   originTimestampNanoSeconds,
                                   currentUTCOffset,
                                   reserved0,
                                   grandmasterPriority1,
                                   grandmasterClockQuality,
                                   grandmasterPriority2,
                                   grandmasterClockIdentity,
                                   stepsRemoved,
                                   timeSource], pdata = pdata, **kv)

        self.description = "PTP Announce"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (pdata is not None):
            self.data = self.next(pdata[self.sizeof():len(pdata)],
                                  timestamp = timestamp)
        else:
            self.data = None


class Sync(pcs.Packet):
    """PTP Sync"""
    _layout = pcs.Layout()
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        originTimestampSeconds = pcs.Field("originTimestampSeconds", 48)
        originTimestampNanoSeconds = pcs.Field("originTimestampNanoSeconds", 32)
        pcs.Packet.__init__(self, [originTimestampSeconds,
                                   originTimestampNanoSeconds],
                            pdata = pdata, **kv)

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

class DelayRequest(pcs.Packet):
    """PTP DelayRequest"""
    _layout = pcs.Layout()
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        originTimestampSeconds = pcs.Field("originTimestampSeconds", 48)
        originTimestampNanoSeconds = pcs.Field("originTimestampNanoSeconds", 32)
        pcs.Packet.__init__(self, [originTimestampSeconds,
                                   originTimestampNanoSeconds],
                            pdata = pdata, **kv)

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

class Followup(pcs.Packet):
    """PTP Followup"""
    _layout = pcs.Layout()
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        """Followup Header """
        preciseOriginTimestampSeconds = pcs.Field("preciseOriginTimestampSeconds",
                                                  48)
        preciseOriginTimestampNanoSeconds = pcs.Field(
            "preciseOriginTimestampNanoSeconds", 32)

        pcs.Packet.__init__(self, [preciseOriginTimestampSeconds,
                                   preciseOriginTimestampNanoSeconds],
                            pdata = pdata, **kv)

        self.description = "Followup"

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

class DelayResponse(pcs.Packet):
    """PTP Delay Response"""
    _layout = pcs.Layout()
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        """Delay Response"""
        receiveTimestampSeconds = pcs.Field("receiveTimestampSeconds", 48)
        receiveTimestampNanoSeconds = pcs.Field("receiveTimestampNanoSeconds", 32)
        requestingPortIdentity = pcs.Field("requestingPortIdentity", 80)
        pcs.Packet.__init__(self, [receiveTimestampSeconds,
                                   receiveTimestampNanoSeconds,
                                   requestingPortIdentity],
                            pdata = pdata, **kv)

        self.description = "Delay Response "

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (pdata is not None):
            self.data = self.next(pdata[self.sizeof():len(pdata)],
                                  timestamp = timestamp)
        else:
            self.data = None

