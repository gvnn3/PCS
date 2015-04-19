# Copyright (c) 2009, Neville-Neil Consulting
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

import pcs
from . import ptp_map
import time

PTP_SUBDOMAIN_NAME_LENGTH = 16
PTP_CODE_STRING_LENGTH = 4
PTP_UUID_LENGTH = 6

class Common(pcs.Packet):
    """PTP Common Header"""
    _layout = pcs.Layout()
    _map = ptp_map.map
    
    def __init__(self, pdata = None, timestamp = None, **kv):
        """initialize the common header """
        transportSpecific = pcs.Field("transportSpecific", 4)
        messageType = pcs.Field("versionNetwork", 4, discriminator = True)
        reserved0 = pcs.Field("reserved0", 4)
        versionPTP = pcs.Field("versionPTP", 4)
        messageLength = pcs.Field("messageLength", 16)
        domainNumber = pcs.Field("domainNumber", 8)
        reserved1 = pcs.Field("reserved1", 8)
        flagField = pcs.Field("flagField", 16)
        correctionField = pcs.Field("correctionField", 64)
        reserved2 = pcs.Field("reserved2", 32)
        sourcePortIdentity = pcs.Field("sourcePortIdentity", 80)
        sequenceId = pcs.Field("sequenceId", 16)
        controlField = pcs.Field("controlField", 8)
        logMessageInterval = pcs.Field("logMessageInterval", 8)
        pcs.Packet.__init__(self, [transportSpecific, messageType,
                                   reserved0,
                                   versionPTP, messageLength, domainNumber,
                                   reserved1,
                                   flagField, correctionField,
                                   reserved2,
                                   sourcePortIdentity, sequenceId, controlField,
                                   logMessageInterval],
                            pdata = pdata, **kv)

        self.description = "PTP Common Header"

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (pdata is not None):
            self.data = self.next(pdata[self.sizeof():len(pdata)],
                                  timestamp = timestamp)
        else:
            self.data = None

