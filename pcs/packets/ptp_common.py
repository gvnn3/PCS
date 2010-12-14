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
import ptp_map
import time

PTP_SUBDOMAIN_NAME_LENGTH = 16
PTP_CODE_STRING_LENGTH = 4
PTP_UUID_LENGTH = 6

class Common(pcs.Packet):
    """PTP Common Header"""
    _layout = pcs.Layout()
    _map = ptp_map.map
    
    def __init__(self, bytes = None, timestamp = None, **kv):
        """initialize the common header """
        versionPTP = pcs.Field("versionPTP", 16)
        versionNetwork = pcs.Field("versionNetwork", 16)
        subdomain = pcs.StringField("subdomain", PTP_SUBDOMAIN_NAME_LENGTH * 8)
        messageType = pcs.Field("messageType", 8)
        sourceCommunicationTechnology = pcs.Field("sourceCommunicationTechnology", 8)
        sourceUuid = pcs.StringField("sourceUuid", PTP_UUID_LENGTH * 8)
        sourcePortId = pcs.Field("sourcePortId", 16)
        sequenceId = pcs.Field("sequenceId", 16)
        control = pcs.Field("control", 8, discriminator = True)
        zero1 = pcs.Field("zero1", 8, default = 0)
        flags = pcs.Field("flags", 16)
        zero2 = pcs.Field("zero2", 32, default = 0)
                                
        pcs.Packet.__init__(self, [versionPTP, versionNetwork,
                                   subdomain, messageType,
                                   sourceCommunicationTechnology,
                                   sourceUuid, sourcePortId, sequenceId,
                                   control, zero1, flags, zero2],
                            bytes = bytes, **kv)

        self.description = "initialize the common header "

        if timestamp is None:
            self.timestamp = time.time()
        else:
            self.timestamp = timestamp

        if (bytes is not None):
            self.data = self.next(bytes[self.sizeof():len(bytes)],
                                  timestamp = timestamp)
        else:
            self.data = None

