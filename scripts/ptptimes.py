#!/usr/bin/env python
# Copyright (c) 2012-2016, Neville-Neil Consulting
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
# Description: Script displays all the times found in various PTP packets.

from pcs.packets.ptp import *
from pcs.packets.ptp_common import Common
from pcs.packets.ipv4 import ipv4
from pcs.packets.udpv4 import udpv4
import pcs

import datetime

def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-f", "--file",
                      dest="file", default=None,
                      help="File to read from.")

    parser.add_option("-n", "--natural",
                      action="store_true",
                      dest="natural", default=False,
                      help="human readable time.")

    (options, args) = parser.parse_args()

    file = pcs.PcapConnector(options.file)

    packet = file.readpkt()

    while(packet != None):
        if packet.data == None:
            continue
        if packet.data.data == None:
            continue
        if packet.data.data.data != None:
            if (options.natural == True):
                ts = datetime.datetime.fromtimestamp(packet.data.data.timestamp)
                ms = ts.microsecond / 1000
                msecond = ts.strftime("%H:%M:%S")
                msecond += (".%d") % ms
                print msecond
            else:
                print packet.data.data.timestamp
            print packet.data.data.data
        if packet.data.data.data.data != None:
            print packet.data.data.data.data
        packet = file.readpkt()


if __name__ == "__main__":
    main()
