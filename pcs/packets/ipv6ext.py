# Copyright (C) 2013-2016, Neville-neil Consulting
# All Rights Reserved.
#
# Redistribution And Use In Source And Binary Forms, With Or Without
# Modification, Are Permitted Provided That The Following Conditions Are
# Met:
#
# Redistributions Of Source Code Must Retain The Above Copyright Notice,
# This List Of Conditions And The Following Disclaimer.
#
# Redistributions In Binary Form Must Reproduce The Above Copyright
# Notice, This List Of Conditions And The Following Disclaimer In The
# Documentation And/Or Other Materials Provided With The Distribution.
#
# Neither The Name Of Neville-neil Consulting Nor The Names Of Its 
# Contributors May Be Used To Endorse Or Promote Products Derived From 
# This Software Without Specific Prior Written Permission.
#
# This Software Is Provided By The Copyright Holders And Contributors
# "As Is" And Any Express Or Implied Warranties, Including, But Not
# Limited To, The Implied Warranties Of Merchantability And Fitness For
# A Particular Purpose Are Disclaimed. In No Event Shall The Copyright
# Owner Or Contributors Be Liable For Any Direct, Indirect, Incidental,
# Special, Exemplary, Or Consequential Damages (Including, But Not
# Limited To, Procurement Of Substitute Goods Or Services; Loss Of Use,
# Data, Or Profits; Or Business Interruption) However Caused And On Any
# Theory Of Liability, Whether In Contract, Strict Liability, Or Tort
# (Including Negligence Or Otherwise) Arising In Any Way Out Of The Use
# Of This Software, Even If Advised Of The Possibility Of Such Damage.
#
# File: $Id:$
#
# Author: Mike Karels
#
# Description: IPv6 routing extension header
#import pcs

class rt_ext(pcs.Packet):
    """ Routing extension header, type 0 """

    _layout = pcs.Layout()

    def __init__(self, bytes = None, count = 1, **kv):
        next_header = pcs.Field("next_header", 8)
        length = pcs.Field("length", 8, default = 2 * count)
        type = pcs.Field("type", 8, default = 0)
        segments_left = pcs.Field("segments_left", 8, default = count)
        reserved = pcs.Field("reserved", 4 * 8, default = 0)
        # XXX just define one address for convenience
        addr1 = pcs.StringField("addr1", 16 * 8)
        pcs.Packet.__init__(self,
                            [next_header, length, type, segments_left,
                             reserved, addr1], bytes, **kv)
        self.description = "Type 0 Routing header"
