# Copyright (c) 2008, Bruce M. Simpson.
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
# Neither the name of the authors nor the names of contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
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
# File: $Id$
#
# Author: Bruce M. Simpson
#
# Description: Test shallow and deep copies of PCS objects.

import unittest

import sys

if __name__ == '__main__':

    if "-l" in sys.argv:
        sys.path.insert(0, "../") # Look locally first
        sys.argv.remove("-l") # Needed because unittest has issues
                              # with extra arguments.

    from copy import copy
    from copy import deepcopy

    import pcs
    from pcs import *
    from pcs.packets.ethernet import ether_atob

class copyTestCase(unittest.TestCase):
    def test_copy_field(self):
        """Test shallow copy of Field. Field is not immutable and contains
           only data types, so deep and shallow copies are identical."""
        addr1 = inet_atol("192.0.2.1")
        addr2 = inet_atol("192.0.2.2")
        f1 = pcs.Field("f1", 32, default=addr1)
        self.assert_(isinstance(f1, pcs.Field))
        self.assertEqual(f1.value, addr1, "f1's value not set by __init__!")
        f1.value = addr2
        self.assertEqual(f1.value, addr2, "f1's value not set by assignment!")
        f2 = copy(f1)
        # should have same name and type
        self.assertEqual(f2.packet, None, "f2.packet is not None!")
        self.assert_(isinstance(f2, pcs.Field))
        self.assertEqual(f2.name, "f1", "f2's name not set by copy()!")
        self.assertEqual(f2.value, addr2, "f2's value not set by copy()!")
        f2.value = addr1
        self.assertEqual(f2.value, addr1, "f2's value not set by assignment!")
        self.assert_(f1.value != f2.value)

    def test_copy_lengthvaluefield(self):
        """Test shallow copy of LengthValueField. It contains two other
           Fields, so a shallow copy should copy only those members."""
        addr1 = inet_atol("192.0.2.1")

        lf1 = pcs.Field("", 8)
        vf1 = pcs.Field("", 32)
        lvf1 = LengthValueField("lvf1", lf1, vf1)
        self.assert_(isinstance(lvf1, pcs.LengthValueField))
        self.assert_(isinstance(lvf1.length, pcs.Field))
        self.assert_(isinstance(lvf1.value, pcs.Field))
        self.assert_(id(lf1) == id(lvf1.length))
        self.assert_(id(vf1) == id(lvf1.value))

        vf1.value = addr1
        self.assertEqual(lvf1.value.value, addr1, \
                         "lvf1's value-field value not set by assignment!")

        lvf2 = copy(lvf1)
        self.assertEqual(lvf2.packet, None, "lvf2.packet is not None!")
        self.assert_(isinstance(lvf2, pcs.LengthValueField))
        self.assert_(isinstance(lvf2.length, pcs.Field))
        self.assert_(isinstance(lvf2.value, pcs.Field))
        # Must be a shallow copy
        self.assert_(id(lf1) == id(lvf2.length))
        self.assert_(id(vf1) == id(lvf2.value))
        self.assertEqual(lvf2.name, "lvf1", "lvf2's name not set by copy()!")
        # Paranoia
        self.assertEqual(lvf2.value.value, inet_atol("192.0.2.1"), \
                         "lvf2's value-field value differs!")

    def test_copy_optionlistfield(self):
        """Test shallow copy of OptionListField."""
        of1 = OptionListField("")
        self.assert_(isinstance(of1, pcs.OptionListField))
        f1 = Field("", 8)
        self.assert_(isinstance(f1, pcs.Field))
        f1.value = 123
        of1.append(f1)
        self.assert_(len(of1), 1)
        self.assert_(isinstance(of1._options[0], pcs.Field))
        self.assert_(id(of1._options[0]) == id(f1))

        of2 = copy(of1)
        self.assert_(isinstance(of2, pcs.OptionListField))
        self.assert_(id(of1) != id(of2))

        self.assertEqual(of2._options[0].value, 123,
                         "of2's first option's value-field value differs!")

    def test_copy_typevaluefield(self):
        """Test shallow copy of TypeValueField."""
        addr1 = inet_atol("192.0.2.1")

        tf1 = pcs.Field("", 8)
        vf1 = pcs.Field("", 32)
        tvf1 = TypeValueField("tvf1", tf1, vf1)
        self.assert_(isinstance(tvf1, pcs.TypeValueField))
        self.assert_(isinstance(tvf1.type, pcs.Field))
        self.assert_(isinstance(tvf1.value, pcs.Field))
        self.assert_(id(tf1) == id(tvf1.type))
        self.assert_(id(vf1) == id(tvf1.value))

        tvf1.value.value = addr1
        self.assertEqual(tvf1.value.value, addr1, \
                         "tvf1's value-field value not set by assignment!")

        tvf2 = copy(tvf1)
        self.assert_(id(tvf1) != id(tvf2))
        self.assertEqual(tvf2.packet, None, "tvf2.packet is not None!")
        self.assert_(isinstance(tvf2, pcs.TypeValueField))
        self.assert_(isinstance(tvf2.type, pcs.Field))
        self.assert_(isinstance(tvf2.value, pcs.Field))
        # Must be a shallow copy
        self.assert_(id(tf1) == id(tvf2.type))
        self.assert_(id(vf1) == id(tvf2.value))
        self.assertEqual(tvf2.name, "tvf1", \
                         "tvf2's name not set by copy()!")
        # Paranoia
        self.assertEqual(tvf2.value.value, inet_atol("192.0.2.1"), \
                         "tvf2's value-field value differs!")

    def test_copy_typelengthvaluefield(self):
        """Test shallow copy of TypeLengthValueField. It contains three other
           Fields, so a deep copy should copy everything."""
        addr1 = inet_atol("192.0.2.1")

        tf1 = pcs.Field("", 8)
        lf1 = pcs.Field("", 8)
        vf1 = pcs.Field("", 32)
        tlvf1 = TypeLengthValueField("tlvf1", tf1, lf1, vf1)
        self.assert_(isinstance(tlvf1, pcs.TypeLengthValueField))
        self.assert_(isinstance(tlvf1.type, pcs.Field))
        self.assert_(isinstance(tlvf1.length, pcs.Field))
        self.assert_(isinstance(tlvf1.value, pcs.Field))
        self.assert_(id(tf1) == id(tlvf1.type))
        self.assert_(id(lf1) == id(tlvf1.length))
        self.assert_(id(vf1) == id(tlvf1.value))

        tlvf1.type.value = 123
        tlvf1.length.value = 4
        tlvf1.value.value = addr1
        self.assertEqual(tlvf1.value.value, addr1, \
                         "tlvf1's value-field value not set by assignment!")

        addr2 = ether_atob("01:02:03:04:05:06")

        tlvf2 = copy(tlvf1)
        self.assert_(id(tlvf1) != id(tlvf2))
        self.assertEqual(tlvf2.packet, None, "tlvf2.packet is not None!")
        self.assert_(isinstance(tlvf2, pcs.TypeLengthValueField))
        self.assert_(isinstance(tlvf2.type, pcs.Field))
        self.assert_(isinstance(tlvf2.length, pcs.Field))
        self.assert_(isinstance(tlvf2.value, pcs.Field))
        # Must be a shallow copy
        self.assert_(id(tf1) == id(tlvf2.type))
        self.assert_(id(lf1) == id(tlvf2.length))
        self.assert_(id(vf1) == id(tlvf2.value))
        self.assertEqual(tlvf2.name, "tlvf1", \
                         "tlvf2's name not set by deepcopy()!")
        # Paranoia
        self.assertEqual(tlvf2.type.value, 123, \
                         "tlvf2's value-field value differs after deepcopy!")
        self.assertEqual(tlvf2.length.value, 4, \
                         "tlvf2's value-field value differs after deepcopy!")
        self.assertEqual(tlvf2.value.value, inet_atol("192.0.2.1"), \
                         "tlvf2's value-field value differs after deepcopy!")

    def test_copy_packet(self):
        """A copy of a Packet is always deep."""
        self.test_deepcopy_packet()

    def test_copy_chain(self):
        """A copy of a Chain is always deep."""
        self.test_deepcopy_chain()

    def test_deepcopy_field(self):
        """A copy of a Field is always deep."""
        self.test_copy_field()

    def test_deepcopy_optionlistfield(self):
        """Test deep copy of OptionListField."""
        of1 = OptionListField("")
        self.assert_(isinstance(of1, pcs.OptionListField))
        f1 = Field("", 8)
        self.assert_(isinstance(f1, pcs.Field))
        f1.value = 123
        of1.append(f1)
        self.assert_(len(of1), 1)
        self.assert_(isinstance(of1._options[0], pcs.Field))
        self.assert_(id(of1._options[0]) == id(f1))

        of2 = deepcopy(of1)
        self.assert_(isinstance(of2, pcs.OptionListField))
        self.assert_(id(of1) != id(of2))
        self.assert_(isinstance(of2._options[0], pcs.Field))
        self.assert_(id(of1._options[0]) != id(of2._options[0]))

    def test_deepcopy_lengthvaluefield(self):
        """Test deep copy of LengthValueField. It contains two other
           Fields, so a deep copy should copy everything."""
        addr1 = inet_atol("192.0.2.1")

        lf1 = pcs.Field("", 8)
        vf1 = pcs.Field("", 32)
        lvf1 = LengthValueField("lvf1", lf1, vf1)
        self.assert_(isinstance(lvf1, pcs.LengthValueField))
        self.assert_(isinstance(lvf1.length, pcs.Field))
        self.assert_(isinstance(lvf1.value, pcs.Field))
        self.assert_(id(lf1) == id(lvf1.length))
        self.assert_(id(vf1) == id(lvf1.value))

        lvf1.value.value = addr1
        self.assertEqual(lvf1.value.value, addr1, \
                         "lvf1's value-field value not set by assignment!")

        addr2 = ether_atob("01:02:03:04:05:06")

        lvf2 = deepcopy(lvf1)
        self.assert_(id(lvf1) != id(lvf2))
        self.assertEqual(lvf2.packet, None, "lvf2.packet is not None!")
        self.assert_(isinstance(lvf2, pcs.LengthValueField))
        self.assert_(isinstance(lvf2.length, pcs.Field))
        self.assert_(isinstance(lvf2.value, pcs.Field))
        # Must be a deep copy
        self.assert_(id(lf1) != id(lvf2.length))
        self.assert_(id(vf1) != id(lvf2.value))
        self.assertEqual(lvf2.name, "lvf1", \
                         "lvf2's name not set by deepcopy()!")
        # Paranoia
        self.assertEqual(lvf2.value.value, inet_atol("192.0.2.1"), \
                         "lvf2's value-field value differs after deepcopy!")

        lvf1.value.value = inet_atol("192.0.2.2")
        self.assertEqual(lvf2.value.value, inet_atol("192.0.2.1"), \
                         "lvf2's value-field value was changed by assignment to lvf1!")
        lvf2.length.value = len(addr2)
        lvf2.value.value = addr2
        self.assertNotEqual(lvf1.length.value, lvf2.length.value,
                            "lvf2's length-field value does not differ after assignment!")

    def test_deepcopy_typevaluefield(self):
        """Test deep copy of TypeValueField. It contains two other
           Fields, so a deep copy should copy everything."""
        addr1 = inet_atol("192.0.2.1")

        tf1 = pcs.Field("", 8)
        vf1 = pcs.Field("", 32)
        tvf1 = TypeValueField("tvf1", tf1, vf1)
        self.assert_(isinstance(tvf1, pcs.TypeValueField))
        self.assert_(isinstance(tvf1.type, pcs.Field))
        self.assert_(isinstance(tvf1.value, pcs.Field))
        self.assert_(id(tf1) == id(tvf1.type))
        self.assert_(id(vf1) == id(tvf1.value))

        tvf1.value.value = addr1
        self.assertEqual(tvf1.value.value, addr1, \
                         "tvf1's value-field value not set by assignment!")

        addr2 = ether_atob("01:02:03:04:05:06")

        tvf2 = deepcopy(tvf1)
        self.assert_(id(tvf1) != id(tvf2))
        self.assertEqual(tvf2.packet, None, "tvf2.packet is not None!")
        self.assert_(isinstance(tvf2, pcs.TypeValueField))
        self.assert_(isinstance(tvf2.type, pcs.Field))
        self.assert_(isinstance(tvf2.value, pcs.Field))
        # Must be a deep copy
        self.assert_(id(tf1) != id(tvf2.type))
        self.assert_(id(vf1) != id(tvf2.value))
        self.assertEqual(tvf2.name, "tvf1", \
                         "tvf2's name not set by deepcopy()!")
        # Paranoia
        self.assertEqual(tvf2.value.value, inet_atol("192.0.2.1"), \
                         "tvf2's value-field value differs after deepcopy!")

        tvf1.value.value = inet_atol("192.0.2.2")
        self.assertEqual(tvf2.value.value, inet_atol("192.0.2.1"), \
                         "tvf2's value-field value was changed by assignment to tvf1!")
        tvf2.type.value = 123
        tvf2.value.value = addr2
        self.assertNotEqual(tvf1.type.value, tvf2.type.value,
                            "lvf2's type-field value does not differ after assignment!")

    def test_deepcopy_typelengthvaluefield(self):
        """Test deep copy of TypeLengthValueField. It contains three other
           Fields, so a deep copy should copy everything."""
        addr1 = inet_atol("192.0.2.1")

        tf1 = pcs.Field("", 8)
        lf1 = pcs.Field("", 8)
        vf1 = pcs.Field("", 32)
        tlvf1 = TypeLengthValueField("tlvf1", tf1, lf1, vf1)
        self.assert_(isinstance(tlvf1, pcs.TypeLengthValueField))
        self.assert_(isinstance(tlvf1.type, pcs.Field))
        self.assert_(isinstance(tlvf1.length, pcs.Field))
        self.assert_(isinstance(tlvf1.value, pcs.Field))
        self.assert_(id(tf1) == id(tlvf1.type))
        self.assert_(id(lf1) == id(tlvf1.length))
        self.assert_(id(vf1) == id(tlvf1.value))

        tlvf1.value.value = addr1
        self.assertEqual(tlvf1.value.value, addr1, \
                         "tlvf1's value-field value not set by assignment!")

        addr2 = ether_atob("01:02:03:04:05:06")

        tlvf2 = deepcopy(tlvf1)
        self.assert_(id(tlvf1) != id(tlvf2))
        self.assertEqual(tlvf2.packet, None, "tlvf2.packet is not None!")
        self.assert_(isinstance(tlvf2, pcs.TypeLengthValueField))
        self.assert_(isinstance(tlvf2.type, pcs.Field))
        self.assert_(isinstance(tlvf2.length, pcs.Field))
        self.assert_(isinstance(tlvf2.value, pcs.Field))
        # Must be a deep copy
        self.assert_(id(tf1) != id(tlvf2.type))
        self.assert_(id(lf1) != id(tlvf2.length))
        self.assert_(id(vf1) != id(tlvf2.value))
        self.assertEqual(tlvf2.name, "tlvf1", \
                         "tlvf2's name not set by deepcopy()!")
        # Paranoia
        self.assertEqual(tlvf2.value.value, inet_atol("192.0.2.1"), \
                         "tlvf2's value-field value differs after deepcopy!")

        tlvf1.value.value = inet_atol("192.0.2.2")
        self.assertEqual(tlvf2.value.value, inet_atol("192.0.2.1"), \
                         "tlvf2's value-field value was changed by assignment to tvf1!")

        tlvf2.type.value = 123
        self.assertNotEqual(tlvf1.type.value, tlvf2.type.value,
                            "tlvf2's type-field value does not differ after assignment!")

        tlvf2.length.value = len(addr2)
        self.assertNotEqual(tlvf1.length.value, tlvf2.length.value,
                            "tlvf2's length-field value does not differ after assignment!")

        tlvf2.value.value = addr2
        self.assertNotEqual(tlvf1.type.value, tlvf2.type.value,
                            "tvf2's type-field value does not differ after assignment!")

    def test_deepcopy_packet(self):
        from pcs.packets.ipv4 import ipv4
        p1 = ipv4(id=123)
        self.assert_(isinstance(p1, ipv4))

        p2 = deepcopy(p1)
        self.assert_(isinstance(p2, ipv4))
        self.assert_(id(p2) != id(p1))

        self.assert_(id(p2._fieldnames['id']) != id(p1._fieldnames['id']))
        self.assert_(p2.id == p1.id)

        p2.id = 456
        self.assert_(id(p2._fieldnames['id']) != id(p1._fieldnames['id']))
        self.assert_(p2.id != p1.id)

        # Copying a Packet DOES NOT copy its payload.
        self.assert_(p2.data == None)

    def test_deepcopy_chain(self):
        from pcs.packets.ipv4 import ipv4
        c1 = Chain([ipv4()])
        p1 = c1.packets[0]
        self.assert_(p1._head is c1)

        c2 = deepcopy(c1)
        self.assert_(c2 is not c1)

        p2 = c2.packets[0]
        self.assert_(p2 is not p1)
        self.assert_(p2._head is c2)

        self.assert_(id(p2) != id(p1))
        self.assert_(id(p2._fieldnames['id']) != id(p1._fieldnames['id']))
        pass

if __name__ == '__main__':
    unittest.main()
