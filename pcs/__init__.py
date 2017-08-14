# Copyright (c) 2005-2016, Neville-Neil Consulting
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
# File: $Id: __init__.py,v 1.9 2006/09/05 07:30:56 gnn Exp $
#
# Author: George V. Neville-Neil
#
# Description: A packet module for Python.  We will package the
# individual protocols separately.

"""PCS aka Packet Construction Set

PCS is a set of Python modules and objects that make building network
protocol testing tools easier for the protocol developer.  The core of
the system is the pcs module itself which provides the necessary
functionality to create classes that implement packets.

In PCS every packet is a class and the layout of the packet is defined
by a Layout class which contains a set of Fields.  Fields can be from
1 to many bits, so it is possible to build packets with arbitrary
width bit fields.  Fields know about the widths and will throw
exceptions when they are overloaded.

Every Packet object, that is an object instantiated from a specific
PCS packet class, has a field named bytes which shows the
representation of the data in the packet at that point in time.  It is
the bytes field that is used when transmitting the packet on the wire.

For more information please see the manual, called pcs, and available in various
formats after installation.
"""

__revision__ = "$Id: __init__.py,v 1.9 2006/09/05 07:30:56 gnn Exp $"

# We need the struct module to pack our class into a byte string.
import struct

# We need the socket module for to implement some of the Connector classes.
from socket import *

import pcs.pcap as pcap

import exceptions
import itertools

# import fast

def attribreprlist(obj, attrs):
    return map(lambda x, y = obj: '%s: %s' % (x.name, repr(getattr(y, x.name))), itertools.ifilter(lambda x, y = obj: hasattr(y, x.name), attrs))

class FieldBoundsError(Exception):
    """When a programmer tries to set a field with an inappropriately
    sized piece of data this exception is raised."""

    def __init__(self, message):
        self.message = message
    def __str__(self):
        return repr(self.message)
    
# XXX Should really be named IntegerField and the common methods shuffled
# off into a base class.
class Field(object):
    """A field is a name, a type, a width in bits, possibly a default
value and can be marked as a dicriminator for higher level packet
demultiplexing .  These classes are used by the packet to define the
layout of the data and how it is addressed."""
    
    def __init__(self, name = "", width = 1, default = None,
                 discriminator = False, compare=None):
        """initialize a field

        name - a string name
        width - a width in bits
        default - a default value
        discriminator - is this field used to demultiplex packets
        match - a match function used to compare this field with another.
        """
        self.packet = None
        ## the name of the Field
        self.name = name
        ## the width, in bites, of the field's data
        self.width = width
        ## the default value of the field, must fit into bits
        self.default = default
        ## Is this field used to demultiplex higher layer packets?
        self.discriminator = discriminator
        ## the comparison function for this field
        self.compare = compare
        ## Fields store the values
        if default is None:
            self.value = 0
        else:
            self.value = default
        
    def __repr__(self):
        """return an appropriate representation for the Field object"""
        return "<pcs.Field  name %s, %d bits, default %s, discriminator %d>" %\
               (self.name, self.width, self.default, self.discriminator)

    def decode(self, bytes, curr, byteBR):
        """Decode a field and return the value and the updated current
        pointer into the bytes array

        bytes - the byte array for the packet
        curr - the current byte position in the bytes array
        byteBR - the number of Bits Remaining in the current byte
        """
#         [ real_value, curr, byteBR ] = fast.decode(self.width, len(bytes), bytes, curr, byteBR)
#         self.value = real_value
#         return [ real_value, curr, byteBR ]

        real_value = 0
        fieldBR = self.width
        length = len(bytes)
        while (fieldBR > 0 and curr < length):
            if fieldBR < byteBR:
                shift = byteBR - fieldBR
                value = ord(bytes[curr]) >> shift
                mask = 2 ** fieldBR -1
                value = (value & mask)
                byteBR -= fieldBR
                fieldBR = 0 # next field
            elif fieldBR > byteBR:
                shift = fieldBR - byteBR
                mask = 2 ** byteBR - 1
                value = (ord(bytes[curr]) & mask)
                fieldBR -= byteBR
                byteBR = 8
                curr += 1 # next byte
            elif fieldBR == byteBR:
                mask = 2 ** byteBR - 1
                value = ord(bytes[curr]) & mask
                fieldBR -= byteBR
                byteBR = 8
                curr += 1 # next byte
            real_value += value << fieldBR
        self.value = real_value
        return [real_value, curr, byteBR]

    def encode(self, bytearray, value, byte, byteBR):
        """encode the a field into the bytes necessary to transmit it
        as part of a packet

        bytearray - the array of bytes that will be returned
        value - the value to encode
        byte - the byte we are encoding, we can encode partial bytes
        byteBR - the bits remaining in the current byte being encoded.
        """
        # The algorithm below hurts my head, as I'm not very
        # smart so it is heavily commented.
        #
        # fieldBR is the bits remaining in the field to be encoded
        # byteBR is the bits remaining in the current byte being encoded
        
#         return fast.encode(self.width, bytearray, value, byte, byteBR)
        fieldBR = self.width
        while byteBR > 0:
            if fieldBR < byteBR:
                shift = byteBR - fieldBR
                byteBR -= fieldBR
                mask = ((2 ** fieldBR) - 1) << shift
                byte = (byte | ((value << shift) & mask))
                # Done with the field, not with the byte get new field
                break
            elif fieldBR > byteBR:
                shift = fieldBR - byteBR
                fieldBR -= byteBR
                mask = ((2 ** byteBR) - 1)
                byte = (byte | ((value >> shift) & mask))
                bytearray.append(struct.pack('B', byte))
                byteBR = 8
                byte = 0
                # Done with this byte, but not the field, get a new byte
            elif fieldBR == byteBR:
                mask = ((2 ** byteBR) - 1)
                byte = (byte | (value & mask))
                bytearray.append(struct.pack('B', byte))
                byte = 0
                byteBR = 8
                # Done with the byte and the field have a nice day
                break

        return [byte, byteBR]

    def set_value(self, value):
        """Set the value of a field."""
        self.value = value

    def get_value(self):
        return self.value
    
    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return 0

    def bounds(self, value):
        """Check the bounds of this field."""
        if ((value is None) or
            (value < 0) or
            (value > (2 ** self.width) - 1)):
            raise FieldBoundsError, "Value must be between 0 and %d but is %d" % ((2 ** self.width - 1), value)

    def width(self):
        """Return the width of a field."""
        return self.width

    def __copy__(self):
        """Return a shallow copy of a Field; used by copy module.
           Fields may be copied, they are not immutable."""
        return self.__deepcopy__()

    def __deepcopy__(self, memo={}):
        """Return a deep copy of a Field; used by copy module.
           Fields may be copied, they are not immutable; however they
           always contain integer types which *are* immutable."""
        result = self.__class__()
        memo[id(self)] = result
        result.__init__(name=self.name, width=self.width, \
                        default=self.default, \
                        discriminator=self.discriminator, \
                        compare=self.compare)
        # Copy value, we can do so here with impunity -- no __setattr__.
        result.value = self.value
        assert result.value == self.value, "value not copied"
        # The new copy MUST NOT be associated with a Packet.
        assert result.packet is None, "dangling reference to Packet"
        return result

    def default_compare(lp, lf, rp, rf):
        """Default comparison method.

           lp - packet on left hand side of comparison
           lf - field in lp being compared
           rp - packet on right hand side of comparison
           rf - field in rp being compared

           This function is installed in Field.compare on assignment.
           It is declared static to allow folk to override it with lambda
           functions. The packets are passed so that back-references
           to other fields in the packet are possible during the match."""
        return lf.value == rf.value

    default_compare = staticmethod(default_compare)


class FieldAlignmentError(Exception):
    """When a programmer tries to decode a field that is not
    on a byte boundary this exception is raised."""
    
    def __init__(self, message):
        """set the FieldAlignmentError message"""
        ## the message that will be output when this error is raised
        self.message = message

# Both StringField and Field contain only immutable data types, therefore
# they share copy semantics through inheritance.

class StringField(Field):
    """A string field is a name, a width in bits, and possibly a
default value.  The data is to be interpreted as a string, but does
not encode the length into the packet.  Length encoded values are
handled by the LengthValueField."""
    
    def __init__(self, name = "", width = 1, default = None, \
                 compare = None ):
        """initialtize a StringField"""
        self.packet = None
        ## the name of the StringField
        self.name = name
        ## the width, in bits, of the StringField
        self.width = width
        ## the default value, if any, of the StringField
        self.default = default
        ## the comparison function
        self.compare = compare
        ## Fields store the values
        if default is None:
            self.value = ""
        else:
            self.value = default
        
    def __repr__(self):
        """return a human readable form of a StringFeild object"""
        return "<pcs.StringField  name %s, %d bits, default %s>" % \
               (self.name, self.width, self.default)

    def decode(self, bytes, curr, byteBR):
        """Decode the field and return the value as well as the new
        current position in the bytes array."""
        # byteBR == 8 is the neutral state
        if (byteBR is not None and byteBR != 8):
            raise FieldAlignmentError, "Strings must start on a byte boundary"
        packarg = "%ds" % (self.width / 8)
        end = curr + self.width / 8
        value = struct.unpack(packarg, bytes[curr:end])[0]
        curr += self.width / 8
        self.value = value
        return [value, curr, byteBR]

    def encode(self, bytearray, value, byte, byteBR):
        """Encode a string field, make sure the bytes are aligned."""
        if (byteBR is not None and byteBR != 8):
            raise FieldAlignmentError, "Strings must start on a byte boundary"
        packarg = "%ds" % (self.width / 8)
        bytearray.append(struct.pack(packarg, value))
        return [byte, byteBR]

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    def bounds(self, value):
        """Check the bounds of this field."""
        if (value is None) or (len (value) > (self.width / 8)):
            raise FieldBoundsError, "Value must be between 0 and %d bytes long" % (self.width / 8)

class LengthValueFieldError(Exception):
    """LengthValue fields only allow access to two internal pieces of data."""
    
    def __init__(self, message):
        """set the error message"""
        ## the message that will be output when this error is raised
        self.message = message

# TODO: Add a means of packing fields according to the length actually
# encoded in them, where a field has variable length.
class LengthValueField(object):
    """A length value field handles parts of packets where a length
    and value are encoded together, usually used to shove strings into
    packets.
    """

    def __init__(self, name, length, value, compare=None):
        self.packet = None
        self.name = name
        self.compare = compare
        if not isinstance(length, Field):
            raise LengthValueFieldError, "Length must be of type Field but is %s" % type(length)
        object.__setattr__(self, 'length', length)
        if isinstance(value, Field) or isinstance(value, StringField):
            object.__setattr__(self, 'value', value)
        else:
            raise LengthValueFieldError, "Value must be of type Field or StringField but is %s" % type(value)
        self.width = length.width + value.width
        #self.packed = packed

    def __repr__(self):
        return "<pcs.LengthValueField name %s, length %s, value %s, " \
               "compare %d" \
               % (self.name, self.length, self.value, self.compare)

    def __len__(self):
        return self.length.width + self.value.width
    
    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if self.packet is not None:
            self.packet.__needencode = True

    def decode(self, bytes, curr, byteBR):
        """Decode a LengthValue field."""
        [self.length.value, curr, byteBR] = self.length.decode(bytes, curr, byteBR)
        [self.value.value, curr, byteBR] = self.value.decode(bytes, curr, byteBR)
        return [self.value.value, curr, byteBR]
        
    def encode(self, bytearray, value, byte, byteBR):
        """Encode a LengthValue field."""
        if not isinstance(self.value, StringField):
            self.length.value = self.value.width
        else:
            self.length.value = len(self.value.value)
            #self.value.width = len(self.value.value) * 8	# XXX packed
        [byte, byteBR] = self.length.encode(bytearray, self.length.value, byte, byteBR)
        [byte, byteBR] = self.value.encode(bytearray, self.value.value, byte, byteBR)
        return [byte, byteBR]

    def set_value(self, value):
        """Set the value of a LengthValueField."""
	self.length.value = len(value)
        self.value.value = value
        if self.packet is not None:
            self.packet.__needencode = True

    #def get_value(self):
    #    return self.value.value

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    def bounds(self, value):
        """Check the bounds of this field."""
        self.value.bounds(value)

    # There is no __setattr__ to stomp on us here.
    def __copy__(self):
        """Return a shallow copy of a LengthValueField; used by copy module.
           A shallow copy just makes references to these Fields in the copy."""
        result = self.__class__(name=self.name, \
                                length=self.length, \
                                value=self.value, \
                                compare=self.compare)
        return result

    def __deepcopy__(self, memo={}):
        """Return a deep copy of a LengthValueField; used by copy module.
           A deep copy copies all of the embedded Fields."""
        from copy import deepcopy
        result = self.__class__(name=self.name, \
                        length=deepcopy(self.length, memo), \
                        value=deepcopy(self.value, memo), \
                        compare=self.compare)
        memo[id(self)] = result
        return result

    def default_compare(lp, lf, rp, rf):
        """Default comparison method."""
        return lf.value == rf.value

    default_compare = staticmethod(default_compare)

class TypeValueField(object):
    """A type-value field handles parts of packets where a type
    is encoded before a value.  """

    def __init__(self, name, type, value, compare=None):
        self.packet = None
        self.name = name
        if not isinstance(type, Field):
            raise LengthValueFieldError, "Type must be of type Field but is %s" % type(type)
        self.type = type
        if isinstance(value, Field) or isinstance(value, StringField):
            self.value = value
        else:
            raise LengthValueFieldError, "Value must be of type Field or StringField but is %s" % type(value)
        self.width = type.width + value.width
        self.compare = compare

    def __repr__(self):
        return "<pcs.TypeValueField name %s, type %s, value %s>" % (self.name, self.type, self.value)

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if self.packet is not None:
            self.packet.__needencode = True

    def decode(self, bytes, curr, byteBR):
        [self.type.value, curr, byteBR] = self.type.decode(bytes, curr, byteBR)
        [self.value.value, curr, byteBR] = self.value.decode(bytes, curr, byteBR)
        return [value, curr, byteBR]
        
    def encode(self, bytearray, value, byte, byteBR):
        [byte, byteBR] = self.type.encode(bytearray, self.type.value, byte, byteBR)
        [byte, byteBR] = self.value.encode(bytearray, self.value.value, byte, byteBR)
        return [byte, byteBR]
        
    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    def bounds(self, value):
        """Check the bounds of this field."""
        if ((value is None) or
            (len (value) > (((2 ** self.valuewidth) - 1) / 8))):
            raise FieldBoundsError, "Value must be between 0 and %d bytes long" % (((2 ** self.width) - 1) / 8)

    # There is no __setattr__ to stomp on us here.
    def __copy__(self):
        """Return a shallow copy of a TypeValueField; used by copy module.
           A shallow copy just makes references to these Fields in the copy."""
        result = self.__class__(name=self.name, \
                                type=self.type, \
                                value=self.value, \
                                compare=self.compare)
        return result

    def __deepcopy__(self, memo={}):
        """Return a deep copy of a TypeValueField; used by copy module.
           A deep copy copies all of the embedded Fields."""
        from copy import deepcopy
        result = self.__class__(name=self.name, \
                        type=deepcopy(self.type, memo), \
                        value=deepcopy(self.value, memo), \
                        compare=self.compare)
        memo[id(self)] = result
        return result

    def default_compare(lp, lf, rp, rf):
        """Default comparison method."""
        return lf.value == rf.value

    default_compare = staticmethod(default_compare)


class TypeLengthValueField(object):
    """A type-length-value field handles parts of packets where a type
    is encoded before a length and value.  """

    def __init__(self, name, type, length, value,
                 inclusive = True, bytewise = True, compare = None):
        self.packet = None
        self.name = name
        if not isinstance(type, Field):
            raise LengthValueFieldError, "Type must be of type Field but is %s" % type(type)
        self.type = type
        if not isinstance(length, Field):
            raise LengthValueFieldError, "Length must be of type Field but is %s" % type(type)
        self.length = length
        if isinstance(value, Field) or isinstance(value, StringField):
            self.value = value
        else:
            raise LengthValueFieldError, "Value must be of type Field or StringField but is %s" % type(value)
        self.width = type.width + length.width + value.width
        self.inclusive = inclusive
        self.bytewise = bytewise
        self.compare = compare

    def __repr__(self):
        return "<pcs.TypeLengthValueField type %s, length %s, value %s>" \
                % (self.type, self.length, self.value)

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if self.packet is not None:
            self.packet.__needencode = True

    def decode(self, bytes, curr, byteBR):
        [self.type.value, curr, byteBR] = self.type.decode(bytes, curr, byteBR)
        [self.length.value, curr, byteBR] = self.length.decode(bytes, curr, byteBR)
        [self.value.value, curr, byteBR] = self.value.decode(bytes, curr, byteBR)
        return [value, curr, byteBR]
        
    def encode(self, bytearray, value, byte, byteBR):
        """Encode a TypeLengthValue field."""

        if isinstance(self.value, Field):
	    # Value is a field. Take its width in bits.
            self.length.value = self.value.width
        else:
	    # Value is any other Python type. Take its actual length in bits. 
            self.length.value = len(self.value) * 8

	if self.inclusive is True:
	    # Length field includes the size of the type and length fields.
            self.length.value += (self.type.width + self.length.width)

	if self.bytewise is True:
	    # Length should be encoded as a measure of bytes, not bits.
            self.length.value /= 8

        [byte, byteBR] = self.type.encode(bytearray, self.type.value, byte, byteBR)
        [byte, byteBR] = self.length.encode(bytearray, self.length.value, byte, byteBR)
        [byte, byteBR] = self.value.encode(bytearray, self.value.value, byte, byteBR)
        return [byte, byteBR]

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    def bounds(self, value):
        """Check the bounds of this field."""
        if ((value is None) or
            (len (value) > (((2 ** self.lengthwidth) - 1) / 8))):
            raise FieldBoundsError, "Value must be between 0 and %d bytes long" % (((2 ** self.width) - 1) / 8)

    # There is no __setattr__ to stomp on us here.
    def __copy__(self):
        """Return a shallow copy of a TypeLengthValueField;
           used by copy module.
           A shallow copy just makes references to these
           Fields in the copy."""
        result = self.__class__(name=self.name, \
                                type=self.type, \
                                length=self.length, \
                                value=self.value, \
                                inclusive=self.inclusive, \
                                bytewise=self.bytewise, \
                                compare=self.compare)
        return result

    def __deepcopy__(self, memo={}):
        """Return a deep copy of a TypeLengthValueField;
           used by copy module.
           A deep copy copies all of the embedded Fields."""
        from copy import deepcopy
        result = self.__class__(name=self.name, \
                                type=deepcopy(self.type, memo), \
                                length=deepcopy(self.length, memo), \
                                value=deepcopy(self.value, memo), \
                                inclusive=self.inclusive, \
                                bytewise=self.bytewise, \
                                compare=self.compare)
        memo[id(self)] = result
        return result

    def default_compare(lp, lf, rp, rf):
        """Default comparison method."""
        return lf.value == rf.value

    default_compare = staticmethod(default_compare)


class CompoundField(object):
    """A compound field may contain other fields."""

class OptionListError(Exception):
    """When a programmer tries to append to an option list and causes
    an error this exception is raised."""

    def __init__(self, message):
        self.message = message
    def __str__(self):
        return repr(self.message)

class OptionListField(CompoundField, list):
    """A option list is a list of Fields.
       Option lists inhabit many protocols, including IP and TCP."""

    def __init__(self, name, width = 0, option_list = [], compare = None):
        """Initialize an OptionListField."""
        list.__init__(self)
        self.packet = None
        self.name = name
        self.width = width
        self._options = []
        if option_list != []:
            for option in option_list:
                self._options.append(option)
        
        self.compare = compare
        self.default = self
        self.value = self
        
    def __len__(self):
        return len(self._options)
    
    def __iter__(self):
        self.index = 0
        return self

    def next(self):
        """Option lists return a pair of (value, option) when iterated"""
        length = len(self._options)
        if length <= 0:
            raise StopIteration
        if self.index > length:
            raise StopIteration
        retval =  (self._options[self.index].value)
        self.index += 1
        return retval

    def get_byname(self, name):
        """Get all options matching the given name"""
        return [opt for opt in self._options if opt.name == name]
    
    def __eq__(self, other):
        """Test two option lists for equality.
           Two option lists are equal if and only if they have the
           same options and values."""
        if (other is None):
            return False
        length = len(self._options)
        if length != len(other._options):
            #print "option list lengths differ"
            return False
        for i in xrange(length):
            #print "comparing option list field"
            f = self._options[i]
            if isinstance(f, Field):
                if f.value != other._options[i].value:
                    return False
            else:
                #print "option list member ", f.name, "is not a Field"
                if f != other._options[i]:
                    #print "did not match"
                    return False
        return True
            
    def __ne__(self, other):
        """test two option lists for inequality"""
        return not self.__eq__(other)
            
    def __repr__(self):
        return self.__str__()

    def __str__(self):
        """return a pretty printed option list"""
        retval = "["
        index = 0
        for option in self._options:
            if isinstance(option, CompoundField):
                retval += "[Field: %s, Value: %s]" % (option.name, option)
            else:
                retval += "[Field: %s, Value: %s]" % (option.name, option.value)
            if (index == (len(self._options) - 1)):
                break
            retval += ", "
            index += 1
        retval += "]"
        return retval
    
    def __setitem__(self, index, value):
        if (index < 0 or index > len(self._options)):
            raise IndexError, "index %d out of range" % index
        else:
            # Three part harmony
            # The caller can pass a list of (value, option) 
            if isinstance(value, list):
                if len(value) != 2:
                    raise OptionListError, "Option must be a pair (value, PCS Field)"
                if not isinstance(value[1], _fieldlist):
                    raise OptionListError, "Option must be a valid PCS Field."
                self._options[index] = value[1]
                self._options[index].value = value[0]
                return
            # or the caller can pass a field, but we have to check the
            # underlying value
            if isinstance(value, _fieldlist):
                value.bounds(self._options[index].value)
                self._options[index] = value
                return
            # of the caller can pass a value but we have to check the bounds
            self._options[index].bounds(value)
            self._options[index].value = value

    def __getitem__(self, index):
        """Return the value of a field in the list."""
        if (index < 0 or index > len(self._options)):
            raise IndexError, "index %d out of range" % index
        else:
            return self._options[index].value

    def bounds(self, value):
        pass

    def set_value(self, value):
        """Set the value of a field."""
        self._options = value

    def __add__(self, other):
        if isinstance(other, _fieldlist):
            self._options += other

    def append(self, option):
        """Append an option, an option/value pair, or a value to an
        options list

        Vaue,Option pairs are given as a list (value, option)
        """
        if not isinstance(option, _fieldlist):
            raise OptionListError, "Option must be a valid PCS Field."
        if not hasattr(self, '_options'):
            self._options = []
        self._options.append(option)
            
    def encode(self, bytearray, value, byte, byteBR):
        """Encode all the options in a list into a set of bytes"""
        if hasattr(self, '_options'):
            for option in self._options:
                if isinstance(option, CompoundField):
                    option.encode(bytearray, None, byte, byteBR)
                else:
                    option.encode(bytearray, option.value, byte, byteBR)
        return [byte, byteBR]

    def decode(self, bytes, curr, byteBR):
        """Decode all the options in the list"""
        if hasattr(self, '_options'):
            for option in self._options:
                if isinstance(option, CompoundField):
                    raise OptionListError, "Can't encode embedded lists yet"
                else:
                    [value, curr, byteBR] = option.decode(bytes, curr, byteBR)
                    option.value = value
        return [None, curr, byteBR]

    def reset(self):
        print self._options

    # There is no __setattr__ to stomp on us here.
    def __copy__(self):
        """Return a shallow copy of an OptionListField; used by copy module.
           A shallow copy just makes references to these Fields in the copy."""
        result = self.__class__(name=self.name, \
                                width=self.width, \
                                option_list=self._options, \
                                compare=self.compare)
        return result

    def __deepcopy__(self, memo={}):
        """Return a deep copy of an OptionListField; used by copy module.
           A deep copy copies all of the embedded Fields."""
        from copy import deepcopy
        optcopy = []
        for opt in self._options:
            optcopy.append(deepcopy(opt, memo))
        result = self.__class__(name=self.name, \
                                width=self.width, \
                                option_list=optcopy, \
                                compare=self.compare)
        memo[id(self)] = result
        return result

    def default_compare(lp, lf, rp, rf):
        """Default comparison method."""
        return lf == rf			# Will use __eq__ defined above.

    default_compare = staticmethod(default_compare)

# Types which implement Field's interface, even if not directly
# inherited from Field. User types may inherit from these types.
_fieldlist = (Field, StringField, LengthValueField, TypeValueField, TypeLengthValueField, CompoundField)

class LayoutDiscriminatorError(Exception):
    """When a programmer tries to set more than one field in a Layout as a 
    discriminator an error is raised."""

    def __init__(self, message):
        self.message = message
    def __str__(self):
        return repr(self.message)

class Layout(list):
    """The layout is a special attribute of a Packet which implements
    the layout of the packet on the wire.  It is actually a list of
    Fields and is implemented as a descriptor.  A layout can only be
    set or get, but never deleted."""

    # No need to implement __deepcopy__, as Layout is a descriptor
    # modeled on the built-in type 'list' and will propagate deep-copies
    # to the objects it contains.

    def __get__(self, obj, typ=None): 
        """return the Layout"""
        ## the layout is the ordering of the fields in the packet
        return self._layout

    # Update the layout itself.  Right now this does not handle
    # removing fields or anything else but must do so in future.
    # XXX Add code to check the type of the value, it must be a
    # list of Field objects

    def __set__(self, obj, value): 
        """set the layout

        obj - the object we are about to set
        value - the value we are setting the field to
        """
        self._layout = value
        for field in self._layout:
            # This is a special case, we don't want to recurse back
            # through the encapsulating class's __setattr__ routine.
            # We want to set this directly in the class's dictionary
            if not hasattr(field, 'default') or field.default is None:
                obj.__dict__[field.name] = field.reset()
            else:
                obj.__dict__[field.name] = field.default

class FieldError(Exception):
    """When a programmer tries to set a field that is not in the
    layout this exception is raised."""

    def __init__(self, message):
        """set the error message when this error is raised"""
        ## the error message passed when this error is raised
        self.message = message
        
reserved_names = ["_layout", "_discriminator", "_map", "_head"]

class Packet(object):
    """A Packet is a base class for building real packets.

       Assigning a value to any field of a Packet, whether by
       keyword argument passed to a constructor, or by using the
       assignment operator, will cause a default comparison function
       to be installed. This is to make it easy to specify match
       filters for Connector.expect().  """

    # The layout is a list of fields without values that indicate how
    # the data in the packet is to be layed in terms of ordering and
    # bit widths.  The update() method, below, uses this list to build
    # the data in the packet.  The actual data is kept in
    # auto-generated class entries that are built whenever the layout
    # is changed.  A layout is implemented as a descriptor, above,
    # with only get() and set() methods and so cannot be deleted.
    # This allows the programmer to set fields in what might be
    # considered a natural way with a foo.bar = baz type of syntax.

    # The bytes are the actual bytes in network byte order of a fully
    # formed packet.  Packets are always fully formed as any setting
    # of a packet field generates a call to the update() method.

    _bytes = ""
    def getbytes(self):
        """return the bytes of the packet"""
        if self._needencode:
            self._needencode = False
            self.encode()
        return self._bytes

    # decode must be defined before its used in the property
    # that is set below it.
    def decode(self, bytes):
        """Reset the bytes field and then update the associated
        attributes of the packet.  This method is used when a packet
        is read in raw form."""
        self._bytes = bytes
        curr = 0
        byteBR = 8
        length = len(bytes)
        for field in self._layout:
            if curr > length:
                break
            [value, curr, byteBR]  = field.decode(bytes, curr, byteBR)

    bytes = property(getbytes, decode)
 
    def encode(self):
        """Update the internal bytes representing the packet.  This
        function ought to be considered private to the class."""

        # Encode the fields, which are a set of bit widths and values
        # into a byte string.  This is achieved by walking the list of
        # fields, and then packing them, byte by byte, into a byte
        # string.  The algorithm below hurts my head, as I'm not very
        # smart so it is heavily commented.
        #
        # fieldBR is the bits remaining in the field to be encoded
        # byteBR is the bits remaining in the current byte being encoded
        #
        
        byteBR = 8
        byte = 0
        bytearray = []
        for field in self._layout:
            value = self._fieldnames[field.name].value
            [byte, byteBR] = field.encode(bytearray, value, byte, byteBR)

        self._bytes = ''.join(bytearray) # Install the new value

    def __init__(self, layout = None, bytes = None, **kv):
        """initialize a Packet object

        layout - the layout of the packet, a list of Field objects
        bytes - if the packet is being set up now the bytes to set in it
        kv - if the packet is being set up now, the initial values of
             each named field, specified as keyword arguments. These
             are always passed as a dict from classes which inherit
             from Packet.
        """
        # XXX
        #self._bytes = ""
        self._layout = layout
        self._fieldnames = {}
        self._head = None
        for field in layout:
            self._fieldnames[field.name] = field
        self._needencode = True
        if bytes is not None:
            self.decode(bytes)

        self._discriminator = None
        self._discriminator_inited = False

        # The layout of the Packet, a list of Field objects.
        for field in layout:
            field.packet = self
            if (not hasattr(field, 'discriminator')):
                continue
            if ((field.discriminator is True) and
                (self._discriminator is not None)):
                raise LayoutDiscriminatorError, "Layout can only have one field marked as a discriminator, but there are at least two %s %s" % (field, self._discriminator)
            if (field.discriminator is True):
                self._discriminator = field

        # Set initial values of Fields using keyword arguments.
        # Ignore any keyword arguments which do not correspond to
        # packet fields in the Layout.
        if kv is not None:
            for kw in kv.iteritems():
                if kw[0] in self._fieldnames:
                    self.__setattr__(kw[0], kw[1])

    def __add__(self, layout = None):
        """add two packets together

        This is really an append operation, of one packet after another.
        """
        for field in layout:
            self._layout.append(field)
            self._needencode = True

    def __setattr__(self, name, value):
        """Setting the layout is a special case because of the
        ramifications this has on the packet.  Only fields represented
        in the layout may be set, no other attributes may be added"""

        # Handle special fields first.
        if name == '_fieldnames':
            object.__setattr__(self, name, value)
            self._bitlength = 0
            for field in self._layout:
                self._bitlength += field.width
            return

        if (name in self._fieldnames):
            field = self._fieldnames[name]
            if hasattr(field, 'bounds'):
                field.bounds(value)
            field.set_value(value)
            # If we are setting a field which has no comparison hook,
            # install the default comparison functor.
            if field.compare is None:
                field.compare = field.default_compare
            # If the field we're initializing is the discriminator field,
            # record that we have initialized it, so that the / operator
            # will not clobber its value.
            if self._discriminator is not None and \
               name == self._discriminator.name:
                self._discriminator_inited = True
            self._needencode = True
        else:
            object.__setattr__(self, name, value)

    def __getattribute__(self, name):
        """Getting an attribute means we may have extended an option.

        If we append to an options list we have to reencode the bytes."""
        object.__setattr__(self, '_needencode', True)

        try: 
            fieldnames = object.__getattribute__(self, '_fieldnames')
        except:
            return {}
        if name in fieldnames:
            if isinstance(fieldnames[name], Field) and not \
                   isinstance(fieldnames[name], (LengthValueField, TypeValueField, TypeLengthValueField)):
                return fieldnames[name].get_value()
            else:
                return fieldnames[name]

        return object.__getattribute__(self, name)

    def __eq__(self, other):
        """Do a comparison of the packets data, including fields and bytes."""
        if (type(self) != type(other)):
            return False
        if (self.bytes != other.bytes):
            return False
        for field in self._layout:
            if self._fieldnames[field.name].value != other._fieldnames[field.name].value:
                return False
        return True

    def __ne__(self, other):
        """Do a comparison of the packets data, including fields and bytes."""
        return not self.__eq__(other)

    def matches(self, other):
        """Return True if the packets match.

           Each contains a reference to a comparison function. If the
           reference is None, we assume no comparison need be performed.
           This allows full flexibility in performing matches."""
        if not isinstance(other, self.__class__):
            #if __debug__:
            #    print "Skipping match: isinstance(%s,%s) is False" % \
            #          (type(self), type(other))
            return False
        nocomps = True
        for fn in self._layout:
            f = self._fieldnames[fn.name]
            if f.compare is None:
                continue
            nocomps = False
            #if __debug__ and f.compare is not f.default_compare:
            #    print "WARNING: %s.%s not using default_compare." % \
            #          (type(self), fn.name)
            #if __debug__ and isinstance(f, Field):
            #    print " comparing", f.value, "with", other._fieldnames[fn.name].value
            if not f.compare(self, f, other, other._fieldnames[fn.name]):
                return False
        #if __debug__ and nocomps is True:
        #    print "WARNING: no comparisons were made"
        return True

    def wildcard_mask(self, fieldnames=[], unmask=True):
        """Mark or unmark a list of fields in this Packet as
           wildcard for match(). If unmask is false, then apply a
           default comparison function specific to the class of the Field.
           If an empty list is passed, apply the mask to all fields."""
        if fieldnames == []:
            fieldnames = self._fieldnames.keys()
        for i in fieldnames:
            field = self._fieldnames[i]
            if unmask is True:
                field.compare = None
            else:
                field.compare = field.default_compare

    def __repr__(self):
        """Walk the entire packet and return the values of the fields."""
        #print "Packet.__repr__() called"
        if hasattr(self, 'description'):
            name = self.description
        else:
            name = 'Packet'
        return '<%s: %s>' % (name, ', '.join(attribreprlist(self, self._layout.__iter__())))

    def println(self):
        """Print the packet in line format."""
        return self.__repr__()

    def __str__(self):
        """Pretty print, with returns, the fields of the packet."""
        #print "Packet.__str__() called"
        retval = ""
        if hasattr(self, 'description'):
            retval += "%s\n" % self.description
        for field in self._layout:
            retval += "%s %s\n" % (field.name,
                                   self._fieldnames[field.name].value)
        #for field in self._layout:
        #    retval += "%s %s\n" % (field.name, field.value)
        return retval

    def __len__(self):
        """Return the count of the number of bytes in the packet."""
        return len(self.bytes)

    def __div__(self, packet):
        """/ operator: Insert a packet after this packet in a chain.
           If I am not already part of a chain, build one.
           If the discriminator field in this packet has not been
           explicitly initialized, either by assignment or by constructor
           keyword arguments, then attempt to initialize it based on the
           type of the packet being appended.
           The packet being appended will have its head pointer overwritten
           to point to the chain it is being appended to.
           The head of the chain is always returned."""
        if not isinstance(packet, Packet):
            raise exceptions.TypeError
        if self._head is None:
            head = self.chain()
            if self._discriminator_inited is not True:
                self.rdiscriminate(packet)
            head.append(packet)
            self._head = head
            packet._head = head
        else:
            head = self._head
            if not isinstance(head, Chain):
                raise exceptions.TypeError
            if head.insert_after(self, packet) is False:
                raise exceptions.IndexError
            packet._head = head
        return head

    def __copy__(self):
        """Return a shallow copy of a Packet; used by copy module.
           This is always implemented as a deep copy."""
        return self.__deepcopy__()

    def __deepcopy__(self, memo={}):
        """Return a deep copy of a Packet; used by copy module.

           All derived classes of Packet create a new instance of Layout
           and what it contains every time they are constructed. We need
           to preserve that API contract down here in the lower layers;
           and we need to return an instance of the derived class, so we
           call its default constructor, and make a deep copy of all the
           field values here.
           The backing store in self.bytes is an immutable buffer
           which is dynamically reallocated when changed, so we can
           either copy it or forget about it."""
        from copy import deepcopy
        newp = self.__class__()
        for field in newp._layout:
            newp._fieldnames[field.name] = \
                deepcopy(self._fieldnames[field.name], memo)
        memo[id(self)] = newp
        return newp

    def chain(self):
        """Return the packet and its next packets as a chain."""
        chain = Chain([])
        packet = self
        done = False
        while not done:
            packet._head = chain
            chain.append(packet)
            if packet.data not in [None, packet]:
                packet = packet.data
            else:
                done = True
        return chain
        
    def next(self, bytes, discriminator = None, timestamp = None):
        """Demultiplex higher layer protocols based on a supplied map and
        discriminator field."""

        # If the caller passes their own discriminator then we use the
        # caller's otherwise we use the one built into the packet.
        # The use of a caller supplied discriminator allows us to
        # more easily unpack packets that are chunked, where the
        # current packet does not contain knowledge about what comes
        # next.

        if ((discriminator is not None) and (self._map is not None)):
            if (discriminator in self._map):
                return self._map[self._fieldnames[discriminator.name].value](bytes, timestamp = timestamp)
            
        if ((self._discriminator is not None) and (self._map is not None)):
            if (self._fieldnames[self._discriminator.name].value in self._map):
                return self._map[self._fieldnames[self._discriminator.name].value](bytes, timestamp = timestamp)
        
        return None

    def rdiscriminate(self, packet, discfieldname = None, map = None):
        """Reverse-map an encapsulated packet back to a discriminator
           field value.
           Given a following packet which is about to be appended or
           inserted in a chain, look at its type, and fill out the
           discriminator field.
           This is 'reverse discrimination', as we are mapping a packet
           type back to a code field, which means a reverse dict lookup.
           The mapping may not be 1:1, in which case we simply return
           the first match; isinstance() is used to match derived classes.
           Individual packet classes should override this if they
           need to return a particular flavour of an encapsulated packet,
           or force a lookup against a map which isn't part of the class.
           This is provided as syntactic sugar, used only by the / operator.

           If we find a match, and set the discriminator field, we will
           also set its compare function to the default for the field's
           class if a comparison function was not already specified.

           Return True if we made any changes to self."""

        if (not isinstance(packet, Packet)):
            raise exceptions.TypeError

        # If we were not passed discriminator field name and map, try
        # to infer it from what's inside the instance.
        if map is None:
           if not hasattr(self, '_map') or self._map is None:
               return False
           map = self._map
        if discfieldname is None:
           if self._discriminator is None:
                return False
           discfieldname = self._discriminator.name

        for i in map.iteritems():
            if isinstance(packet, i[1]):
                field = self._fieldnames[discfieldname]
                field.value = i[0]
                if field.compare is None:
                    field.compare = field.default_compare
                return True

        return False

    def calc_checksum(self):
        """Compute checksum for this packet.
           The base class does nothing, it has no notion of checksum."""
        #print "Packet.calc_checksum()"
        pass

    def calc_length(self):
        """Compute length field for this packet.
           The base class does nothing, it has no notion of a length field."""
        pass

    def sizeof(self):
        """Return the size, in bytes, of the packet."""
        return (self._bitlength / 8)

    def toXML(self):
        """Transform the Packet into XML."""
        pass

    def fromXML(self):
        """Create a Packet from XML."""
        pass

    def toHTML(self):
        """Transform a Packet to HTML."""
        pass

    def fromHTML(self):
        """Create a Packet from HTML."""
        pass

    def field(self, name):
        """Return a field by name"""
        for field in self._layout:
            if field.name == name:
                return (field)
        raise FieldError()

class Chain(list):
    """A chain is simply a list of packets.  Chains are used to
    aggregate related sub packets into one chunk for transmission."""

    def __init__(self, packets=[]):
        """initialize a Chain object

        packets - an optional list of packets to add to the new Chain
        """
        list.__init__(self)
        self.packets = packets
        for p in self.packets:
            # XXX We may clobber packets which belong to an existing Chain.
            #if __debug__ and p._head is not None:
            #    print "WARNING: clobbering head pointer"
            p._head = self
        self.encode()

    def __eq__(self, other):
        """test two Chain objects for equality

        Two chains are equal iff they have the same packets and their
        packets have the same data in them."""
        if len(self.packets) != len(other.packets):
            return False
        length = len(self.packets)
        for i in xrange(length):
            if self.packets[i] != other.packets[i]:
                return False
        return True
            
    def __ne__(self, other):
        """test two Chain objects for inequality"""
        return not self.__eq__(other)
            
    def __str__(self):
        """return a pretty printed Chain"""
        #print "Chain.__str__() called"
        #self.encode()
        retval = ""
        for packet in self.packets:
            retval += "%s " % packet.__str__()
        return retval

    def __repr__(self):
        #print "Chain.__repr__() called"
        return self.packets.__repr__()

    def __div__(self, packet, rdiscriminate=True):
        """/ operator: Append a packet to the end of a chain.
           The packet's head pointer will be overwritten to point to
           this chain.
           The default behaviour is to fill out the discriminator field
           of the packet in front of the new tail packet."""
        if not isinstance(packet, Packet):
            raise exceptions.TypeError
        if rdiscriminate is True:
            # Don't clobber a previously initialized field.
            if self.packets[-1]._discriminator_inited is not True:
                self.packets[-1].rdiscriminate(packet)
        self.append(packet)
        packet._head = self
        return self

    def __copy__(self):
        """Return a shallow copy of a Chain; used by copy module.
           This is always implemented as a deep copy."""
        return self.__deepcopy__()

    def __deepcopy__(self, memo={}):
        """Return a deep copy of a Chain; used by copy module.

           Chain is derived from list. We can't rely on the default deepcopy
           handler for list, as it doesn't know our representation.

           Chain may contain Packets, and Packets may refer back to their
           parent Chain. Because of this, we need to make deep copies of
           all Packets contained within a Chain to avoid clobbering
           the contents of existing Chains, and set their head pointer
           to point to the newly created Chain.

           Also, the constructor for Chain needs a list of Packet, so we
           pass it an empty list and then append each copied Packet to
           its internal list."""
        from copy import deepcopy
        newchain = self.__class__([])
        memo[id(self)] = newchain
        for p in self.packets:
            newp = deepcopy(p, memo)
            newp._head = newchain
            newchain.packets.append(newp)
        newchain.encode()
        return newchain

    def append(self, packet):
        """Append a packet to a chain.  Appending a packet requires
        that we update the bytes as well."""
        self.packets.append(packet)
        self.encode()

    def insert_after(self, p1, p2, rdiscriminate=True):
        """Insert a packet into a chain after a given packet instance.
           Used only by the div operator. The default behaviour is to
           set discriminator fields in p1 based on p2."""
        length = len(self.packets)
        for i in xrange(length):
            if self.packets[i] is p1:
                if rdiscriminate is True:
                    p1.rdiscriminate(p2)
                self.packets.insert(i, p2)
                self.encode()
                return True
        return False

    def contains(self, packet):
        """If this chain contains a packet which matches the packet provided,
           return its index. Otherwise, return None.

           It is assumed that 'packet' contains any wildcard patterns;
           this is the logical reverse of Field.match() and Packet.match().
           A bitwise comparison is not performed; a structural match
           using the match() function is used instead."""
        (p, i) = self.find_first_of(type(packet))
        if p is not None and packet.matches(p):
            return i
        return None

    def matches(self, chain):
        """Return True if this chain matches the chain provided.

           It is assumed that *this* chain contains any wildcard patterns.
           A strict size comparison is not performed.
           A bitwise comparison is not performed; a structural match
           using the match() function is used instead."""
        if len(self.packets) > len(chain.packets):
            #print "Skipping: packet header counts don't match"
            return False
        i = 0
        for p in self.packets:
            #print "comparing %s", type(p)
            if not p.matches(chain.packets[i]):
                return False
            i += 1
        return True

    def wildcard_mask(self, unmask=True):
        """Mark or unmark all of the fields in each Packet in this Chain
           as a wildcard for match() or contains()."""
        length = len(self.packets)
        for i in xrange(length):
            self.packets[i].wildcard_mask([], unmask)

    def encode(self):
        """Encode all the packets in a chain into a set of bytes for the Chain"""
        self.bytes = ""
        for packet in self.packets:
            self.bytes += packet.bytes
    
    def decode(self, bytes):
        """Decode all the bytes of all the packets in a Chain into the underlying packets"""
        for packet in self.packets:
            packet.decode(packet.bytes)

    # XXX We are a model of list so if we proxy this to member
    # self.packets this can be renamed index() and go away.
    def index_of(self, packet):
        """Return the index of 'packet' in this chain."""
        n = 0
        for i in self.packets:
            if i is packet:
                pseen = True
                break
            n += 1
        #print "index of %s is %d" % (type(packet), n)
        assert pseen is True, "Chain inconsistent: packet not found"
        return n

    def collate_following(self, packet):
        """Given a packet which is part of this chain, return a string
           containing the bytes of all packets following it in this chain.
           Helper method used by Internet transport protocols."""
        tmpbytes = ""
        n = self.index_of(packet)
        if n == len(self.packets)-1:
            return tmpbytes
        for p in self.packets[n+1:]:
            #print "collating %s" % (type(p))
            tmpbytes += p.getbytes()
        return tmpbytes

    def find_first_of(self, ptype):
        """Find the first packet of type 'ptype' in this chain.
           Return a tuple (packet, index)."""
        n = 0
        for p in self.packets:
            if isinstance(p, ptype):
                return (p, n)
            n += 1
        return (None, None)

    def find_preceding(self, packet, ptype, adjacent=True):
        """Given a packet which is part of this chain, return a reference
           to a packet of the given type which precedes this packet,
           and its index in the chain, as a tuple.

           If the 'adjacent' argument is True, then the packet
           immediately preceding 'packet' must be an instance of type.
           Helper method used by Internet transport protocols."""
        n = self.index_of(packet)
        if n == 0:
            return (None, None)
        lower = 0
        if adjacent is True:
            lower = max(n - 2, 0)
        for p in reversed(self.packets[lower:n]):
            n -= 1
            if isinstance(p, ptype):
                return (p, n)
        return (None, None)

    def calc_checksums(self):
        """Compute and store checksums for all packets in this chain,
           taking encapsulation into account.

           By default the packets are enumerated in reverse order
           to how they appear on the wire. This is how IETF-style
           protocols are normally dealt with; ITU-style protocols
           may require other quirks."""
        #print "Chain.calc_checksum()"
        for packet in reversed(self.packets):
            packet.calc_checksum()

    def calc_lengths(self):
        """Compute and store length fields for all packets in this chain,
           taking encapsulation into account. """
        for packet in reversed(self.packets):
            packet.calc_length()

    def fixup(self):
        """Convenience method to calculate lengths, checksums, and encode."""
        self.calc_lengths()
        self.calc_checksums()
        self.encode()

class ConnNotImpError(Exception):
    """Calling a method that is not implemented raises this exception.

    The base class, and some of the derived classes do not implement
    every moethod that could be.  This exception is meant to catch and
    report thos instances.
    """

    def __init__(self, message):
        self.message = message

class EOFError(Exception):
    """If the I/O handle was closed, or end of file seen,
       raise this exception. """

    def __init__(self, message='End of file'):
        self.message = message

class LimitReachedError(Exception):
    """If a packet input threshold is reached, raise this exception. """

    def __init__(self, message='Limit reached'):
        self.message = message

class TimeoutError(Exception):
    """If a possibly blocking read operation times out, this exception
       will be raised. """

    def __init__(self, message='Timed out'):
        self.message = message

class UnpackError(Exception):
    """Error raised when we fail to unpack a packet."""
    def __init__(self, message):
        self.message = message

class EOF(object):
    """This type allows end-of-file to be matched as a pattern by expect()."""
    def __init__(self):
        pass

class TIMEOUT(object):
    """This type allows timeouts to be matched as a pattern by expect()."""
    def __init__(self):
        pass

class LIMIT(object):
    """This type allows 'limit reached' to be matched by expect()."""
    def __init__(self):
        pass

class Connector(object):
    """Connectors are a way of have a very generic socket like
    mechanism over which the packets can be sent.  Unlike the current
    split between sockets, which work OK down to almost the RAW layer,
    and low level stuff like pcap and bpf, connectors will are a
    unifying mechanism so you can write packets over any of the
    available APIs and the connector will do the right thing.

    The Connector class is a virtual base class upon which all the
    real classes are based."""

    def __init__(self):
        self.matches = None
        self.match_index = None
        # XXX Can't do protected constructors in Python.
        #raise ConnNotImpError, "Cannot use base class"

    def accept(self):
        raise ConnNotImpError, "Cannot use base class"

    def bind(self):
        raise ConnNotImpError, "Cannot use base class"

    def connect(self):
        raise ConnNotImpError, "Cannot use base class"

    def listen(self):
        raise ConnNotImpError, "Cannot use base class"

    def read(self):
        raise ConnNotImpError, "Cannot use base class"

    def poll_read(self, timeout):
        """Poll the underlying I/O layer for a read.
           Return TIMEOUT if the timeout was reached."""
        raise ConnNotImpError, "Cannot use base class"

    def read_packet(self):
        """Read a packet from the underlying I/O layer, and return
           an instance of a class derived from pcs.Packet appropriate
           to the data-link or transport layer in use.
           If the Connector has multiple data-link layer support, then
           the type returned by this method may vary.
           If the underlying packet parsers throw an exception, it
           will propagate here. """
        raise ConnNotImpError, "Cannot use base class"

    def read_chain(self):
        """Read the next available packet and attempt to decapsulate
           all available layers of encapsulation into Python objects.
           If the underlying packet parsers throw an exception, it
           will propagate here."""
        p = self.read_packet()
        return p.chain()

    def try_read_n_chains(self, n):
        """Try to read at most n packet chains from the underlying
           I/O layer. If n is None or 0, try to read exactly one packet.
           Connectors with their own buffering semantics should override
           this method (e.g. PcapConnector). Used by expect()."""
        result = []
        if n is None or n == 0:
            n = 1
        for i in xrange(n):
            p = self.read_packet()
            if p is not None:
                c = p.chain()
                result.append(c)
            else:
                break
        return result

    def write(self):
        raise ConnNotImpError, "Cannot use base class"

    def send(self):
        raise ConnNotImpError, "Cannot use base class"

    def sendto(self):
        raise ConnNotImpError, "Cannot use base class"

    def recv(self):
        raise ConnNotImpError, "Cannot use base class"

    def recvfrom(self):
        raise ConnNotImpError, "Cannot use base class"

    def close(self):
        raise ConnNotImpError, "Cannot use base class"

    def expect(self, patterns=[], timeout=None, limit=None):
        """Read from the Connector and return the index of the
           first pattern which matches the input chain; otherwise,
           raise an exception.

           On return, the matches property will contain a list of matching
           packet chain(s). There may be more than one match if a live
           capture matches more than one before the loop exits.

            * If the 'limit' argument is set, raise an exception after 'limit'
              packets have been read, regardless of match.
            * If 'timeout' is set, raise an exception after the
              timeout expires. This is only supported if the underlying
              Connector fully implements non-blocking I/O.

           The syntax is intentionally similar to that of pexpect:
            * If any of EOF, LIMIT or TIMEOUT are specified, the exceptions
              are not raised but are instead matched as patterns.
            * If a Chain is specified, it is matched against
              the chain using the Chain.match() method.
            * If neither a timeout or a limit is specified, or an EOF
              was not encountered, this function may potentially block forever.
            * NOTE: Packets can no longer be specified on their own as filters.

           TODO: Make this drift and jitter robust (CLOCK_MONOTONIC)."""
        from time import time
        start = time()
        then = start
        remaining = limit
        delta = timeout
        self.matches = None
        self.match_index = None
        while True:
            result = self.poll_read(delta)

            # Compute the wait quantum for the next read attempt.
            if timeout is not None:
                now = time()
                delta = now - then
                then = now

            # Check if the user tried to match exceptional conditions
            # as patterns. We need to check for timer expiry upfront.
            length = len(patterns)
            if timeout is not None and (now - start) > timeout:
                for i in xrange(length):
                    if isinstance(patterns[i], TIMEOUT):
                        self.matches = [patterns[i]]
                        self.match_index = i
                        return i
                raise TimeoutError

            if isinstance(result, TIMEOUT):
                if delta > 0:
                    #print "woken up early"
                    continue

            if isinstance(result, EOF):
                for i in xrange(length):
                    if isinstance(patterns[i], EOF):
                        self.matches = [patterns[i]]
                        self.match_index = i
                        return i
                raise EOFError

            # Try to read as many pending packet chains as we can; some
            # Connectors override this as their I/O layers expect to return
            # multiple packets at once, and reentering Python might lose
            # a race with the ring buffer (e.g. pcap_dispatch()).
            chains = self.try_read_n_chains(remaining)

            next_chain = 0
            matches = []
            match_index = None

            # Check for a first match in the filter list.
            # If we exceed the remaining packet count, break.
            for i in xrange(len(chains)):
                c = chains[i]
                #print "expect() firstpass: saw", str(type(c.packets[2]))[:-2].split('.')[-1]
                if limit is not None:
                    remaining -= 1
                for j in xrange(length):
                    filter = patterns[j]
                    if isinstance(filter, Chain) and filter.matches(c):
                        #print "matched at index", i
                        #print "appending ip proto ", c.packets[1].protocol, \
                        #   "with type ", type(c.packets[2]), "as match"
                        matches.append(c)
                        match_index = j
                        next_chain = i+1
                        break
                # We need to break out of the outer loop too if we match.
                if match_index is not None or \
                   limit is not None and remaining == 0:
                    break

            # If one of our filters matched, try to match all the other
            # packets we got in a batch from a possibly live capture.
            if match_index is not None:
                filter = patterns[match_index]
                #print "scanning", next_chain, "to", len(chains)
                for i in xrange(next_chain, len(chains)):
                    c = chains[i]
                    #print "expect() lastpass: saw", str(type(c.packets[2]))[:-2].split('.')[-1]
                    if isinstance(filter, Chain) and filter.matches(c):
                        #print "matched at index", i
                        #print "appending ip proto ", c.packets[1].protocol, \
                        #   "with type ", type(c.packets[2]), "as match"
                        matches.append(c)

                self.matches = matches
                self.match_index = match_index
                return match_index

            # If we never got a match, and we reached our limit,
            # return an error.
            if limit is not None and remaining == 0:
                for i in xrange(length):
                    if isinstance(patterns[i], LIMIT):
                        self.matches = [patterns[i]]
                        self.match_index = i
                        return i
                raise LimitReachedError

            #print "next expect() iteration"

        return None

class PcapConnector(Connector):
    """A connector for protocol capture and injection using the pcap library

    The Pcap connector looks like all the rest of the connectors for
    PCS with the differnece that it provides direct network access and
    bypasses all the protocol stacks on a system.  The usual
    precautions about routing, framing and the like apply so do not
    use this connector if you're not prepared to do all the protocol
    work on your own.
    """

    def __init__(self, name=None, snaplen=65535, promisc=True, \
                 timeout_ms=500):
        """initialize a PcapConnector object

        name - the name of a file or network interface to open
        snaplen   - maximum number of bytes to capture for each packet
        promisc   - boolean to specify promiscuous mode sniffing
        timeout_ms - read timeout in milliseconds
        """
        super(PcapConnector, self).__init__()
        try:
            self.file = pcap.pcap(name, snaplen, promisc, timeout_ms)
        except:
            raise

        # Grab the underlying pcap objects members for convenience
        self.dloff = self.file.dloff
        self.setfilter = self.file.setfilter
        self.dlink = self.file.datalink()

        # Default to blocking I/O.
        self.file.setnonblock(False)
        self.is_nonblocking = False

    def read(self):
        """read a packet from a pcap file or interface

        returns the packet as a bytearray
        """
        return self.file.next()[1]

    def next(self):
        """return a packet with its timestamp"""
        return self.file.next()

    def recv(self):
        """recv a packet from a pcap file or interface"""
        return self.file.next()[1]
    
    def recvfrom(self):
        """recvfrom a packet from a pcap file or interface"""
        return self.file.next()[1]

    def setdirection(self, inout):
        """Set the pcap direction."""
        return self.file.setdirection(inout)

    def poll_read(self, timeout=None):
        """Poll the underlying I/O layer for a read.
           Return TIMEOUT if the timeout was reached."""
        from select import select
        fd = self.file.fileno()
        # Switch to non-blocking mode if entered without.
        if not self.is_nonblocking:
            self.file.setnonblock(True)
        result = select([fd],[],[], timeout)
        # Restore non-blocking mode if entered without.
        if not self.is_nonblocking:
            self.file.setnonblock(False)
        if not fd in result[0]:
            return TIMEOUT()
        return None

    def read_packet(self):
        (timestamp, packet) = self.file.next()
        return self.unpack(packet, self.dlink, self.dloff, timestamp)

    def readpkt(self):
        # XXX legacy name.
        return self.read_packet()

    def try_read_n_chains(self, n):
        """Try to read at most n packet chains from the pcap session.
           Used by Connector.expect() to do the right thing with
           buffering live captures."""
        if n is None or n == 0:
            n = -1	# pcap: process all of the buffer in a live capture
        result = []	# list of chain
        ltp = []	# list of tuple (ts, packet)
        def handler(ts, p, *args):
            ltp = args[0]
            ltp.append((ts, p))
        self.file.dispatch(n, handler, ltp)
        #print "PcapConnector.try_read_n_chains() read ", len(ltp)
        for tp in ltp:
            p = self.unpack(tp[1], self.dlink, self.dloff, tp[0])
            c = p.chain()
            result.append(c)
        return result

    def expect(self, patterns=[], timeout=None, limit=None):
        """PcapConnector needs to override expect to set it up for
           non-blocking I/O throughout. We do this to avoid losing
           packets between expect sessions.
           Typically we would also set up pcap filter programs here
           if performing potentially expensive matches."""
        oldnblock = self.is_nonblocking
        if oldnblock is False:
            self.file.setnonblock(True)
            self.is_nonblocking = True
        result = Connector.expect(self, patterns, timeout, limit)
        if oldnblock is False:
            self.file.setnonblock(False)
            self.is_nonblocking = False
        return result

    def write(self, packet, bytes):
        """Write a packet to a pcap file or network interface.

        bytes - the bytes of the packet, and not the packet object
"""
        return self.file.inject(packet, bytes)

    def send(self, packet, bytes):
        """Write a packet to a pcap file or network interface.

        bytes - the bytes of the packet, and not the packet object"""
        return self.file.inject(packet, bytes)

    def sendto(self, packet, bytes):
        """Write a packet to a pcap file or network interface.

        bytes - the bytes of the packet, and not the packet object"""
        return self.file.inject(packet, bytes)

    def unpack(self, packet, dlink, dloff, timestamp):
        """Create a Packet from a string of bytes.

        packet - a Packet object
        dlink - a data link layer as defined in the pcap module
        dloff - a datalink offset as defined in the pcap module
        """
        import packets.ethernet
        import packets.localhost

        if dlink == pcap.DLT_EN10MB:
            return packets.ethernet.ethernet(packet, timestamp)
        elif dlink == pcap.DLT_NULL:
            return packets.localhost.localhost(packet, timestamp)
        elif dlink == pcap.DLT_RAW:
            return packets.ipv4.ipv4(packet, timestamp)
        else:
            raise UnpackError, "Could not interpret packet"
                
    def close(self):
        """Close the pcap file or interface."""
        self.file.close()

    def set_bpf_program(self, prog):
        from pcs.bpf import program
        if not isinstance(prog, program):
            raise ValueError, "not a BPF program"
        return self.file.setbpfprogram(prog)

    # The intention is to offload some, but not all, of the filtering work
    # from PCS to PCAP using BPF as an intermediate representation.
    # Only add BPF match opcodes for discriminator fields which satisfy
    # certain criteria.
    # Relative branches are forward only up to 256 instructions.
    # The length of each packet header may not be constant if optional
    # fields are present in filter chain, so calculate offset into
    # chain using getbytes() not sizeof().
    # XXX We always assume a datalink header is present in the chain.
    def make_bpf_program(c):
        """Given a filter chain c, create a simple BPF filter program."""
        from pcs.bpf import program, ldw, ldb, ldh, jeq, ret
        assert isinstance(c, Chain)
        # XXX It seems necessary to compute offsets in bits. At the
        # moment this code does no special handling of bytes within
        # BPF's 32-bit words.
        foff = 0
        prog = program()
        for p in c.packets:
            for fn in p._layout:
                f = p._fieldnames[fn.name]
                #print "foff: ", foff
                if isinstance(f, Field) and \
                 f.compare is f.default_compare and \
                 f.discriminator is True and (f.width % 8) == 0:
                    if f.width == 8:
                         prog.instructions.append(ldb(foff>>3))
                    elif f.width == 16:
                         prog.instructions.append(ldh(foff>>3))
                    elif f.width == 32:
                         prog.instructions.append(ldw(foff>>3))
                    prog.instructions.append(jeq(0, 0, f.value))
                foff += f.width
        prog.instructions.append(ret(96))
        prog.instructions.append(ret(0))
        jfabs = len(prog.instructions) - 1
        ii = 0
        # Relative branch displacements are measured from the address of
        # the following opcode.
        for i in prog.instructions:
            ii += 1
            if isinstance(i, jeq):
                assert ((jfabs - ii) <= 255), "Relative branch overflow."
                i.jf = jfabs - ii
        return prog

    make_bpf_program = staticmethod(make_bpf_program)

class PcapDumpConnector(Connector):
    """A connector for dumping packets to a file for later re-use.

    The PcapDump connector allows the programmer to write libpcap
    compatible files full of packets.  Unlike the PcapConnector it
    does not alloww the programmer to read from a dump file, for that
    the PcapConnector class should be used.
    """

    def __init__(self, dumpfile = None, dumptype = None):
        """initialize a pcap dump connector"""
        from pcap import pcap
        try:
            self.file = pcap(dumpfile = dumpfile, dumptype=dumptype)
        except:
            raise

        # Grab the underlying pcap objects members for convenience
        self.dloff = self.file.dloff
        self.setfilter = self.file.setfilter
        
    def write(self, packet):
        """write a packet to the dumpfile"""
        if type(packet) is buffer:
            packarg = "%ds" % len(packet)
            packet = struct.unpack(packarg, packet)[0]
        return self.file.dump(packet)

    def send(self, packet):
        """send a packet to the dumpfile

        calls the write() method"""
        return self.file.dump(packet)

    def sendto(self, packet, header):
        """sendto a packet to the dumpfile

        calls the write() method"""
        return self.file.dump(packet, header)

    def close(self):
        """close the dumpfile"""
        self.file.dump_close()


class TapConnector(Connector):
    """A connector for capture and injection using the character
       device slave node of a TAP interface.
       Like PcapConnector, reads are always blocking, however writes
       may always be non-blocking. The underlying I/O is non-blocking;
       it is hard to make it work with Python's buffering strategy
       for file(), so os-specific reads/writes are used.
       No filtering is currently performed, it would be useful to
       extend pcap itself to work with tap devices.
    """

    def __init__(self, name):
        """initialize a TapConnector object
        name - the name of a file or network interface to open
        """
        import os
        from os import O_NONBLOCK, O_RDWR
        self.is_nonblocking = False
        try:
            self.fileno = os.open(name, O_RDWR)
        except:
            raise

    def read(self):
        """read a packet from a tap interface
        returns the packet as a bytearray
        """
        return self.blocking_read()

    def recv(self):
        """recv a packet from a tap interface"""
        return self.blocking_read()
    
    def recvfrom(self):
        """recvfrom a packet from a tap interface"""
        return self.blocking_read()

    def read_packet(self):
        """Read a packet from a pcap file or interfaces returning an
        appropriate packet object."""
        bytes = self.blocking_read()
        return packets.ethernet.ethernet(bytes)

    def readpkt(self):
        # XXX legacy name.
        return self.read_packet()

    def write(self, packet, bytes):
        """Write a packet to a pcap file or network interface.
        bytes - the bytes of the packet, and not the packet object
        """
        return self.blocking_write(packet)

    def send(self, packet, bytes):
        """Write a packet to a pcap file or network interface.
        bytes - the bytes of the packet, and not the packet object"""
        return self.blocking_write(packet)

    def sendto(self, packet, bytes):
        """Write a packet to a pcap file or network interface.
        bytes - the bytes of the packet, and not the packet object"""
        return self.blocking_write(packet)

    # XXX We could just call PcapConnector's method here.
    def poll_read(self, timeout=None):
        """Poll the underlying I/O layer for a read.
           Return TIMEOUT if the timeout was reached."""
        from select import select
        fd = self.file.fileno()
        # Switch to non-blocking mode if entered without.
        if not self.is_nonblocking:
            self.file.setnonblock(True)
        result = select([fd],[],[], timeout)
        # Restore non-blocking mode if entered without.
        if not self.is_nonblocking:
            self.file.setnonblock(False)
        if not fd in result[0]:
            return TIMEOUT()
        return None

    def try_read_n_chains(self, n):
        """Try to read as many packet chains from the tap device as are
           currently available. Used by Connector.expect() to do the
           right thing with buffering live captures.
           Note that unlike pcap, timestamps are not real-time."""
        from time import time
        result = []	# list of chain
        lpb = []	# list of strings (packet buffers) 
        if __debug__ and not self.is_nonblocking:
            print "WARNING: TapConnector.try_read_n_chains w/o O_NONBLOCK"
        ts = time()
        for i in xrange(n):
            pb = self.try_read_one()
            if pb is None:
                break
            lpb.append(pb)
        for pb in lpb:
            p = self.unpack(pb, self.dlink, self.dloff, ts)
            c = p.chain()
            result.append(c)
        return result

    # XXX We could just call PcapConnector's method here.
    def expect(self, patterns=[], timeout=None, limit=None):
        """TapConnector needs to override expect just like
           PcapConnector does."""
        # Force non-blocking mode.
        oldnblock = self.is_nonblocking
        if oldnblock is False:
            self.setnonblock(True)
            self.is_nonblocking = True
        # Call base class expect() routine.
        result = Connector.expect(self, patterns, timeout, limit)
        # Unconditionally restore O_NBLOCK mode.
        self.setnonblock(oldnblock)
        self.is_nonblocking = oldnblock
        return result

    def setnonblock(enabled):
        """Set the non-blocking flag. Return the value of the file flags."""
        from os import O_NONBLOCK
        from fcntl import fcntl, F_SETFL, F_GETFL
        flags = fcntl(self.fileno, F_GETFL)
        if ((flags & O_NONBLOCK) == O_NONBLOCK) != enabled:
            flags ^= O_NONBLOCK
            if fcntl(self.fileno, F_SETFL, flags) == -1:
                raise OSError, "fcntl"
        return flags

    def write(self, packet, bytes):
        """Write a packet to a pcap file or network interface.
           bytes - the bytes of the packet, and not the packet object"""
        return self.file.inject(packet, bytes)

    def send(self, packet, bytes):
        """Write a packet to a pcap file or network interface.

        bytes - the bytes of the packet, and not the packet object"""
        return self.file.inject(packet, bytes)

    def blocking_read(self):
        """Block until the next packet arrives and return it."""
        # Force a blocking read.
        oldnblock = self.is_nonblocking
        if oldnblock is True:
            self.setnonblocking(False)
            self.is_nonblocking = False
            poll_read(None)
        result = try_read_one(self)
        # Unconditionally restore O_NBLOCK mode.
        self.setnonblocking(oldnblock)
        self.is_nonblocking = oldnblock
        return result

    def try_read_one(self):
        """Low-level non-blocking read routine, tries to read the
           next frame from the tap."""
        import array
        import fcntl
        import os
        from termios import FIONREAD
        try:
            buf = array.array('i', [0])
            s = fcntl.ioctl(self.fileno, FIONREAD, buf)
            qbytes = buf.pop()
            if qbytes == 0:
                return None
            return os.read(self.fileno, qbytes)
        except:
            raise
        return None

    def blocking_write(self, bytes):
        import os
        # Force a blocking write.
        oldnblock = self.is_nonblocking
        if oldnblock is True:
            self.setnonblocking(False)
            self.is_nonblocking = False
        result = os.write(self.fileno, bytes)
        # Unconditionally restore O_NBLOCK mode.
        self.setnonblocking(oldnblock)
        self.is_nonblocking = oldnblock
        return result

    def close(self):
        import os
        os.close(self.fileno)

class IP4Connector(Connector):
    """Base class for all IPv4 connectors.

    This class implements all the necessary functions for a plain IPv4
    based connector.  In particular the data access methods, such as
    read, write, etc. likely do not need to be overridden by the sub classes.
    """

    def __init__(self, name = None):
        """initialize an IP4Connector"""
        try:
            self.file = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
        except:
            raise

    def connect(self, address):
        """connect to a foreign IPv4 address"""
        return self.file.connect(address)

    def read(self, len):
        """read data from an IPv4 socket"""
        return self.file.recv(len)

    def read_packet(self):
        bytes = self.file.read()
        return packets.ipv4.ipv4(bytes)

    def recv(self, len, flags = 0):
        """recv data from an IPv4 socket"""
        return self.file.recv(len, flags)
    
    def recvfrom(self, len, flags = 0):
        """recvfrom data from an IPv4 socket"""
        return self.file.recvfrom(len, flags)

    def write(self, packet, flags = 0):
        """write data to an IPv4 socket"""
        return self.file.sendall(packet, flags)

    def send(self, packet, flags = 0):
        """send data to an IPv4 socket"""
        return self.file.send(packet, flags)

    def sendto(self, packet, addr, flags = 0):
        """sendto data to an IPv4 socket"""
        return self.file.sendto(packet, flags, addr)

    def close(self):
        """close an IPv4 Connector"""
        self.file.close()
    
class UDP4Connector(IP4Connector):
    """A connector for IPv4 UDP sockets
    """

    def __init__(self, address = None, port = None):
        """initialize a UDPv4 connector

        address - an optional address to connect to
        port - an optional port to connect to
        """
        try:
            self.file = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        except:
            raise

        if (address is not None and port is not None):
            try:
                self.file.connect((address, port))
            except:
                raise

class TCP4Connector(IP4Connector):
    """A connector for IPv4 TCP sockets

    The TCP4Connector implements a IPv4 TCP connection
    """

    def __init__(self, addr = None, port = None ):
        """initialize a TCP4Connector class for TCP over IPv4"""
        try:
            self.file = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        except:
            raise

        if (addr is not None and port is not None):
            try:
                self.file.connect((addr, port))
            except:
                raise

class UmlMcast4Connector(UDP4Connector):
    """A connector for hooking up to a User Mode Linux virtual LAN,
       implemented by Ethernet frames over UDP sockets in a multicast group.
       Typically used for interworking with QEMU. See:
          http://user-mode-linux.sourceforge.net/old/text/mcast.txt

       No additional encapsulation of the frames is performed, nor is
       any filtering performed.
       Be aware that this encapsulation may fragment traffic if sent
       across a real LAN. The multicast API is being somewhat abused here
       to send and receive the session on the same socket; generally apps
       shouldn't bind to group addresses, and it's not guaranteed to work
       with all host IP stacks.
    """

    def __init__(self, group, port, ifaddr = None):
        """initialize a UML Mcast v4 connector
        group - the multicast group to join
        port - the UDP source/destination port for the session
        ifaddr - optionally, the interface upon which to join the group.
        """
        import os
        import fcntl
        from os import O_NONBLOCK
        from fcntl import F_GETFL, F_SETFL
        if ifaddr is None:
            ifaddr = "127.0.0.1"
        try:
	    self.group = group
	    self.port = int(port)

            self.file = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)

            flags = fcntl.fcntl(self.file, F_GETFL)
            flags |= O_NONBLOCK
            fcntl.fcntl(self.file, F_SETFL, flags)

            self.file.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.file.setsockopt(IPPROTO_IP, IP_MULTICAST_LOOP, 1)

            gaddr = inet_atol(self.group)
            mreq = struct.pack('!LL', gaddr, inet_atol(ifaddr))
            self.file.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mreq)

            self.file.bind((self.group, self.port))
        except:
            raise

    def read_packet(self):
        bytes = self.blocking_read()
        return packets.ethernet.ethernet(bytes)

    def readpkt(self):
        # XXX legacy name.
        return self.read_packet()

    def poll_read(self, timeout=None):
        from select import select
        fd = self.file.fileno()
        result = select([fd],[],[], timeout)
        if not fd in result[0]:
            return TIMEOUT()
        return None

    def blocking_read(self):
        # XXX Should use recvfrom.
        # XXX Shouldn't have to guess buffer size.
        import os
        poll_read(None)
        return os.read(self.file.fileno(), 1502)

    def write(self, packet, flags = 0):
        """write data to an IPv4 socket"""
        return self.file.sendto(packet, flags, (self.group, self.port))


class SCTP4Connector(IP4Connector):
    """A connector for IPv4 SCTP sockets

    The TCP4Connector implements a IPv4 SCTP connection
    """

    def __init__(self, addr = None, port = None ):
        """initialize a SCTP4Connector class for TCP over IPv4"""
        try:
            self.file = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)
        except:
            raise

        if (addr is not None and port is not None):
            try:
                self.file.connect((addr, port))
            except:
                raise

class IP6Connector(Connector):
    """Base class for all IPv6 connectors.

    This class implements all the necessary functions for a plain IPv6
    based connector.  In particular the data access methods, such as
    read, write, etc. likely do not need to be overridden by the sub classes.
    """

    def __init__(self, name = None):
        """initialize an IPPConnector class for raw IPv6 access"""
        try:
            self.file = socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6)
        except:
            raise

    def read(self, len):
        """read from an IPv6 connection"""
        return self.file.recv(len)

    def read_packet(self):
        bytes = self.file.read()
        return packets.ipv6.ipv6(bytes)

    def recv(self, len, flags = 0):
        """recv data from an IPv4 socket"""
        return self.file.recv(len, flags)

    def recv(self, len, flags = 0):
        """recv from an IPv6 connection"""
        return self.file.recv(len, flags)
    
    def recvfrom(self, len, flags = 0):
        """readfrom on an IPv6 connection"""
        return self.file.recvfrom(len, flags)

    def write(self, packet, flags = 0):
        """write to an IPv6 connection"""
        return self.file.sendall(packet, flags)

    def send(self, packet, flags = 0):
        """send to an IPv6 connection"""
        return self.file.send(packet, flags)

    def sendto(self, packet, addr, flags = 0):
        """sendto to an IPv6 connection"""
        return self.file.sendto(packet, flags, addr)

    def mcast(self, iface):
        """set IP6 connector into multicast mode"""
        # TODO: support Windows; use ctypes module in Python >2.5.
        import dl
        _libc = dl.open('libc.so')
        ifn = _libc.call('if_nametoindex', iface)
        self.sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1)
        self.sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 5)
        self.sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_IF, ifn)


class UDP6Connector(IP6Connector):
    """A connector for IPv6 UDP sockets """

    def __init__(self, name = None):
        """initialize a UDPv6 connector"""
        try:
            self.file = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        except:
            raise

        if (address is not None and port is not None):
            try:
                self.file.connect([address, port])
            except:
                raise

class TCP6Connector(IP6Connector):
    """A connector for IPv4 TCP sockets

    The TCP4Connector implements a IPv4 TCP connection
    """

    def __init__(self, name = None):
        """initialize a TCPv6 connector"""
        try:
            self.file = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
        except:
            raise

        if (address is not None and port is not None):
            try:
                self.file.connect([address, port])
            except:
                raise

class SCTP6Connector(IP6Connector):
    """A connector for IPv6 SCTP sockets

    The SCTP  implements a IPv4 TCP connection
    """

    def __init__(self, name = None):
        """initialize a SCTP6Connector"""
        try:
            self.file = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP)
        except:
            raise

        if (address is not None and port is not None):
            try:
                self.file.connect([address, port])
            except:
                raise

###
### Convenience functions and adjuncts to certain probelmatic bits of Python
### network code.  (These versions from Zach Riggle)
###

def inet_lton(integer):
    return struct.pack(">L",integer)

def inet_ltoa(integer):
    return socket.inet_ntoa(inet_lton(integer))

def inet_ntol(byteString):
    return struct.unpack(">L",byteString)[0]

def inet_atol(ipString):
    return inet_ntol(inet_aton(ipString))

def bsprintf(flags, fmt):
    """Return a formatted list of flag names.

       flags  -  the flag values to format
       fmt    -  a sequence of bit numbers and descriptions as a string

       Compatible with bprintf() from BSD's route(8) command sources.
       This can be used to emulate %b from BSD's kernel printf(9)."""
    assert isinstance(flags, int) and isinstance(fmt, str)
    s = ""
    i = 0
    j = 0
    fmtlen = len(fmt)
    while i < fmtlen:
        c = ord(fmt[i])
        if c > 32:
            i += 1
        else:
            for j in xrange(i+1, fmtlen):
                if ord(fmt[j]) <= 32:
                    break
            if (flags & (1 << (c - 1))) != 0:
                if len(s) > 0:
                    s += ','
                s += fmt[i+1:j+1]
            i = j
    if len(s) > 0:
        s = '<' + s
        s += '>'
    return s
    
