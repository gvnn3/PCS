# Copyright (c) 2005, Neville-Neil Consulting
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

def attribreprlist(obj, attrs):
    return map(lambda x, y = obj: '%s: %s' % (x.name, repr(getattr(y, x.name))), itertools.ifilter(lambda x, y = obj: hasattr(y, x.name), attrs))

class FieldBoundsError(Exception):
    """When a programmer tries to set a field with an inappropriately
    sized piece of data this exception is raised."""

    def __init__(self, message):
        self.message = message
    def __str__(self):
        return repr(self.message)
    
class Field(object):
    """A field is a name, a type, a width in bits, possibly a default
value and can be marked as a dicriminator for higher level packet
demultiplexing .  These classes are used by the packet to define the
layout of the data and how it is addressed."""
    
    def __init__(self, name = "", width = 1, default = None,
                 discriminator = False, is_wildcard=False):
        """initialize a field

        name - a string name
        width - a width in bits
        default - a default value
        discriminator - is this field used to demultiplex packets
        """
        ## the name of the Field
        self.name = name
        ## the width, in bites, of the field's data
        self.width = width
        ## the default value of the field, must fit into bits
        self.default = default
        ## Is this field used to demultiplex higher layer packets?
        self.discriminator = discriminator
        ## Should this field be ignored by the Packet.matches() method?
        self.is_wildcard = is_wildcard
        ## Fields store the values
        if default == None:
            self.value = 0
        else:
            self.value = default
        
    def __repr__(self):
        """return an appropriate representation for the Field object"""
        return "<pcs.Field  name %s, %d bits, default %s, discriminator %d, " \
               "wildcard %d>" % \
               (self.name, self.width, self.default, self.discriminator, \
                self.is_wildcard)

    def decode(self, bytes, curr, byteBR):
        """Decode a field and return the value and the updated current
        pointer into the bytes array

        bytes - the byte array for the packet
        curr - the current byte position in the bytes array
        byteBR - the number of Bits Remaining in the current byte
        """
        real_value = 0
        fieldBR = self.width
        while fieldBR > 0 and curr < len(bytes):
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
        if ((value == None) or
            (value < 0) or
            (value > (2 ** self.width) - 1)):
            raise FieldBoundsError, "Value must be between 0 and %d but is %d" % ((2 ** self.width - 1), value)
        
class FieldAlignmentError(Exception):
    """When a programmer tries to decode a field that is not
    on a byte boundary this exception is raised."""
    
    def __init__(self, message):
        """set the FieldAlignmentError message"""
        ## the message that will be output when this error is raised
        self.message = message

class StringField(Field):
    """A string field is a name, a width in bits, and possibly a
default value.  The data is to be interpreted as a string, but does
not encode the length into the packet.  Length encoded values are
handled by the LengthValueField."""
    
    def __init__(self, name = "", width = 1, default = None, \
                 is_wildcard = False ):
        """initialtize a StringField"""
        ## the name of the StringField
        self.name = name
        ## the width, in bits, of the StringField
        self.width = width
        ## the default value, if any, of the StringField
        self.default = default
        ## if this field is a wildcard field in a filter
        self.is_wildcard = is_wildcard
        ## Fields store the values
        if default == None:
            self.value = ""
        else:
            self.value = default
        
    def __repr__(self):
        """return a human readable form of a StringFeild object"""
        return "<pcs.StringField  name %s, %d bits, default %s, " \
               "wildcard %d>" % \
               (self.name, self.width, self.default, self.is_wildcard) # 

    def decode(self, bytes, curr, byteBR):
        """Decode the field and return the value as well as the new
        current position in the bytes array."""
        # byteBR == 8 is the neutral state
        if (byteBR != None and byteBR != 8):
            raise FieldAlignmentError, "Strings must start on a byte boundary"
        packarg = "%ds" % (self.width / 8)
        end = curr + self.width / 8
        value = struct.unpack(packarg, bytes[curr:end])[0]
        curr += self.width / 8
        self.value = value
        return [value, curr, byteBR]

    def encode(self, bytearray, value, byte, byteBR):
        """Encode a string field, make sure the bytes are aligned."""
        if (byteBR != None and byteBR != 8):
            raise FieldAlignmentError, "Strings must start on a byte boundary"
        packarg = "%ds" % (self.width / 8)
        bytearray.append(struct.pack(packarg, value))
        return [byte, byteBR]

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    def bounds(self, value):
        """Check the bounds of this field."""
        if (value == None) or (len (value) > (self.width / 8)):
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

    def __init__(self, name, length, value, is_wildcard=False):
        self.packet = None
        self.name = name
        self.is_wildcard = is_wildcard
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
               "wildcard %d" \
               % (self.name, self.length, self.value, self.is_wildcard)

    def __len__(self):
        return self.length.width + self.value.width
    
    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if self.packet != None:
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
        if self.packet != None:
            self.packet.__needencode = True

    #def get_value(self):
    #    return self.value.value

    def reset(self):
        """Return a resonable value to use in resetting a field of this type."""
        return ""

    def bounds(self, value):
        """Check the bounds of this field."""
        self.value.bounds(value)

class TypeValueField(object):
    """A type-value field handles parts of packets where a type
    is encoded before a value.  """

    def __init__(self, name, type, value, is_wildcard=False):
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

    def __repr__(self):
        return "<pcs.TypeValueField name %s, type %s, value %s, wildcard %d" % (self.name, self.type, self.value, self.is_wildcard)

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if self.packet != None:
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
        if ((value == None) or
            (len (value) > (((2 ** self.valuewidth) - 1) / 8))):
            raise FieldBoundsError, "Value must be between 0 and %d bytes long" % (((2 ** self.width) - 1) / 8)


class TypeLengthValueField(object):
    """A type-length-value field handles parts of packets where a type
    is encoded before a length and value.  """

    def __init__(self, name, type, length, value,
                 inclusive = True, bytewise = True):
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

    def __repr__(self):
        return "<pcs.TypeLengthValueField type %s, length %s, value %s>" \
                % (self.type, self.length, self.value)

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if self.packet != None:
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
        if ((value == None) or
            (len (value) > (((2 ** self.lengthwidth) - 1) / 8))):
            raise FieldBoundsError, "Value must be between 0 and %d bytes long" % (((2 ** self.width) - 1) / 8)

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

    def __init__(self, name, width = 0, option_list = [], is_wildcard = False):
        """Iniitialize an OptionListField."""
        list.__init__(self)
        self.name = name
        self.width = width
        self._options = []
        if option_list != []:
            for option in option_list:
                self._options.append(option)
        
        self.is_wildcard = is_wildcard
        self.default = self
        self.value = self
        
    def __len__(self):
        return len(self._options)
    
    def __iter__(self):
        self.index = 0
        return self

    def next(self):
        """Option lists return a pair of (value, option) when iterated"""
        if len(self._options) <= 0:
            raise StopIteration
        if self.index > len(self._options):
            raise StopIteration
        retval =  (self._options[self.index].value)
        self.index += 1
        return retval
    
    def __eq__(self, other):
        """Test two option lists for equality.
           Two option lists are equal if and only if they have the
           same options and values."""
        if (other == None):
            return False
        if len(self._options) != len(other._options):
            return False
        for i in range(len(self._options)):
            if self._options[i].value != other._options[i].value:
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
            if not hasattr(field, 'default') or field.default == None:
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
    """A Packet is a base class for building real packets."""

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
        for field in self._layout:
            if curr > len(bytes):
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

    def __init__(self, layout = None, bytes = None):
        """initialize a Packet object

        layout - the layout of the packet, a list of Field objects
        bytes - if the packet is being set up now the bytes to set in it
        """
        self._layout = layout
        self._fieldnames = {}
        self._head = None
        for field in layout:
            self._fieldnames[field.name] = field
        self._needencode = True
        if bytes != None:
            self.decode(bytes)

        self._discriminator = None
        # The layout of the Packet, a list of Field objects.
        for field in layout:
            field.packet = self
            if (not hasattr(field, 'discriminator')):
                continue
            if ((field.discriminator == True) and
                (self._discriminator != None)):
                raise LayoutDiscriminatorError, "Layout can only have one field marked as a discriminator, but there are at least two %s %s" % (field, self._discriminator)
            if (field.discriminator == True):
                self._discriminator = field
                
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

        if (hasattr(self, '_fieldnames') and (name in self._fieldnames)):
            self._fieldnames[name].bounds(value)
            self._fieldnames[name].set_value(value)
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
        """Return True if the packets match. A wildcard match is performed.

           This packet is assumed to contain fields which have the
           'is_wildcard' flag set, and they will be ignored for the
           comparison. Byte-wise comparison is NOT performed. """
        if (type(self) != type(other)):
            return False
        # TODO: Push logic into per-field match for richer filters.
        for field in self._layout:
            wild = self._fieldnames[field.name].is_wildcard
            if not wild:
                if self._fieldnames[field.name].value != \
                   other._fieldnames[field.name].value:
                    return False
        return True

    def wildcard_mask(self, fieldnames=[], is_wildcard=True):
        """Mark or unmark a list of fields in this Packet as
           wildcard for match().
           If an empty list is passed, apply is_wildcard to all fields."""
        if fieldnames != []:
            for i in fieldnames:
                field = self._fieldnames[i]
                field.is_wildcard = is_wildcard
        else:
            for f in self._fieldnames.iteritems():
                f[1].is_wildcard = is_wildcard

    def __repr__(self):
        """Walk the entire packet and return the values of the fields."""
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
        retval = ""
        if hasattr(self, 'description'):
            retval += "%s\n" % self.description
        for field in self._layout:
            retval += "%s %s\n" % (field.name,
                                   self._fieldnames[field.name].value)
        return retval

    def __len__(self):
        """Return the count of the number of bytes in the packet."""
        return len(self.bytes)

    def __div__(self, packet):
        """/ operator: Insert a packet after this packet in a chain.
           If I am not already part of a chain, build one.
           The default behaviour is to attempt to initialize any
           discriminator fields based on the type of the packet
           being appended.
           The head of the chain is always returned."""
        if not isinstance(packet, Packet):
            raise exceptions.TypeError
        if self._head is None:
            head = self.chain()
            self.rdiscriminate(packet)
            head.append(packet)
            self._head = head
        else:
            head = self._head
            if not isinstance(head, Chain):
                raise exceptions.TypeError
            if head.insert_after(self, packet) == False:
                raise exceptions.IndexError
        return head

    def chain(self):
        """Return the packet and its next packets as a chain."""
        packet_list = []
        done = False
        packet = self
        while not done:
            packet_list.append(packet)
            if (packet.data != None):
                packet = packet.data
            else:
                done = True
        return Chain(packet_list)
        
    def next(self, bytes, discriminator = None, timestamp = None):
        """Demultiplex higher layer protocols based on a supplied map and
        discriminator field."""

        # If the caller passes their own discriminator then we use the
        # caller's otherwise we use the one built into the packet.
        # The use of a caller supplied discriminator allows use to
        # more easily unpack packets that are chunked, where the
        # current packet does not contain knowledge about what comes
        # next.

        if ((discriminator != None) and (self._map != None)):
            if (discriminator in self._map):
                return self._map[self._fieldnames[discriminator.name].value](bytes, timestamp = timestamp)
            
        if ((self._discriminator != None) and (self._map != None)):
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
           Return True if we made any changes to self."""

        if (not isinstance(packet, Packet)):
            raise exceptions.TypeError

        # If we were not passed discriminator field name and map, try
        # to infer it from what's inside the instance.
        if map == None:
           map = self._map
           if map == None:
               return False
        if discfieldname == None:
           if self._discriminator == None:
                return False
           discfieldname = self._discriminator.name

        for i in map.iteritems():
            if isinstance(packet, i[1]):
                self._fieldnames[discfieldname].value = i[0]
                return True

        return False

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

class Chain(list):
    """A chain is simply a list of packets.  Chains are used to
    aggregate related sub packets into one chunk for transmission."""

    def __init__(self, packets = None):
        """initialize a Chain object

        packets - an optionl array of packets to add to the new Chain
        """
        list.__init__(self)
        self.packets = packets
        self.encode()

    def __eq__(self, other):
        """test two Chain objects for equality

        Two chains are equal iff they have the same packets and their
        packets have the same data in them."""
        if len(self.packets) != len(other.packets):
            return False
        for i in range(len(self.packets)):
            if self.packets[i] != other.packets[i]:
                return False
        return True
            
    def __ne__(self, other):
        """test two Chain objects for inequality"""
        return not self.__eq__(other)
            
    def __str__(self):
        """return a pretty printed Chain"""
        retval = ""
        for packet in self.packets:
            retval += "%s " % packet.__str__()
        return retval

    def __div__(self, packet, rdiscriminate=True):
        """/ operator: Append a packet to the end of a chain.
           The default behaviour is to fill out the discriminator field
           of the packet in front of the new tail packet."""
        if not isinstance(packet, Packet):
            raise exceptions.TypeError
        if rdiscriminate is True:
            self.packets[-1].rdiscriminate(packet)
        self.append(packet)
        return self

    def append(self, packet):
        """Append a packet to a chain.  Appending a packet requires
        that we update the bytes as well."""
        self.packets.append(packet)
        self.encode()

    def insert_after(self, p1, p2, rdiscriminate=True):
        """Insert a packet into a chain after a given packet instance.
           Used only by the div operator. The default behaviour is to
           set discriminator fields in p1 based on p2."""
        for i in range(len(self.packets)):
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
        result = None
        for i in range(len(self.packets)):
            if isinstance(self.packets[i], type(packet)):
                if packet.matches(self.packets[i]):
                    result = i
                    break
        return result

    def matches(self, chain):
        """Return True if this chain matches the chain provided.

           It is assumed that this chain contains any wildcard patterns.
           A bitwise comparison is not performed; a structural match
           using the match() function is used instead."""
        if len(self.packets) != len(chain.packets):
            return False
        for i in range(len(self.packets)):
            if not self.packets[i].matches(chain.packets[i]):
                return False
        return True

    def wildcard_mask(self, is_wildcard=True):
        """Mark or unmark all of the fields in each Packet in this Chain
           as a wildcard for match() or contains()."""
        for i in range(len(self.packets)):
            self.packets[i].wildcard_mask([], is_wildcard)

    def encode(self):
        """Encode all the packets in a chain into a set of bytes for the Chain"""
        self.bytes = ""
        for packet in self.packets:
            self.bytes += packet.bytes
    
    def decode(self, bytes):
        """Decode all the bytes of all the packets in a Chain into the underlying packets"""
        for packet in self.packets:
            packet.decode(packet.bytes)

    def calc_checksum(self):
        """Calculate a checksum for the whole chain based on RFC 792

        In this calculation any packet that specifically calls out a
        checksum field will have that field zeroed first before the
        checksum is calculated.
        """
        total = 0
        bytes = ""
        for packet in self.packets:
            if (hasattr(packet, 'checksum')):
                packet.checksum = 0
            bytes = bytes + packet.bytes
        if len(bytes) % 2 == 1:
            bytes += "\0"
        for i in range(len(bytes)/2):
            total += (struct.unpack("!H", bytes[2*i:2*i+2])[0])
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ~total & 0xffff

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
        self.match = None
        self.match_index = None
        raise ConnNotImpError, "Cannot use base class"

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

           On return, the match property will contain the matching
           packet chain.

           The syntax is intentionally similar to that of pexpect.
            Both timeouts and limits may be specified as patterns.
            If a pattern contains a Packet, it is matched against
            the chain using the Chain.contains() method.
            If a pattern contains a Chain, it is matched against
            the chain using the Chain.match() method.

           If a timeout is specified, raise an exception after the
           timeout expires. This is only supported if the underlying
           Connector implements non-blocking I/O.

           If a limit is specified, raise an exception after 'limit'
           packets have been read, regardless of match.
           If neither a timeout or a limit is specified, or an EOF
           was not encountered, this function may potentially block forever.

           TODO: Buffer for things like TCP reassembly.
           TODO: Make this drift and jitter robust (CLOCK_MONOTONIC).
           TODO: Accept a wider pattern language. """
        from time import time
        start = time()
        then = start
        count = 0
        delta = timeout
        while True:
            result = self.poll_read(delta)

            # Compute the wait quantum for the next read attempt.
            if timeout != None:
                now = time()
                delta = now - then
                then = now

            c = self.read_chain()    # XXX Should check for EOF.
            count += 1

            # Check if the user tried to match exceptional conditions
            # as patterns. We need to check for timer expiry upfront.
            if timeout != None and (now - start) > timeout:
                for i in range(len(patterns)):
                    if isinstance(patterns[i], TIMEOUT):
                        self.match = p
                        return i
                raise TimeoutError

            if isinstance(result, TIMEOUT):
                if delta > 0:
                    continue   # Early wakeup.

            elif isinstance(result, EOF):
                for i in range(len(patterns)):
                    if isinstance(patterns[i], EOF):
                        self.match = p
                        self.match_index = i
                        return i
                raise EOFError
            elif limit != None and count == limit:
                for i in range(len(patterns)):
                    if isinstance(patterns[i], LIMIT):
                        self.match = p
                        self.match_index = i
                        return i
                raise LimitReachedError

            # Otherwise, look for a chain or packet match. The index of
            # the first match is returned.
            for i in range(len(patterns)):
                p = patterns[i]
                if isinstance(p, Chain):
                    if p.matches(c):
                        self.match = c
                        self.match_index = i
                        return i
                if isinstance(p, Packet):
                    if c.contains(p):
                        self.match = c
                        self.match_index = i
                        return i

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

    def __init__(self, name = None):
        """initialize a PcapConnector object

        name - the name of a file or network interface to open
        """
        try:
            self.file = pcap.pcap(name)
        except:
            raise

        # Grab the underlying pcap objects members for convenienc
        self.dloff = self.file.dloff
        self.setfilter = self.file.setfilter
        self.dlink = self.file.datalink()
        
    def read(self):
        """read a packet from a pcap file or interface

        returns the packet as a bytearray
        """
        return self.file.next()[1]

    def recv(self):
        """recv a packet from a pcap file or interface"""
        return self.file.next()[1]
    
    def recvfrom(self):
        """recvfrom a packet from a pcap file or interface"""
        return self.file.next()[1]

    def poll_read(self, timeout=None):
        """Poll the underlying I/O layer for a read.
           Return TIMEOUT if the timeout was reached."""
        from select import select
        fd = self.file.fileno()
        self.file.setnonblock()
        result = select([fd],[],[], timeout)
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
        """create a packet from a set of bytes

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
        else:
            raise UnpackError, "Could not interpret packet"
                
    def close(self):
        """Close the pcap file or interface."""
        self.file.close()

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
        return self.file.dump(packet)

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
        try:
            self.fileno = os.open(name, O_RDWR + O_NONBLOCK)
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

    def readpkt(self):
        """read a packet from a pcap file or interfaces returning an
        appropriate packet object """
        bytes = self.blocking_read()
        return packets.ethernet.ethernet(bytes)

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

    def blocking_read(self):
        import array
        import fcntl
        import os
        from select import select
        from termios import FIONREAD
        try:
            # Block until data is ready to be read.
            select([self.fileno],[],[])
            # Ask the kernel how many bytes are in the queued Ethernet frame.
            buf = array.array('i', [0])
            s = fcntl.ioctl(self.fileno, FIONREAD, buf)
            qbytes = buf.pop()
            return os.read(self.fileno, qbytes)
        except:
            raise
        return -1

    def blocking_write(self, bytes):
        import os
        return os.write(self.fileno, bytes)

    def close(self):
        import os
        os.close(self.fileno)


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
        try:
            self.fileno = os.open(name, O_RDWR + O_NONBLOCK)
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

    def poll_read(self, timeout=None):
        """Needed to work with expect"""
        from select import select
        fd = self.fileno
        result = select([fd],[],[], timeout)
        if not fd in result[0]:
            return TIMEOUT()
        return None

    def blocking_read(self):
        import array
        import fcntl
        import os
        from termios import FIONREAD
        try:
            # Block until data is ready to be read.
            poll_read(None)
            # Ask the kernel how many bytes are in the queued Ethernet frame.
            buf = array.array('i', [0])
            s = fcntl.ioctl(self.fileno, FIONREAD, buf)
            qbytes = buf.pop()
            return os.read(self.fileno, qbytes)
        except:
            raise
        return -1

    def blocking_write(self, bytes):
        import os
        return os.write(self.fileno, bytes)

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

        if (address != None and port != None):
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

        if (addr != None and port != None):
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

    def readpkt(self):
        """read a packet from a pcap file or interfaces returning an
        appropriate packet object """
        bytes = self.blocking_read()
        return packets.ethernet.ethernet(bytes)

    def blocking_read(self):
        import os
        from select import select
	#print "going to sleep"
        select([self.file],[],[])
	#print "woken up"
	# XXX Should use recvfrom.
	# XXX Shouldn't have to guess buffer size.
        return os.read(self.file.fileno(), 1502)

    def write(self, packet, flags = 0):
        """write data to an IPv4 socket"""
        return self.file.sendto(packet, flags, (self.group, self.port))


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

        if (addr != None and port != None):
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
            self.file = socket(AF_INET6, SOCK_RAW, IPPROTO_IP)
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

        if (address != None and port != None):
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

        if (address != None and port != None):
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

        if (address != None and port != None):
            try:
                self.file.connect([address, port])
            except:
                raise

###
### Convenience functions and adjuncts to certain probelmatic bits of Python
### network code.
###

def inet_atol(string):
    """convert an ascii IPv4 address into a Long"""
    from socket import inet_aton
    value = 0
    addr = inet_aton(string)
    for i in range(4):
        value += ord(addr[i]) << (3 - i) * 8
    return value

