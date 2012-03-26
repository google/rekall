# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

""" This file defines some basic types which might be useful for many
OS's
"""
import copy
import logging
import socket
import struct

from volatility import obj
from volatility import constants
from volatility.plugins.overlays import native_types


class String(obj.StringProxyMixIn, obj.NativeType):
    """Class for dealing with Null terminated C Strings.

    Note that these strings are _not_ text strings - they are effectively bytes
    arrays and therefore are not encoded in any particular unicode encoding.
    """
    def __init__(self, length = 1, **kwargs):
        super(String, self).__init__(**kwargs)

        ## Allow length to be a callable:
        if callable(length):
            length = length(self.obj_parent)

        self.length = length

        ## length must be an integer
        self.format_string = "{0}s".format(int(length))

    def proxied(self, name):
        """ Return an object to be proxied """
        return self.__str__()

    def __str__(self):
        ## Make sure its null terminated:
        return self.v().split("\x00")[0]

    def __unicode__(self):
        return self.v().decode("utf8", "replace").split("\x00")[0]

    def __format__(self, formatspec):
        return format(unicode(self), formatspec)

    def __add__(self, other):
        """Set up mappings for concat"""
        return str(self) + other

    def __radd__(self, other):
        """Set up mappings for reverse concat"""
        return other + str(self)


class UnicodeString(String):
    """A class for dealing with encoded text strings.

    Text strings are always encoded in some way in memory. The specific way of
    encoding them is called the "encoding" - for example usually (but not
    always) in windows the encoding is called "utf16", while on linux its
    usually "utf8".

    By default we take the encoding from the profile constant
    "default_text_encoding".
    """
    def __init__(self, encoding=None, **kwargs):
        super(UnicodeString, self).__init__(**kwargs)
        if encoding is None:
            self.encoding = self.obj_profile.get_constant('default_text_encoding')

    def v(self, vm=None):
        """Note this returns a unicode object."""
        # Null terminate the string
        data = super(UnicodeString, self).v().decode(self.encoding, "ignore")
        return data.split("\x00")[0]

    def __str__(self):
        """This function returns an encoded string in utf8."""
        return self.v().encode("utf8")


class Flags(obj.NativeType):
    """ This object decodes each flag into a string """
    ## This dictionary maps each bit to a String
    bitmap = None

    ## This dictionary maps a string mask name to a bit range
    ## consisting of a list of start, width bits
    maskmap = None

    def __init__(self, theType = None, offset = 0, vm = None, parent = None,
                 bitmap = None, maskmap = None, target = "unsigned long",
                 **kwargs):
        self.bitmap = bitmap or {}
        self.maskmap = maskmap or {}
        self.target = target

        self.target_obj = obj.Object(target, offset = offset, vm = vm, parent = parent)
        obj.NativeType.__init__(self, theType, offset, vm, parent, **kwargs)

    def v(self, vm=None):
        return self.target_obj.v(vm=vm)

    def __str__(self):
        result = []
        value = self.v()
        keys = self.bitmap.keys()
        keys.sort()
        for k in keys:
            if value & (1 << self.bitmap[k]):
                result.append(k)

        return ', '.join(result)

    def __format__(self, formatspec):
        return format(self.__str__(), formatspec)

    def __getattr__(self, attr):
        maprange = self.maskmap.get(attr)
        if not maprange:
            return obj.NoneObject("Mask {0} not known".format(attr))

        bits = 2 ** maprange[1] - 1
        mask = bits << maprange[0]

        return self.v() & mask


class Enumeration(obj.NativeType):
    """Enumeration class for handling multiple possible meanings for a single value"""

    def __init__(self, choices = None, target = "unsigned long", **kwargs):
        super(Enumeration, self).__init__(**kwargs)
        self.choices = choices or {}
        self.target = target
        self.target_obj = self.obj_profile.Object(
            target, offset=self.offset, vm=self.obj_vm)

    def v(self, vm=None):
        return self.target_obj.v(vm=vm)

    def __str__(self):
        value = self.v()
        if value in self.choices.keys():
            return self.choices[value]
        return 'Unknown choice ' + str(value)

    def __format__(self, formatspec):
        return format(self.__str__(), formatspec)

class IpAddress(obj.NativeType):
    """Provides proper output for IpAddress objects"""

    def __init__(self, **kwargs):
        super(IpAddress, self).__init__(**kwargs)

        # IpAddress is always a 32 bit int.
        self.format_string = "<I"

    def v(self, vm=None):
        value = super(IpAddress, self).v(vm=vm)
        return socket.inet_ntoa(struct.pack("<I", value))


# TODO: Remove this hack.
class VOLATILITY_MAGIC(obj.CType):
    """Class representing a VOLATILITY_MAGIC namespace

       Needed to ensure that the address space is not verified as valid for constants
    """
    def __init__(self, theType, offset, vm, **kwargs):
        try:
            obj.CType.__init__(self, theType, offset, vm, **kwargs)
        except obj.InvalidOffsetError:
            # The exception will be raised before this point,
            # so we must finish off the CType's __init__ ourselves
            self.__initialized = True




# We define two kinds of basic profiles, a 32 bit one and a 64 bit one
class Profile32Bits(obj.Profile):
    """Basic profile for 32 bit systems."""
    _md_memory_model = '32bit'

    def __init__(self, **kwargs):
        super(Profile32Bits, self).__init__(**kwargs)
        self.add_types(native_types.x86_native_types)
        self.add_constants(PoolAlignment=8, MAX_FAST_REF=7)


class Profile64Bits(obj.Profile):
    """Basic profile for 64 bit systems."""
    _md_memory_model = '64bit'

    def __init__(self, **kwargs):
        super(Profile64Bits, self).__init__(**kwargs)
        self.add_types(native_types.x64_native_types)
        self.add_constants(PoolAlignment=16, MAX_FAST_REF=15)


class BasicWindowsClasses(obj.Profile):
    """Basic profile which introduces the basic classes."""

    def __init__(self, **kwargs):
        super(BasicWindowsClasses, self).__init__(**kwargs)
        self.add_classes({
            'String': String,
            'UnicodeString': UnicodeString,
            'Flags': Flags,
            'Enumeration': Enumeration,
            'IpAddress': IpAddress,
            })

        self.add_constants(default_text_encoding="utf16")
