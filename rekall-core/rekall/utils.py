# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Michael Hale Ligh <michael.hale@gmail.com>
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

"""These are various utilities for rekall."""
import __builtin__
import cPickle
import cStringIO
import importlib
import itertools
import json
import ntpath
import re
import shutil
import socket

import sys
import tempfile
import threading
import traceback
import time
import weakref

import sortedcontainers

from rekall import registry


def SmartStr(string, encoding="utf8"):
    """Forces the string to be an encoded byte string."""
    if type(string) == unicode:
        return string.encode("utf8", "ignore")

    try:
        return string.__unicode__().encode(encoding)
    except AttributeError:
        return str(string)


def SmartUnicode(string, encoding="utf8"):
    """Forces the string into a unicode object."""
    try:
        # Allow the object to have a __unicode__ method.
        return unicode(string)
    except UnicodeError:
        return str(string).decode(encoding, "ignore")


def Hexdump(data, width=16):
    """Hexdump function shared by various plugins """
    for offset in xrange(0, len(data), width):
        row_data = data[offset:offset + width]
        translated_data = [
            x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
        hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

        yield offset, hexdata, translated_data


def WriteHexdump(renderer, data, base=0, width=16):
    """Write the hexdump to the fd."""
    renderer.table_header([dict(name="offset", style="address"),
                           dict(name="hex", width=width * 3),
                           dict(name='data', width=width)])

    for offset, hexdata, translated_data in Hexdump(data):
        renderer.table_row(base + offset, hexdata, "".join(translated_data))


# This is a synchronize decorator.
def Synchronized(f):
    """Synchronization decorator."""

    def NewFunction(self, *args, **kw):
        if self.lock:
            with self.lock:
                return f(self, *args, **kw)
        else:
            return f(self, *args, **kw)

    return NewFunction


class Node(object):
    """An entry to a linked list."""
    next = None
    prev = None
    data = None

    def __init__(self, data):
        self.data = data

    def __str__(self):
        return "Node:" + SmartStr(self.data)


class LinkedList(object):
    """A simple doubly linked list used for fast caches."""

    def __init__(self):
        # We are the head node.
        self.next = self.prev = self
        self.size = 0
        self.lock = threading.RLock()

    def Append(self, data):
        return self.AppendNode(Node(data))

    def AppendNode(self, node):
        self.size += 1
        last_node = self.prev

        last_node.next = node
        node.prev = last_node
        node.next = self
        self.prev = node

        return node

    def PopLeft(self):
        """Returns the head node and removes it from the list."""
        if self.next is self:
            raise IndexError("Pop from empty list.")

        first_node = self.next
        self.Unlink(first_node)

        return first_node.data

    def Pop(self):
        """Returns the tail node and removes it from the list."""
        if self.prev is self:
            raise IndexError("Pop from empty list.")

        last_node = self.tail
        self.Unlink(last_node)

        return last_node.data

    def Unlink(self, node):
        """Removes a given node from the list."""
        self.size -= 1

        node.prev.next = node.next
        node.next.prev = node.prev
        node.next = node.prev = None

    def __iter__(self):
        p = self.next
        while p is not self:
            yield p.data
            p = p.next

    def __len__(self):
        return self.size

    def __str__(self):
        p = self.next
        s = []
        while p is not self:
            s.append(str(p.data))
            p = p.next

        return "[" + ", ".join(s) + "]"


class FastStore(object):
    """This is a cache which expires objects in oldest first manner.

    This implementation first appeared in PyFlag and refined in GRR.

    This class implements an LRU cache which needs fast updates of the LRU order
    for random elements. This is implemented by using a dict for fast lookups
    and a linked list for quick deletions / insertions.
    """

    STORES = {}

    def __init__(self, max_size=10, kill_cb=None, lock=False):
        """Constructor.

        Args:
             max_size: The maximum number of objects held in cache.
             kill_cb: An optional function which will be called on each
                                object terminated from cache.
             lock: If True this cache will be thread safe.
        """
        self._age = LinkedList()
        self._hash = {}
        self._limit = max_size
        self._kill_cb = kill_cb
        self.lock = None
        if lock:
            self.lock = threading.RLock()
        self.hits = self.misses = 0
        self.creator = GetStack()
        self.STORES[id(self)] = weakref.proxy(
            self, lambda _, id=id(self), s=self.STORES: s.pop(id))

    def __len__(self):
        return len(self._hash)

    @Synchronized
    def Expire(self):
        """Expires old cache entries."""
        while len(self._age) > self._limit:
            x = self._age.PopLeft()
            self.ExpireObject(x)

    @Synchronized
    def Put(self, key, item):
        """Add the object to the cache."""
        hit = self._hash.get(key, self)
        if hit is not self:
            self._age.Unlink(hit[0])

        node = self._age.Append(key)
        self._hash[key] = (node, item)

        self.Expire()

        return key

    @Synchronized
    def ExpireObject(self, key):
        """Expire a specific object from cache."""
        _, item = self._hash.pop(key, (None, None))

        if self._kill_cb and item is not None:
            self._kill_cb(item)

        return item

    @Synchronized
    def ExpireRegEx(self, regex):
        """Expire all the objects with the key matching the regex."""
        reg = re.compile(regex)
        for key in self._hash.keys():
            if reg.match(key):
                self.ExpireObject(key)

    @Synchronized
    def ExpirePrefix(self, prefix):
        """Expire all the objects with the key having a given prefix."""
        for key in self._hash.keys():
            if key.startswith(prefix):
                self.ExpireObject(key)

    @Synchronized
    def Get(self, key):
        """Fetch the object from cache.

        Objects may be flushed from cache at any time. Callers must always
        handle the possibility of KeyError raised here.

        Args:
            key: The key used to access the object.

        Returns:
            Cached object.

        Raises:
            KeyError: If the object is not present in the cache.
        """
        hit = self._hash.get(key, self)
        if hit is self:
            self.misses += 1
            raise KeyError(key)

        # Remove the item and put to the end of the age list
        node, item = hit
        self._age.Unlink(node)
        self._age.AppendNode(node)
        self.hits += 1

        return item

    def __iter__(self):
        return self._hash.iteritems()

    def keys(self):
        return self._hash.keys()

    @Synchronized
    def __contains__(self, key):
        result = key in self._hash
        if result:
            node, _ = self._hash[key]
            self._age.Unlink(node)
            self._age.AppendNode(node)

        return result

    @Synchronized
    def __getitem__(self, key):
        return self.Get(key)

    @Synchronized
    def Flush(self):
        """Flush all items from cache."""
        while self._age:
            x = self._age.PopLeft()
            self.ExpireObject(x)

        self._hash = {}

    @Synchronized
    def __getstate__(self):
        """When pickled the cache is fushed."""
        if self._kill_cb:
            raise RuntimeError("Unable to pickle a store with a kill callback.")

        self.Flush()
        return dict(max_size=self._limit)

    def __setstate__(self, state):
        self.__init__(max_size=state["max_size"])


class AgeBasedCache(FastStore):
    """A cache which removes objects after some time."""

    def __init__(self, max_age=20, **kwargs):
        super(AgeBasedCache, self).__init__(**kwargs)
        self.max_age = max_age

    def Put(self, key, item):
        super(AgeBasedCache, self).Put(key, (item, time.time()))

    def Get(self, key):
        item, timestamp = super(AgeBasedCache, self).Get(key)

        if timestamp + self.max_age > time.time():
            return item

        else:
            self.ExpireObject(key)
            raise KeyError("Item too old.")


# Compensate for Windows python not supporting socket.inet_ntop and some
# Linux systems (i.e. OpenSuSE 11.2 w/ Python 2.6) not supporting IPv6.

def inet_ntop(address_family, packed_ip):

    def inet_ntop4(packed_ip):
        if not isinstance(packed_ip, str):
            raise TypeError("must be string, not {0}".format(type(packed_ip)))

        if len(packed_ip) != 4:
            raise ValueError("invalid length of packed IP address string")

        return "{0}.{1}.{2}.{3}".format(*[ord(x) for x in packed_ip])

    def inet_ntop6(packed_ip):
        if not isinstance(packed_ip, str):
            raise TypeError("must be string, not {0}".format(type(packed_ip)))

        if len(packed_ip) != 16:
            raise ValueError("invalid length of packed IP address string")

        words = []
        for i in range(0, 16, 2):
            words.append((ord(packed_ip[i]) << 8) | ord(packed_ip[i + 1]))

        # Replace a run of 0x00s with None
        numlen = [(k, len(list(g))) for k, g in itertools.groupby(words)]
        max_zero_run = sorted(sorted(
            numlen, key=lambda x: x[1], reverse=True),
                              key=lambda x: x[0])[0]
        words = []
        for k, l in numlen:
            if (k == 0) and (l == max_zero_run[1]) and not None in words:
                words.append(None)
            else:
                for i in range(l):
                    words.append(k)

        # Handle encapsulated IPv4 addresses
        encapsulated = ""
        if (words[0] is None) and (len(words) == 3 or (
                len(words) == 4 and words[1] == 0xffff)):
            words = words[:-2]
            encapsulated = inet_ntop4(packed_ip[-4:])
        # If we start or end with None, then add an additional :
        if words[0] is None:
            words = [None] + words
        if words[-1] is None:
            words += [None]
        # Join up everything we've got using :s
        return (":".join(
            ["{0:x}".format(w) if w is not None else "" for w in words]) +
                encapsulated)

    if address_family == socket.AF_INET:
        return inet_ntop4(packed_ip)
    elif address_family == socket.AF_INET6:
        return inet_ntop6(packed_ip)
    raise socket.error("[Errno 97] Address family not supported by protocol")


def ConditionalImport(name):
    try:
        return importlib.import_module(name)
    except ImportError:
        pass


# This is only available on unix systems.
fcntl = ConditionalImport("fcntl")


class FileLock(object):
    """A self releasing file lock."""

    def __init__(self, fd):
        self.fd = fd

    def __enter__(self):
        if fcntl:
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_EX)
        return self.fd

    def __exit__(self, exc_type, exc_value, traceback):
        if fcntl:
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)


class TempDirectory(object):
    """A self cleaning temporary directory."""

    def __enter__(self):
        self.name = tempfile.mkdtemp()

        return self.name

    def __exit__(self, exc_type, exc_value, traceback):
        shutil.rmtree(self.name, True)


class AttributedString(object):
    """This is just a container for a string and some metadata."""
    highlights = None

    __metaclass__ = registry.UniqueObjectIdMetaclass

    def __init__(self, value, highlights=None, **options):
        self.highlights = highlights
        self.value = value
        self.options = options

    def __unicode__(self):
        return unicode(self.value)

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return "%s(%s, highlights=%s)" % (self.__class__.__name__,
                                          repr(self.value),
                                          repr(self.highlights))


class HexDumpedString(AttributedString):
    """A string which should be hex dumped."""


class HexInteger(long):
    """An int which should be rendered as a hex digit."""

    def __hex__(self):
        return super(HexInteger, self).__hex__().rstrip("L")


class FormattedAddress(object):
    """A container for an address that should be formatted.

    Addresses are usually formatted with the address resolver, but this can be
    expensive as the address resolver needs to work out what modules exist in
    the address space and build profiles for them. Although this is necessary
    for actually formatting the address, sometimes plugins want to return a
    formatted address, but this might be filtered away - in which case the
    formatting effort is wasted.

    This container object encapsulates the resolver and the address and then
    uses an ObjectRenderer to do the actual formatting at rendering time. If the
    address is discarded, no formatting is done and we save some cycles.
    """

    def __init__(self, resolver, address, max_distance=1e6, max_count=100,
                 hex_if_unknown=True):
        self.resolver = resolver
        self.address = address
        self.max_distance = max_distance
        self.max_count = max_count
        self.hex_if_unknown = hex_if_unknown

    def __str__(self):
        names = self.resolver.format_address(
            self.address, max_distance=self.max_distance)[:self.max_count]
        if names:
            return ", ".join(names)

        elif self.hex_if_unknown:
            return "%#x" % self.address

        else:
            return ""


class SlottedObject(object):
    """A general purpose PODO."""

    # Declare this object's fields here.
    __slots__ = ()

    def __init__(self):
        for k in self.__slots__:
            setattr(self, k, None)

    def keys(self):
        return [x for x in dir(self) if not x.startswith("_")]


class AttributeDict(dict):
    """A dict that can be accessed via attributes.

    This object is very slow due to use of __setstate__. Please consider using
    SlottedObject instead.
    """
    dirty = False

    _object_id = None
    __metaclass__ = registry.UniqueObjectIdMetaclass

    def __setattr__(self, attr, value):
        try:
            # Check that the object itself has this attribute.
            object.__getattribute__(self, attr)

            return object.__setattr__(self, attr, value)
        except AttributeError:
            self.Set(attr, value)

    def Get(self, item, default=None):
        return self.get(item, default)

    def Set(self, attr, value):
        self.dirty = True

        # Setting a key to None means to remove it from the cache. NOTE! This
        # must be exactly None not a NoneObject() since it should be possible to
        # cache a NoneObject() as the value of some key.
        if value is None:
            self.pop(attr, None)
        else:
            self[attr] = value

    def __getattr__(self, attr):
        # Do not allow private attributes to be set.
        if attr.startswith("_"):
            raise AttributeError(attr)

        return self.get(attr)

    def __dir__(self):
        return sorted(self)


def FormatIPAddress(family, value):
    """Formats a value as an ascii IP address determined by family."""
    if value == None:
        return value

    return socket.inet_ntop(
        getattr(socket, str(family)),
        value.obj_vm.read(value.obj_offset, value.obj_size))


def ntoh(value):
    size = value.obj_size
    if size == 2:
        return socket.ntohs(value.v())
    elif size == 4:
        return socket.ntohl(value.v())

    from rekall import obj
    return obj.NoneObject("Not a valid integer")


def Invert(dictionary):
    """Inverts keys and values in dictionary.

    Assume the keys and values are unique.
    """
    return {v:k for k, v in dictionary.items()}


def PPrint(data, depth=0):
    """A pretty printer for a profile.

    This only supports dict, list and non-unicode strings.

    This produces both a valid json and a valid python file.
    """
    result = []
    if type(data) is bool:
        return str(data).lower()

    if isinstance(data, dict):
        # Empty dicts emitted on one line.
        if not data:
            return "{}"

        result.append("{")
        tmp = []
        for key, value in sorted(data.items()):
            # Only emit non-empty dicts.
            if value != {}:
                tmp.append(
                    " %s%s: %s" % (
                        " " * depth,
                        json.dumps(str(key)),
                        PPrint(data[key], depth + 1).strip()))

        result.append(", \n".join(tmp)[depth:])

        result.append("}")
        return "\n".join([(" " * depth + x) for x in result])

    if isinstance(data, (list, tuple)):
        for item in data:
            pp_item = PPrint(item, depth)

            result.append(pp_item.strip())

        res = "[" + ", ".join(result) + "]"

        return res

    if isinstance(data, basestring):
        return json.dumps(SmartUnicode(data))

    # JSON encodes None as null.
    elif data is None:
        return "null"

    return SmartStr(data)


DEFINE_REGEX = re.compile(r"#define\s+([A-Z0-9_]+)\s+((0x)?[0-9A-Z]+)")

def MaskMapFromDefines(text):
    """Generates a maskmap dict from a list of #defines.

    This function allows us to copy the relevant #define sections from header
    files without needing to manually edit them. We get to keep the comments etc
    for readability.
    """
    result = {}
    for line in text.splitlines():
        m = DEFINE_REGEX.search(line)
        if m:
            name = m.group(1)
            value = m.group(2)
            if m.group(3):
                value = int(value, 16)
            elif value.startswith("0"):
                value = int(value, 8)
            else:
                value = int(value)

            result[name] = value

    return result


def EnumerationFromDefines(text):
    """Generate an Enumeration from a list of #defines."""
    result = {}
    for line in text.splitlines():
        m = DEFINE_REGEX.search(line)
        if m:
            name = m.group(1)
            value = m.group(2)
            if m.group(3):
                value = int(value, 16)
            else:
                value = int(value)

            result[value] = name

    return result


class SortedCollection(sortedcontainers.SortedDict):
    def __init__(self, *args, **kwargs):
        self.key_func = kwargs.pop("key", lambda x: x[0])
        super(SortedCollection, self).__init__(*args, **kwargs)

    def insert(self, item):
        key = self.key_func(item)
        self[key] = item

    def __iter__(self):
        return self.itervalues()

    def get_value_smaller_than(self, k):
        for x in self.irange(0, k, reverse=True):
            return x, self[x]

        return None, None

    def get_value_larger_than(self, k):
        for x in self.irange(k):
            return x, self[x]

        return None, None

    def find_le(self, k):
        for x in self.irange(0, k, reverse=True):
            return self[x]

        raise ValueError('No item found with key below: %r' % (k,))

    def find_ge(self, k):
        for x in self.irange(k):
            return self[x]

        raise ValueError('No item found with key at or above: %r' % (k,))



class RangedCollection(object):
    """A convenience wrapper around SortedCollection for ranges."""

    def __init__(self):
        self.collection = SortedCollection()

    def insert(self, start, end, data):
        start = int(start)
        end = int(end)
        self.collection[(start, end)] = data

    def get_next_range_start(self, address):
        """Gets the start address of the next range larger than address."""
        range, _ = self.collection.get_value_larger_than((address, None))
        if range is not None:
            return range[0]

    def get_containing_range(self, address):
        """Retrieve the data associated with the range that contains value.

        Retuns:
          A tuple of start, end, data for the range that contains address.
        """
        tmp, data = self.collection.get_value_smaller_than((address + 1, None))
        if tmp is not None:
            start, end = tmp
            if start <= address < end:
                return start, end, data

        return None, None, None

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.collection == other.collection

        return NotImplemented

    def clear(self):
        self.collection.clear()

    def __getitem__(self, item):
        key = self.collection.iloc[item]
        return key[0], key[1], self.collection[key]

    def __iter__(self):
        for (start, end), data in self.collection.iteritems():
            yield start, end, data

    def __reversed__(self):
        for key in reversed(self.collection):
            start, end = key
            yield start, end, self.collection[key]

    def __str__(self):
        result = []
        for start, end, data in self:
            result.append("<%#x, %#x> %s" % (start, end, data))

        return "\n".join(result)


class JITIteratorCallable(object):
    def __init__(self, func, *args):
        if not callable(func):
            raise RuntimeError("Function must be callable")

        self.func = func
        self.args = args

    def __iter__(self):
        for x in self.func(*self.args):
            yield x

    def __contains__(self, item):
        return item in list(self)

    def __str__(self):
        return str(list(self))


class JITIterator(JITIteratorCallable):
    def __init__(self, baseclass):
        super(JITIterator, self).__init__(
            lambda: (x.name for x in baseclass.classes.values() if x.name))


def CopyFDs(in_fd, out_fd, length=2**64):
    """Copy from one fd to another.

    If length is specified, we stop when we copied this many bytes. We always
    stop when in_fd reaches EOF.
    """
    while length > 0:
        data = in_fd.read(min(10000000, length))
        if not data:
            return

        out_fd.write(data)
        length -= len(data)


def CopyAStoFD(in_as, out_fd, start=0, length=2**64,
               cb=lambda off, length: None):
    """Copy an address space into a file-like object."""
    blocksize = 1024 * 1024

    for run in in_as.get_address_ranges(start=start, end=start+length):
        for offset in xrange(run.start, run.end, blocksize):
            to_read = min(blocksize, run.end - offset, length)
            if to_read == 0:
                break

            data = in_as.read(offset, to_read)

            out_fd.seek(offset)
            out_fd.write(data)
            length -= len(data)

            cb(offset, len(data))


def issubclass(obj, cls):    # pylint: disable=redefined-builtin
    """A sane implementation of issubclass.

    See http://bugs.python.org/issue10569

    Python bare issubclass must be protected by an isinstance test first since
    it can only work on types and raises when provided something which is not a
    type.

    Args:
      obj: Any object or class.
      cls: The class to check against.

    Returns:
      True if obj is a subclass of cls and False otherwise.
    """
    return isinstance(obj, type) and __builtin__.issubclass(obj, cls)


def XOR(string1, string2):
    """Returns string1 xor string2."""
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(string1, string2))


def xrange(start, end, step=1):
    """In Python2 the xrange builtin is broken.

    It raises when start or end do not fit in an int. Since python does not
    generally care about this we need to implement a clean version of this
    builtin.
    """
    x = start
    while x < end:
        yield x
        x += step


def SafePickle(data):
    """An unpickler for serialized tuple/lists/strings etc.

    Does not support recovering instances.
    """
    return cPickle.dumps(data, -1)

def SafeUnpickler(data):
    """An unpickler for serialized tuple/lists/strings etc.

    Does not support recovering instances.
    """
    unpickler = cPickle.Unpickler(cStringIO.StringIO(data))
    unpickler.find_global = None

    return unpickler.load()


def SplitPath(path):
    """Splits the path into a list of components."""
    result = []
    while 1:
        path, filename = ntpath.split(path)

        if filename:
            result.append(filename)
        else:
            if path and path not in ("\\", "/"):
                result.append(path)
            break

    result.reverse()
    return result


def CaseInsensitiveDictLookup(key, dictionary):
    """Lookup the dictionary with a case insensitive key."""
    # First try as is.
    result = dictionary.get(key)
    if result is None:
        for k, v in dictionary.iteritems():
            if k.lower() == key.lower():
                return v

    return result


def TimeIt(f):
    def NewFunction(self, *args, **kw):
        try:
            now = time.time()
            return f(self, *args, **kw)
        finally:
            print "Took %s sec" % (time.time() - now)

    return NewFunction

def GetStack():
    """Returns the current call stack as a string."""
    return "".join(traceback.format_stack())


def InternObject(obj):
    """Copies and interns strings in a recursive object."""
    obj_cls = obj.__class__
    if obj_cls is str:
        return intern(obj)

    if obj_cls is unicode:
        return intern(str(obj))

    if obj_cls is dict:
        result = {}
        for k, v in obj.iteritems():
            k = InternObject(k)
            v = InternObject(v)
            result[k] = v

        return result

    if obj_cls is list:
        return [InternObject(x) for x in obj]

    return obj


class safe_property(property):
    """Re-Raises AttributeError in properties.

    In Python @property swallows AttributeError and calls __getattr__. This is
    rarely what you want because sometime an AttributeError is erronously raised
    from legitimately broken property code and just swallowing it automatically
    can cause weird error messages (e.g. Attribute foobar does not exist, if
    foobar is a property) or even worse, it calls __getattr__ which does
    something completely different.
    """

    def __get__(self, *args, **kwargs):
        try:
            return super(safe_property, self).__get__(*args, **kwargs)
        except AttributeError as e:
            message = "AttributeError raised: %s" % e

            # Retain the original backtrace but re-raise a RuntimeError to
            # prevent the property from calling __getattr__.
            raise RuntimeError, message, sys.exc_info()[2]


def EscapeForFilesystem(filename):
    """Creates a filesystem suitable name.

    Very conservative.
    """
    s = SmartStr(filename).strip().replace(" ", "_")
    return re.sub(r"(?u)[^-\w.]", "", s)


def get_all_subclasses(base=None):
    for x in base.__subclasses__():
        yield x.__name__
        for y in get_all_subclasses(x):
            yield y


def join_path(*args):
    result = "/".join(args)
    result = re.sub("/+", "/", result)
    return result.strip("/")


def normpath(path):
    return "/" + join_path(*path.split("/"))
