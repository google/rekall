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
import bisect
import importlib
import itertools
import json
import re
import socket
import threading
import time


def SmartStr(string, encoding="utf8"):
    """Forces the string to be an encoded byte string."""
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
    """ Hexdump function shared by various plugins """
    for offset in xrange(0, len(data), width):
        row_data = data[offset:offset + width]
        translated_data = [
            x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
        hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

        yield offset, hexdata, translated_data


def WriteHexdump(renderer, data, base=0, width=16):
    """Write the hexdump to the fd."""
    renderer.table_header([('Offset', 'offset', '[addrpad]'),
                           ('Hex', 'hex', '^' + str(width * 3)),
                           ('Data', 'data', '^' + str(width))])

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


    @Synchronized
    def Expire(self):
        """Expires old cache entries."""
        while len(self._age) > self._limit:
            x = self._age.PopLeft()
            self.ExpireObject(x)

    @Synchronized
    def Put(self, key, item):
        """Add the object to the cache."""
        try:
            node, _ = self._hash[key]
            self._age.Unlink(node)
        except KeyError:
            pass

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
        # Remove the item and put to the end of the age list
        try:
            node, item = self._hash[key]
            self._age.Unlink(node)
            self._age.AppendNode(node)
        except ValueError:
            raise KeyError(key)

        return item

    @Synchronized
    def __contains__(self, item):
        return item in self._hash

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
    """A self cleaning temporary directory."""

    def __init__(self, fd):
        self.fd = fd

    def __enter__(self):
        if fcntl:
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_EX)
        return self.fd

    def __exit__(self, exc_type, exc_value, traceback):
        if fcntl:
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)


class AttributeDict(dict):
    """A dict that can be accessed via attributes."""

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
        self[attr] = value

    def __getattr__(self, attr):
        return self.get(attr)

    def __dir__(self):
        return sorted(self)


def FormatIPAddress(family, value):
    """Formats a value as an ascii IP address determined by family."""
    return socket.inet_ntop(
        getattr(socket, str(family)),
        value.obj_vm.read(value.obj_offset, value.size()))

def ntoh(value):
    size = value.size()
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
    if isinstance(data, dict):
        # Empty dicts emitted on one line.
        if not data:
            return "{}"

        result.append("{")
        tmp = []
        for key, value in sorted(data.items()):
            # Only emit non-empty dicts.
            if value:
                tmp.append(
                    " %s%s: %s" % (
                        " " * depth,
                        json.dumps(str(key)),
                        PPrint(data[key], depth + 1).strip()))

        result.append(", \n".join(tmp)[depth:])

        result.append(" }")
        return "\n".join([(" " * depth + x) for x in result])

    if isinstance(data, (list, tuple)):
        for item in data:
            result.append(PPrint(item, depth).strip())

        return "[" + ", ".join(result) + "]"

    if isinstance(data, basestring):
        try:
            data = json.dumps(data.encode("ascii"))
        except UnicodeError:
            pass

    return str(data)


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


# The following is from
# http://code.activestate.com/recipes/577197-sortedcollection/
# Created by Raymond Hettinger on Fri, 16 Apr 2010 (MIT)

class SortedCollection(object):
    '''Sequence sorted by a key function.

    SortedCollection() is much easier to work with than using bisect() directly.
    It supports key functions like those use in sorted(), min(), and max().
    The result of the key function call is saved so that keys can be searched
    efficiently.

    Instead of returning an insertion-point which can be hard to interpret, the
    five find-methods return a specific item in the sequence. They can scan for
    exact matches, the last item less-than-or-equal to a key, or the first item
    greater-than-or-equal to a key.

    Once found, an item's ordinal position can be located with the index()
    method.

    New items can be added with the insert() and insert_right() methods.
    Old items can be deleted with the remove() method.

    The usual sequence methods are provided to support indexing, slicing,
    length lookup, clearing, copying, forward and reverse iteration, contains
    checking, item counts, item removal, and a nice looking repr.

    Finding and indexing are O(log n) operations while iteration and insertion
    are O(n).  The initial sort is O(n log n).

    The key function is stored in the 'key' attibute for easy introspection or
    so that you can assign a new key function (triggering an automatic re-sort).

    In short, the class was designed to handle all of the common use cases for
    bisect but with a simpler API and support for key functions.

    >>> from pprint import pprint
    >>> from operator import itemgetter

    >>> s = SortedCollection(key=itemgetter(2))
    >>> for record in [
    ...         ('roger', 'young', 30),
    ...         ('angela', 'jones', 28),
    ...         ('bill', 'smith', 22),
    ...         ('david', 'thomas', 32)]:
    ...     s.insert(record)

    >>> pprint(list(s))         # show records sorted by age
    [('bill', 'smith', 22),
     ('angela', 'jones', 28),
     ('roger', 'young', 30),
     ('david', 'thomas', 32)]

    >>> s.find_le(29)           # find oldest person aged 29 or younger
    ('angela', 'jones', 28)
    >>> s.find_lt(28)           # find oldest person under 28
    ('bill', 'smith', 22)
    >>> s.find_gt(28)           # find youngest person over 28
    ('roger', 'young', 30)

    >>> r = s.find_ge(32)       # find youngest person aged 32 or older
    >>> s.index(r)              # get the index of their record
    3
    >>> s[3]                    # fetch the record at that index
    ('david', 'thomas', 32)

    >>> s.key = itemgetter(0)   # now sort by first name
    >>> pprint(list(s))
    [('angela', 'jones', 28),
     ('bill', 'smith', 22),
     ('david', 'thomas', 32),
     ('roger', 'young', 30)]

    '''

    def __init__(self, iterable=(), key=None):
        self._given_key = key
        key = (lambda x: x) if key is None else key
        decorated = sorted((key(item), item) for item in iterable)
        self._keys = [k for k, item in decorated]
        self._items = [item for k, item in decorated]
        self._key = key

    def _getkey(self):
        return self._key

    def _setkey(self, key):
        if key is not self._key:
            self.__init__(self._items, key=key)

    def _delkey(self):
        self._setkey(None)

    key = property(_getkey, _setkey, _delkey, 'key function')

    def clear(self):
        self.__init__([], self._key)

    def copy(self):
        return self.__class__(self, self._key)

    def __len__(self):
        return len(self._items)

    def __getitem__(self, i):
        return self._items[i]

    def __iter__(self):
        return iter(self._items)

    def __reversed__(self):
        return reversed(self._items)

    def __repr__(self):
        return '%s(%r, key=%s)' % (
            self.__class__.__name__,
            self._items,
            getattr(self._given_key, '__name__', repr(self._given_key))
        )

    def __reduce__(self):
        return self.__class__, (self._items, self._given_key)

    def __contains__(self, item):
        k = self._key(item)
        i = bisect.bisect_left(self._keys, k)
        j = bisect.bisect_right(self._keys, k)
        return item in self._items[i:j]

    def index(self, item):
        'Find the position of an item.  Raise ValueError if not found.'
        k = self._key(item)
        i = bisect.bisect_left(self._keys, k)
        j = bisect.bisect_right(self._keys, k)
        return self._items[i:j].index(item) + i

    def count(self, item):
        'Return number of occurrences of item'
        k = self._key(item)
        i = bisect.bisect_left(self._keys, k)
        j = bisect.bisect_right(self._keys, k)
        return self._items[i:j].count(item)

    def insert(self, item):
        'Insert a new item.  If equal keys are found, add to the left'
        k = self._key(item)
        i = bisect.bisect_left(self._keys, k)
        self._keys.insert(i, k)
        self._items.insert(i, item)

    def insert_right(self, item):
        'Insert a new item.  If equal keys are found, add to the right'
        k = self._key(item)
        i = bisect.bisect_right(self._keys, k)
        self._keys.insert(i, k)
        self._items.insert(i, item)

    def remove(self, item):
        'Remove first occurence of item.  Raise ValueError if not found'
        i = self.index(item)
        del self._keys[i]
        del self._items[i]

    def find(self, k):
        'Return first item with a key == k.  Raise ValueError if not found.'
        i = bisect.bisect_left(self._keys, k)
        if i != len(self) and self._keys[i] == k:
            return self._items[i]
        raise ValueError('No item found with key equal to: %r' % (k,))

    def find_le(self, k):
        'Return last item with a key <= k.  Raise ValueError if not found.'
        i = bisect.bisect_right(self._keys, k)
        if i:
            return self._items[i-1]
        raise ValueError('No item found with key at or below: %r' % (k,))

    def find_lt(self, k):
        'Return last item with a key < k.  Raise ValueError if not found.'
        i = bisect.bisect_left(self._keys, k)
        if i:
            return self._items[i-1]
        raise ValueError('No item found with key below: %r' % (k,))

    def find_ge(self, k):
        """Return first item with a key >= equal to k.

        Raise ValueError if not found
        """
        i = bisect.bisect_left(self._keys, k)
        if i != len(self):
            return self._items[i]
        raise ValueError('No item found with key at or above: %r' % (k,))

    def find_gt(self, k):
        'Return first item with a key > k.  Raise ValueError if not found'
        i = bisect.bisect_right(self._keys, k)
        if i != len(self):
            return self._items[i]
        raise ValueError('No item found with key above: %r' % (k,))
