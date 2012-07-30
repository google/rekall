"""These are various utilities for volatility."""
# Volatility
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

import itertools
import socket
import threading
import time


def SmartStr(string, encoding="utf8"):
    """Forces the string to be an encoded byte string."""
    if isinstance(string, unicode):
        return string.encode(encoding)

    return str(string)


def SmartUnicode(string, encoding="utf8"):
    """Forces the string into a unicode object."""
    try:
        # Allow the object to have a __unicode__ method.
        return unicode(string)
    except UnicodeError:
        return str(string).decode(encoding, "ignore")


class VolatilityException(Exception):
    """Generic Volatility Specific exception, to help differentiate from other exceptions"""


def Hexdump(data, width = 16):
    """ Hexdump function shared by various plugins """
    for offset in xrange(0, len(data), width):
        row_data = data[offset:offset + width]
        translated_data = [x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
        hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

        yield offset, hexdata, translated_data


def WriteHexdump(fd, data, base=0, width=16):
    """Write the hexdump to the fd."""
    for offset, hexdata, translated_data in Hexdump(data):
        fd.write(u"{0:#010x}  {1:<48}  {2}\n".format(
                base + offset, hexdata, "".join(translated_data)))


# This is a synchronize decorator.
def Synchronized(f):
  """Synchronization decorator."""

  def NewFunction(self, *args, **kw):
    with self.lock:
      return f(self, *args, **kw)

  return NewFunction


class FastStore(object):
  """This is a cache which expires objects in oldest first manner.

  This implementation first appeared in PyFlag and refined in GRR.
  """

  def __init__(self, max_size=10, kill_cb=None):
    """Constructor.

    Args:
       max_size: The maximum number of objects held in cache.
       kill_cb: An optional function which will be called on each
                object terminated from cache.
    """
    self._age = []
    self._hash = {}
    self._limit = max_size
    self._kill_cb = kill_cb
    self.lock = threading.RLock()

  @Synchronized
  def Expire(self):
    """Expires old cache entries."""
    while len(self._age) > self._limit:
      x = self._age.pop(0)
      self.ExpireObject(x)

  @Synchronized
  def Put(self, key, obj):
    """Add the object to the cache."""
    try:
      idx = self._age.index(key)
      self._age.pop(idx)
    except ValueError:
      pass

    self._hash[key] = obj
    self._age.append(key)

    self.Expire()

    return key

  @Synchronized
  def ExpireObject(self, key):
    """Expire a specific object from cache."""
    obj = self._hash.pop(key, None)

    if self._kill_cb and obj is not None:
      self._kill_cb(obj)

    return obj

  @Synchronized
  def ExpireRegEx(self, regex):
    """Expire all the objects with the key matching the regex."""
    for key in self._hash.keys():
      if re.match(regex, key):
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
      idx = self._age.index(key)
      self._age.pop(idx)
      self._age.append(key)
    except ValueError:
      raise KeyError(key)

    return self._hash[key]

  @Synchronized
  def __contains__(self, obj):
    return obj in self._hash

  @Synchronized
  def __getitem__(self, key):
    return self.Get(key)

  @Synchronized
  def Flush(self):
    """Flush all items from cache."""
    while self._age:
      x = self._age.pop(0)
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
                numlen, key = lambda x: x[1], reverse = True),
                              key = lambda x: x[0])[0]
        words = []
        for k, l in numlen:
            if (k == 0) and (l == max_zero_run[1]) and not (None in words):
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
