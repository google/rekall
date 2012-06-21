"""These are various utilities for volatility."""
# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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
import threading

import volatility.addrspace as addrspace

#pylint: disable-msg=C0111

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


class CacheRelativeURLException(VolatilityException):
    """Exception for gracefully not saving Relative URLs in the cache"""


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
