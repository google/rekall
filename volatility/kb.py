# This module provides for a central knowledge base which plugins can use to
# collect information.

import bisect
import re


class SymbolContainer(object):
    """A container class for symbols."""


class SortedAddresses(object):
    """An object to abstract searching for known memory locations."""

    def __init__(self):
        self._data = []
        self._map = {}

    def AddMemoryLocation(self, offset, data):
        """Adds the data to the memory offset."""
        bisect.insort_right(self._data, offset)
        self._map.setdefault(offset, []).append(data)

    def GetSpan(self, offset):
        """Gets the next lowest and next highest data below the offset or None."""
        idx = bisect.bisect_left(self._data, offset)

        if idx == 0:
            lowest = None
        else:
            lowest = self._map.get(self._data[idx - 1])

        if idx == len(self._data):
            highest = None
        else:
            highest = self._map.get(self._data[idx])

        return lowest, highest


class SymbolAddresses(SortedAddresses):

    def __init__(self):
        super(SymbolAddresses, self).__init__()
        self.symbols = SymbolContainer()

    def AddMemoryLocation(self, offset, func):
        """Add the function object to the list."""
        super(SymbolAddresses, self).AddMemoryLocation(offset, func)

        try:
            module_name, func_name = func.obj_name.split(":")
            module_name = re.match("[_a-zA-Z0-9]+", module_name).group(0)
            func_name = re.match("[_a-zA-Z0-9]+", func_name).group(0)

            module = getattr(self.symbols, module_name, None)
            if module is None:
                module = SymbolContainer()
                setattr(self.symbols, module_name, module)

            setattr(module, func_name, offset)

        except ValueError as e:
            pass


# A dict keyed by AS name organizing the symbols known for this address space.
SYMBOLS = {}
