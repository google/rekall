# Implement efilter protocols for Rekall types.

from efilter.protocols import applicative
from efilter.protocols import associative
from efilter.protocols import eq
from efilter.protocols import number
from efilter.protocols import ordered
from efilter.protocols import repeated
from efilter.protocols import string
from efilter.protocols import structured

from rekall import obj

from rekall.plugins.overlays import basic

from rekall_lib import registry
from rekall_lib import utils

import arrow
import parsedatetime
import pytz
import time


def resolve_Pointer(ptr, member):
    """Delegate to target of the pointer, if any."""
    target_obj = ptr.deref()
    if not target_obj:
        ptr.session.logging.warn(
            "Attempting to access member %r of a void pointer %r.", member, ptr)
    if target_obj:
        return structured.resolve(target_obj, member)


# Pointer.member is implemented as Pointer.dereference().member.
structured.IStructured.implement(
    for_type=obj.Pointer,
    implementations={
        structured.resolve: resolve_Pointer
    }
)

# AttributeDict is like a dict, except it does not raise when accessed
# via an attribute - it just returns None. Plugins can return an
# AttributeDict when they may return arbitrary columns and then
# Efilter can simply reference these columns via the "." operator. If
# the field does not exist, the column will simply have None there.
structured.IStructured.implement(
    for_type=utils.AttributeDict,
    implementations={
        structured.resolve: lambda d, m: d.get(m),
        structured.getmembers_runtime: lambda d: list(d),
    }
)

# SlottedObject is similar in functionality to AttributeDict but it is much
# faster and so it is preferred.
structured.IStructured.implement(
    for_type=utils.SlottedObject,
    implementations={
        structured.resolve: lambda s, m: getattr(s, m, None),
        structured.getmembers_runtime: lambda d: d.__slots__,
    }
)


# This lets us recurse into a NoneObject without raising errors.
structured.IStructured.implement(
    for_type=obj.NoneObject,
    implementations={
        structured.resolve: lambda x, y: x,
    }
)

# This lets us do flags.member.
structured.IStructured.implement(
    for_type=basic.Flags,
    implementations={
        structured.resolve: getattr,
        structured.getmembers_runtime: lambda x: list(x.maskmap),
    }
)

# This lets us get indices out of Arrays.
associative.IAssociative.implement(
    for_type=obj.Array,
    implementations={
        associative.select: lambda obj, key: obj[key],
    }
)


# This lets us do some_array.some_member. Useful for accessing properties.
structured.IStructured.implement(
    for_type=obj.Array,
    implementations={
        structured.resolve: getattr
    }
)



# Pointers are only repeated if the thing they are pointing to is.
repeated.isrepeating.implement(
    for_type=obj.Pointer,
    implementation=lambda x: repeated.isrepeating(x.deref()))

repeated.IRepeated.implement(
    for_type=obj.Array,
    implementations={
        repeated.getvalues: lambda x: iter(x)
    }
)


string.IString.implement(
    for_type=basic.String,
    implementations={
        string.string: lambda x: utils.SmartUnicode(x)
    }
)


# Number operations on a pointer manipulate the pointer's value.
number.INumber.implement(
    for_types=(obj.Pointer, obj.NumericProxyMixIn),
    implementations={
        number.sum: lambda x, y: int(x) + y,
        number.product: lambda x, y: int(x) * y,
        number.difference: lambda x, y: int(x) - y,
        number.quotient: lambda x, y: int(x) / y
    }
)


def _robust_lt(x, y):
    try:
        return x < y
    except Exception as e:
        # No valid comparison between the two items, return False
        return False


# Rekall objects with NumericProxyMixIn are orderable.
ordered.IOrdered.implement(
    for_types=(obj.NumericProxyMixIn, ),
    implementations={
        ordered.lt: _robust_lt,
    }
)

def _string_lt(x, y):
    if string.isstring(y):
        return string.string(x) < string.string(y)

    return False

# We can compare a string like object with another string like object.
ordered.IOrdered.implement(
    for_types=(obj.StringProxyMixIn,),
    implementations={
        ordered.lt: _string_lt,
    }
)


# Handle UnixTimeStamp comparisons. The timestamp formats we accept
# can be seen in https://bear.im/code/parsedatetime/docs/index.html

@registry.memoize
def _parse_datetime(string, timezone):
    res, code = parsedatetime.Calendar().parseDT(
        string, sourceTime=time.localtime(),
        tzinfo=pytz.timezone(timezone),
    )

    if code == 0:
        raise ValueError("Unable to parse %s as a timestamp" % string)

    return arrow.Arrow.fromdatetime(res)

def _timestamp_lt(unix_timestamp, y):
    if string.isstring(y):
        timestamp = _parse_datetime(
            y, unix_timestamp.obj_session.GetParameter("timezone", "UTC"))
        if timestamp != None:
            return unix_timestamp.as_arrow() < timestamp

    return False

def _timestamp_eq(unix_timestamp, y):
    if string.isstring(y):
        timestamp = _parse_datetime(
            y, unix_timestamp.obj_session.GetParameter("timezone", "UTC"))
        if timestamp != None:
            return unix_timestamp.as_arrow() == timestamp

    return False

# Special handling for timestamps.
ordered.IOrdered.implement(
    for_types=(basic.UnixTimeStamp,),
    implementations={
        ordered.lt: _timestamp_lt,
    }
)

eq.IEq.implement(
    for_types=(basic.UnixTimeStamp,),
    implementations={
        eq.eq: _timestamp_eq,
    }
)
