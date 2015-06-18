import cPickle
import cStringIO
import os
import time

from rekall import config
from rekall import io_manager
from rekall import obj
from rekall import utils
from rekall.ui import json_renderer


config.DeclareOption(
    "--cache", default="file", type="String",
    choices=["file", "memory", "timed"],
    help="Type of cache to use. ")


class PicklingDirectoryIOManager(io_manager.DirectoryIOManager):
    def Encoder(self, data, **_):
        encoder = json_renderer.JsonEncoder(
            session=self.session, renderer="JsonRenderer")
        data = encoder.Encode(data)

        try:
            return cPickle.dumps(data, -1)
        except TypeError:
            raise io_manager.EncodeError("Unable to pickle data")

    def Decoder(self, raw):
        """Safe Unpickling.

        Unpickle only safe primitives like tuples, dicts and
        strings. Specifically does not allow arbitrary instances to be
        recovered.
        """
        unpickler = cPickle.Unpickler(cStringIO.StringIO(raw))
        unpickler.find_global = None

        json_renderer_obj = json_renderer.JsonRenderer(
            session=self.session)
        decoder = json_renderer.JsonDecoder(
            self.session, json_renderer_obj)

        decoded = unpickler.load()

        return decoder.Decode(decoded)


class Cache(object):
    def __init__(self):
        self.data = {}

    def Get(self, item, default=None):
        return self.data.get(item, default)

    def Set(self, item, value, volatile=True):
        _ = volatile
        if value is None:
            self.data.pop(item, None)
        else:
            self.data[item] = value

    def Clear(self):
        self.data.clear()

    def Flush(self):
        """Called to sync the cache to external storage if required."""

    def __str__(self):
        """Print the contents somewhat concisely."""
        result = []
        for k, v in self.data.iteritems():
            if isinstance(v, obj.BaseObject):
                v = repr(v)

            value = "\n  ".join(str(v).splitlines())
            if len(value) > 1000:
                value = "%s ..." % value[:1000]

            result.append("  %s = %s" % (k, value))

        return "{\n" + "\n".join(sorted(result)) + "\n}"


class TimedCache(Cache):
    """A limited time Cache.

    This is useful for live analysis to ensure that information is not stale.
    """
    expire_time = 5

    def Get(self, item, default=None):
        now = time.time()
        data, timestamp = self.data.get(item, (default, now))
        if timestamp + self.expire_time < now:
            del self.data[item]
            return default

        return data

    def Set(self, item, value, volatile=True):
        """Sets the item to the value.

        The value will be cached for the expiry time if it is volatile (by
        default). Non-volatile data will never expire.

        Even on a live system, we cache information which can not change for the
        life of the system (e.g. the profile or dtb values). These are marked
        non-volatile and will not be expired.
        """
        if value is None:
            self.data.pop(item, None)
        else:
            if volatile:
                now = time.time()
            else:
                now = 2**63

            self.data[item] = (value, now)

    def __str__(self):
        """Print the contents somewhat concisely."""
        result = []
        now = time.time()
        for k, (v, timestamp) in self.data.items():
            if timestamp + self.expire_time < now:
                self.data.pop(k)
                continue

            if isinstance(v, obj.BaseObject):
                v = repr(v)

            value = "\n  ".join(str(v).splitlines())
            if len(value) > 1000:
                value = "%s ..." % value[:1000]

            result.append("  %s = %s" % (k, value))

        return "{\n" + "\n".join(sorted(result)) + "\n}"


class FileCache(Cache):
    """A cache which syncs to a persistent on disk representation.
    """
    def __init__(self, session):
        super(FileCache, self).__init__()
        self._io_manager = None
        self.session = session
        self.fingerprint = None
        self.name = None

        # Record all the dirty cached keys.
        self.dirty = set()

    @property
    def io_manager(self):
        if self._io_manager is None:
            cache_dir = self.session.GetParameter("cache_dir")
            # Cache dir may be specified relative to the home directory.
            if config.GetHomeDir():
                cache_dir = os.path.join(config.GetHomeDir(), cache_dir)

            if os.access(cache_dir, os.F_OK | os.R_OK | os.W_OK | os.X_OK):
                self._io_manager = PicklingDirectoryIOManager(
                    "%s/sessions" % cache_dir, session=self.session,
                    mode="w")

        return self._io_manager

    def SetName(self, name):
        self.name = name

    def SetFingerprint(self, fingerprint):
        name = fingerprint["hash"]
        if self.name != name and self.io_manager:
            indexes = self.io_manager.GetData("sessions/index") or {}
            indexes[name] = fingerprint["tests"]

            self.name = name
            self.io_manager.StoreData("sessions/index", indexes)

    def Get(self, item, default=None):
        if (self.io_manager and             # We are backing to a file.
                item not in self.data and   # Item not already cached in memory.
                item not in self.dirty):    # Item was not previously changed.
            try:
                data = self.io_manager.GetData(
                    "sessions/%s/%s" % (self.name, item),
                    default=self)
                if data is not self:
                    self.data[item] = data
            except Exception:
                self.session.logging.error(
                    "Unable to decode cached object %s", item)

        return super(FileCache, self).Get(item, default=default)

    def Set(self, item, value, volatile=True):
        super(FileCache, self).Set(item, value, volatile=volatile)
        self.dirty.add(item)

    def Flush(self):
        """Write out all dirty items at once."""
        if self.name and self.io_manager:
            # Save to disk the dirty items.
            for key, item in self.data.iteritems():
                if key in self.dirty or getattr(item, "dirty", False):
                    now = time.time()
                    self.io_manager.StoreData(
                        "sessions/%s/%s" % (self.name, key), item)
                    self.session.logging.debug("Flushed %s in %s" % (
                        key, (time.time() - now)))

            self.io_manager.FlushInventory()

    def DetectImage(self, address_space):
        if not self.io_manager:
            return

        session_index = self.io_manager.GetData("sessions/index")
        for name, tests in session_index.iteritems():
            item = SessionIndex(name, tests)
            if item.Test(address_space):
                self.SetName(item.name)
                self.data.clear()
                return item.name


class SessionIndex(object):
    def __init__(self, name, tests):
        self.name = name
        self.test = tests

    def Test(self, address_space):
        for offset, expected in self.test:
            expected = utils.SmartStr(expected)
            if (offset and expected !=
                    address_space.read(offset, len(expected))):
                return False

        return True



def Factory(session, cache_type):
    """Instantiate the most appropriate cache for this session."""
    if cache_type == "memory":
        return Cache()

    if cache_type == "timed":
        return TimedCache()

    if cache_type == "file":
        return FileCache(session)

    return Cache()
