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

    def __init__(self, *args, **kwargs):
        super(PicklingDirectoryIOManager, self).__init__(*args, **kwargs)
        self.renderer = json_renderer.JsonRenderer(session=self.session)

    def Encoder(self, data, **_):
        data = self.renderer.encoder.Encode(data)

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
        now = time.time()
        unpickler = cPickle.Unpickler(cStringIO.StringIO(raw))
        unpickler.find_global = None

        try:
            decoded = unpickler.load()
        except Exception:
            raise io_manager.DecodeError("Unable to unpickle cached object")

        result = self.renderer.decoder.Decode(decoded)
        self.session.logging.debug("Decoded in %s sec.", time.time() - now)

        return result


class Cache(object):
    def __init__(self, session):
        self.data = {}
        self.session = session
        if session == None:
            raise RuntimeError("Session must be set")

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
            if len(value) > 100:
                value = "%s ..." % value[:100]

            result.append("  %s = %s" % (k, value))

        return "{\n" + "\n".join(sorted(result)) + "\n}"


class TimedCache(Cache):
    """A limited time Cache.

    This is useful for live analysis to ensure that information is not stale.
    """

    @utils.safe_property
    def expire_time(self):
        # Change this via the session.SetParameter("cache_expiry_time", XXX)
        return self.data.get("cache_expiry_time", 600)

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
        super(FileCache, self).__init__(session)
        self._io_manager = None
        self.fingerprint = None
        self.name = None

        # Record all the dirty cached keys.
        self.dirty = set()
        self.cache_dir = None
        self.enabled = True

        # Make sure we get flushed when the session is closed.
        self.session.register_flush_hook(self, self.Flush)

    @utils.safe_property
    def io_manager(self):
        if not self.enabled:
            return

        cache_dir = os.path.expandvars(
            self.session.GetParameter("cache_dir", cached=False))

        cache_dir = os.path.join(config.GetHomeDir(self.session), cache_dir)

        # Force the IO manager to be recreated if the cache dir has
        # changed. This allows the session to change it's cache directory on the
        # fly (which is actually done when setting it from the command line).
        if cache_dir != self.cache_dir:
            self._io_manager = None
            self.cache_dir = cache_dir

        if self._io_manager is None and cache_dir:
            # Cache dir may be specified relative to the home directory.
            if os.access(cache_dir, os.F_OK | os.R_OK | os.W_OK | os.X_OK):
                self._io_manager = PicklingDirectoryIOManager(
                    "%s/sessions" % cache_dir, session=self.session,
                    mode="w")

                self.cache_dir = cache_dir
            else:
                self.session.logging.warn(
                    "Cache directory inaccessible. Disabling.")
                self.enabled = False

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

    def Clear(self):
        super(FileCache, self).Clear()

        # Also delete the files backing this cache.
        if self._io_manager:
            self._io_manager.Destroy("sessions/%s" % self.name)

    @utils.safe_property
    def location(self):
        return "%s/v1.0/sessions/%s" % (self._io_manager.location, self.name)

    def Flush(self):
        """Write out all dirty items at once."""
        if self.fingerprint is None and self.session.HasParameter("profile"):
            self.SetFingerprint(self.session.GetParameter("image_fingerprint"))

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

        self.data.clear()
        self.dirty.clear()

    def DetectImage(self, address_space):
        if not self.io_manager:
            return

        session_index = self.io_manager.GetData("sessions/index")
        for name, tests in session_index.iteritems():
            item = SessionIndex(name, tests)
            if item.Test(address_space):
                self.SetName(item.name)

                # Force current data to be flushed to disk so we do not lose it.
                self.Flush()
                return item.name

    def __repr__(self):
        if self._io_manager:
            return "<FileCache @ %s>" % self.location
        else:
            return "<FileCache (unbacked)>"


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


def GetCacheDir(session):
    """Returns the path of a usable cache directory."""
    cache_dir = os.path.expandvars(session.GetParameter("cache_dir"))

    if not cache_dir:
        raise io_manager.IOManagerError(
            "Local profile cache is not configured - "
            "add a cache_dir parameter to ~/.rekallrc.")

    # Cache dir may be specified relative to the home directory.
    cache_dir = os.path.join(config.GetHomeDir(session), cache_dir)

    if not os.access(cache_dir, os.F_OK | os.R_OK | os.W_OK | os.X_OK):
        try:
            os.makedirs(cache_dir)
        except (IOError, OSError):
            raise io_manager.IOManagerError(
                "Unable to create or access cache directory %s" % cache_dir)

    return cache_dir


def Factory(session, cache_type):
    """Instantiate the most appropriate cache for this session."""
    if cache_type == "memory":
        return Cache(session)

    if cache_type == "timed":
        return TimedCache(session)

    if cache_type == "file":
        return FileCache(session)

    return Cache(session)
