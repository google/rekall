from rekall_lib import serializer


class Resources(serializer.SerializedObject):
    """Measure resource usage."""

    schema = [
        dict(name="user_time", type="float", default=60.0),
        dict(name="system_time", type="float", default=60.0),
        dict(name="wall_time", type="float", default=60.0),
    ]

    def start(self):
        """Reset internal resource counters and start measuring."""
        raise NotImplementedError()

    def stop(self):
        """Stop measuring."""
        raise NotImplementedError()

    def update(self):
      raise NotImplementedError()


class Quota(Resources):
    schema = [
        dict(name="used", type=Resources,
             doc="The resources actually used."),
    ]

    def check(self):
        """Ensure our resource use does not exceed the quota."""
        raise NotImplementedError()
