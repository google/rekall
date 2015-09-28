from rekall.plugins import yarascanner
from rekall.plugins.darwin import common


class DarwinYaraScan(yarascanner.YaraScanMixin, common.DarwinProcessFilter):
    """Scan using yara signatures."""
