from rekall.plugins import yarascanner
from rekall.plugins.common import scanners
from rekall.plugins.darwin import common


class DarwinYaraScan(yarascanner.YaraScanMixin,
                     scanners.BaseScannerPlugin,
                     common.ProcessFilterMixin,
                     common.AbstractDarwinCommand):
    """Scan using yara signatures."""
