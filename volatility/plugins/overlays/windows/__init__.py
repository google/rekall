# Note that we deliberately do not import all the vtypes here as they get
# imported only when the profile is instantiated. This leads to much faster
# startup times, especially when packed.
from volatility.plugins.overlays.windows import windows
from volatility.plugins.overlays.windows import xp
