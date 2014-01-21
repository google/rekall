# Import and register the core plugins
# pylint: disable=unused-import

from rekall.plugins import addrspaces
from rekall.plugins import core
from rekall.plugins import darwin

# This plugin is currently disabled pending a rewrite with the new profile
# repository..
# from rekall.plugins import guess_profile
from rekall.plugins import hypervisors
from rekall.plugins import imagecopy
from rekall.plugins import linux
from rekall.plugins import overlays
from rekall.plugins import tools
from rekall.plugins import windows
