"""This file defines some common messages in a central place.

Many of these have been directly converted from GRR.
"""
import platform
import socket
import yaml
from wheel import pep425tags

from rekall import resources
from rekall_agent import serializer

# Get field definitions from messages.yaml.
path = resources.get_resource("messages.yaml", "rekall-agent",
                              prefix="messages")

DEFINITIONS = yaml.safe_load(open(path, "rb").read())


class Uname(serializer.SerializedObject):
    """Stores information about the system."""

    schema = DEFINITIONS["Uname"]

    @classmethod
    def from_current_system(cls, session=None):
        """Gets a Uname object populated from the current system"""
        uname = platform.uname()
        fqdn = socket.getfqdn()
        system = uname[0]
        architecture, _ = platform.architecture()
        if system == "Windows":
            service_pack = platform.win32_ver()[2]
            kernel = uname[3]  # 5.1.2600
            release = uname[2]  # XP, 2000, 7
            version = uname[3] + service_pack  # 5.1.2600 SP3, 6.1.7601 SP1
        elif system == "Darwin":
            kernel = uname[2]  # 12.2.0
            release = "OSX"  # OSX
            version = platform.mac_ver()[0]  # 10.8.2
        elif system == "Linux":
            kernel = uname[2]  # 3.2.5
            release = platform.linux_distribution()[0]  # Ubuntu
            version = platform.linux_distribution()[1]  # 12.04

        # Emulate PEP 425 naming conventions - e.g. cp27-cp27mu-linux_x86_64.
        pep425tag = "%s%s-%s-%s" % (pep425tags.get_abbr_impl(),
                                    pep425tags.get_impl_ver(),
                                    str(pep425tags.get_abi_tag()).lower(),
                                    pep425tags.get_platform())

        return cls.from_keywords(
            session=session,
            system=system,
            architecture=architecture,
            node=uname[1],
            release=release,
            version=version,
            machine=uname[4],              # x86, x86_64
            kernel=kernel,
            fqdn=fqdn,
            pep425tag=pep425tag,
        )


# The rest will be automatically created as plain old data objects (PODO).
globals().update(serializer.load_from_dict(DEFINITIONS, [
    "CpuSample", "ClientInformation", "IOSample", "ClientStats",
    "CpuSeconds",
]))
