from rekall_lib import yaml_utils
from rekall_lib.rekall_types import location
from rekall_lib.rekall_types import actions
from rekall_lib import serializer

ClientInformation = Uname = None

# It is more convenient to load the following automatically from yaml data.
specs = yaml_utils.ordered_load("""
ClientInformation:
- name: client_name
  type: unicode
- name: client_version
  type: int
- name: revision
  type: int
- name: build_time
  type: unicode
- name: client_description
  type: unicode
- name: labels
  repeated: true
  type: unicode

CpuSample:
- name: user_cpu_time
  type: int
- name: system_cpu_time
  type: int
- name: cpu_percent
  type: int
- name: timestamp
  type: epoch
  doc: The time of this sample.

IOSample:
- name: read_count
  type: int
- name: write_count
  type: int
- name: read_bytes
  type: int
- name: write_bytes
  type: int
- name: timestamp
  type: epoch
  doc: The time of this sample.

ClientStats:
- name: cpu_samples
  repeated: true
  type: CpuSample
- name: RSS_size
  type: int
- name: VMS_size
  type: int
- name: memory_percent
  type: int
- name: bytes_received
  type: int
- name: bytes_sent
  type: int
- name: io_samples
  repeated: true
  type: IOSample
- name: create_time
  type: int
- name: boot_time
  type: int

CpuSeconds:
- name: user_cpu_time
  type: int
- name: system_cpu_time
  type: int

Uname:
- name: system
  type: unicode
  doc: The system platform (Windows|Darwin|Linux).
- name: node
  type: unicode
  doc: The hostname of this system.
- name: release
  type: unicode
  doc: The OS release identifier e.g. 7, OSX, debian.
- name: version
  type: unicode
  doc: The OS version ID e.g. 6.1.7601SP1, 10.9.2, 14.04.
- name: machine
  type: unicode
  doc: The system architecture e.g. AMD64, x86_64.
- name: kernel
  type: unicode
  doc: The kernel version string e.g. 6.1.7601, 13.1.0, 3.15-rc2.
- name: fqdn
  type: unicode
  doc: "The system's fully qualified domain name."
- name: install_date
  type: epoch
  doc: When system was installed.
- name: libc_ver
  type: unicode
  doc: The C library version
- name: architecture
  type: unicode
  doc: The architecture of this binary. (Note this can be different from the machine
    architecture in the case of a 32 bit binary running on a 64 bit system)
- name: pep425tag
  type: unicode
  doc: The unique signature of this python system (as defined by PEP425 tags).
""")

# Inject the definitions into this module's namespace.
globals().update(serializer.load_from_dicts(specs))


class StartupMessage(serializer.SerializedObject):
    """A ticket written to the startup queue."""
    schema = [
        dict(name="client_id"),

        dict(name="client_info", type=ClientInformation,
             doc="Information about the client agent itself."),

        dict(name="boot_time", type="epoch",
             doc="Time the system booted last."),

        dict(name="agent_start_time", type="epoch",
             doc="Time the agent started."),

        dict(name="timestamp", type="epoch",
             doc="The timestamp this message was created."),

        dict(name="system_info", type=Uname,
             doc="Information about the running system"),

        dict(name="labels", repeated=True),
    ]


class StartupAction(actions.Action):
    """The startup message.

    When the client starts up it sends a message to the server containing vital
    information about itself. This allows the client to self enroll without any
    server action at all. The workflow is:

    1) The client reads the deployment manifest file. The manifest is validated.

    2) The manifest file contains a Flow specifying to run the StartupAction.

    2) The client prepares and populates a StartupMessageBatch() message.

    3) The client writes the StartupMessageTicket() message to its specified
       Location.

    4) The client proceeds to poll for its jobs queue. The client is now
       enrolled.

    In the server an EnrollerBatch runs collecting the StartupMessage messages
    and updating the relevant ClientInformation() objects at the client's VFS
    path.

    Using this information the client may be tasked with new flows.

    This enrollment scheme has several benefits:

    1) It does not depend on server load. Clients are enrolled immediately and
       do not need to wait for the server to do anything.

    2) The interrogate step is done at once at startup time every time. The
       system therefore has a fresh view of all clients all the time. Unlike GRR
       which runs the interrogate flow weekly it is not necessary to wait for an
       interrogation in order to view fresh client information.

    3) We can handle a huge influx of enrollment messages with minimal server
       resources. While agents are immediately enrolled, the rate at which
       clients can be tasked depends only on the rate at which the
       EnrollerBatch() can process through them.

    This is important when the system is first deployed because at that time all
    the new clients will be attempting to communicate at the same time.
    """
    schema = [
      dict(name="location", type=location.Location)
    ]
