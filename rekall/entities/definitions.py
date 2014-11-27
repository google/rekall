# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
This module defines all the components that Rekall knows about.

A component is a collection of properties that relate to an entity, which is
an encapsulated notion of identity. In Rekall, components are basically just
named tuples which we store in a big hashtable, indexed by the entity they
relate to.

See:
  http://en.wikipedia.org/wiki/Entity_component_system
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.entities import component
from rekall.entities import entity
from rekall.entities import types


# The remainder of this file are component definitions:
# =====================================================


# Has to be defined first!
Entity = component.DeclareComponent(
    "Entity", "A special component that's always present.",
    component.Field("identity", entity.IdentityDescriptor(), "The identity."),
    component.Field("collectors", [str],
                    "The collectors that contributed to this entity."))

Named = component.DeclareComponent(
    "Named", "Human-readable identifying information.",
    component.Field("name", str, "Human-readable name", width=40),
    component.Field("kind", str, "Human-readable type", width=16))


MemoryObject = component.DeclareComponent(
    "MemoryObject", "Stores base objects, mostly structs.",
    component.Field("base_object", types.BaseObjectDescriptor(),
                    "An instance of BaseObject."),
    component.Field("type", str, "Class name of the base object."),
    component.Field("state", {"freed", "allocated"},
                    "Allocation state (freed or not)."))


Buffer = component.DeclareComponent(
    "Buffer", "Stores raw memory contents at a given address.",
    component.Field("start", "BaseObjectDescriptor",
                    "Pointer to start of the buffer."),
    component.Field("end", "BaseObjectDescriptor",
                    "Pointer to end of the buffer."),
    component.Field("kind", {"flat", "ring"},
                    "Ring buffer's end can be lower than its start."),
    component.Field("size", int, "Size of the buffer (in bytes)."),
    component.Field("state", {"freed", "allocated"},
                    "Allocation state (freed or not)."),
    component.Field("contents", str,
                    "Raw contents (contains unprintable characters)."),
    component.Field("purpose",
                    {"zones", "terminal_input", "terminal_output",
                     "clipboard", "pipe", "socket", "mmap", "ubc"},
                    "Use of the buffer, e.g. pipe, tty, mmap..."),
    component.Field("context", entity.IdentityDescriptor(),
                    "Owner of the buffer, e.g. a zone, terminal..."))


SignatureMatch = component.DeclareComponent(
    "SignatureMatch",
    "Stores a successful string or signature match.",
    component.Field("matched_object", entity.IdentityDescriptor(),
                    "The object containing the match."),
    component.Field("signature", str, "The signature used in the search."),
    component.Field("method", {"string", "yara", "regex"},
                    "How was the scan done?"))


NetworkInterface = component.DeclareComponent(
    "NetworkInterface", "A network interface.",
    component.Field("name", str, "E.g. en01, tunnel, etc."),
    component.Field("addresses", [(str, str)],
                    "List of (protocol family, address)."))


Process = component.DeclareComponent(
    "Process", "A process.",
    component.Field("pid", int, "PID, on systems that have one.", width=6),
    component.Field("cr3", "PointerDescriptor",
                    "Saved CR3 value (DTB location).", width=14,
                    style="address"),
    component.Field("parent", entity.IdentityDescriptor(),
                    "Process that spawned this process.", width=20),
    component.Alias("children", alias="&Process/parent",
                    docstring="Children of this process."),
    component.Field("user", entity.IdentityDescriptor(),
                    "The user with whose credentials this is running.",
                    width=20),
    component.Field("command", str,
                    "The path to the binary or the command that executed.",
                    width=30),
    component.Field("image_file", entity.IdentityDescriptor(),
                    "The file where the process was loaded from.",
                    hidden=True),
    component.Field("priority", int, "Priority of this process.", hidden=True),
    component.Field("env", str, "Process env variables.", hidden=True),
    component.Field("arguments", [str],
                    "List of arguments.", width=40, hidden=True),
    component.Field("is_64bit", bool, "Is the process running in 64bit.",
                    width=10),
    component.Field("session", entity.IdentityDescriptor(),
                    "The session this process belongs to.",
                    width=20),
    component.Alias("handles", alias="&Handle/process",
                    docstring="Handles owned by this process."),)


Terminal = component.DeclareComponent(
    "Terminal", "A terminal (tty) session.",
    component.Field("session", entity.IdentityDescriptor(),
                    "The login session of this TTY."),
    component.Field("file", entity.IdentityDescriptor(),
                    "The file for this TTY."))


Session = component.DeclareComponent(
    "Session", "A user session.",
    component.Field("user", entity.IdentityDescriptor(), "The user."),
    component.Field("sid", int, "Session ID."))


Connection = component.DeclareComponent(
    "Connection", "A connection or socket.",
    component.Field("protocol_family", str,
                    "Protocol family determines addressing."),
    component.Field("active", bool, "Human-readable state."),
    component.Field("bytes_received", int, "Bytes in."),
    component.Field("bytes_sent", int, "Bytes out."),
    component.Field("packets_received", int, "Packets in."),
    component.Field("packets_sent", int, "Packets out."),
    component.Alias("handles", alias="&Handle/resource",
                    docstring="Handles by processes on this file."))


OSILayer3 = component.DeclareComponent(
    "OSILayer3", "Network-layer connection.",
    component.Field("src_addr", str, "Address of source."),
    component.Field("dst_addr", str, "Address of destination"),
    component.Field("protocol", str, "Layer 3 protocol."))


OSILayer4 = component.DeclareComponent(
    "OSILayer4", "Transport-layer connection.",
    component.Field("src_port", int, "Port at source."),
    component.Field("dst_port", int, "Port at destination."),
    component.Field("state", str, "State of the connection, if stateful."),
    component.Field("protocol", str, "Layer 4 protocol."))


OSIDataLayer = component.DeclareComponent(
    "OSIDataLayer", "OSI layers 5-7 constitute the data layer.",
    component.Field("protocol", str,
                    "Highest-layer protocol (usually layer 7)."))


Socket = component.DeclareComponent(
    "Socket", "A UNIX domain socket",
    component.Field("address", str, "Memory address of the socket."),
    component.Field("connected", str,
                    "Memory address of other socket in pair."),
    component.Field("type", {"STREAM", "DGRAM", "SEQPACKET"},
                    "Type in AF_UNIX/AF_LOCAL family."),
    component.Field("file", entity.IdentityDescriptor(),
                    "The file this socket binds to."))


Handle = component.DeclareComponent(
    "Handle", "A handle from process to file/connection/etc.",
    component.Field("resource", entity.IdentityDescriptor(),
                    "The object of the handle, e.g. file or socket", width=80),
    component.Field("process", entity.IdentityDescriptor(),
                    "The process that owns this handle.", width=40),
    component.Field("fd", int, "File descriptor as known to the process.",
                    width=5),
    component.Field("flags", None, "Arbitrary OS-level flags."))


File = component.DeclareComponent(
    "File", "A file/directory/socket with a FS path.",
    component.Field("path", str, "The filesystem path to this file."),
    component.Field("parent", entity.IdentityDescriptor(),
                    "Parent file (directory, ZIP archive, etc.)"),
    component.Alias("handles", alias="&Handle/resource",
                    docstring="Handles by processes on this file."),
    component.Field("mount", entity.IdentityDescriptor(),
                    "The volume this file is on."),
    component.Field("type", {"file", "socket", "directory", "link", "other"},
                    "Is this a directory, normal file, etc."))


Event = component.DeclareComponent(
    "Event",
    "Something that happened, e.g. 'User/name=h4x0r', 'pwned', 'local/*'",
    component.Field("actor", entity.IdentityDescriptor(), "Who done it.",
                    width=40),
    component.Field("action", str,
                    "One word action, such as 'created' or 'pwned'."),
    component.Field("target", entity.IdentityDescriptor(),
                    "Unwitting (or is it) victim.", width=40),
    component.Field("description", str,
                    "What happened. Did Timmy fall down the well?"),
    component.Field("native_id", str,
                    "Native event ID, such as Windows Event ID, etc."),
    component.Field("timestamp", "DatetimeDescriptor", "When did this go down?",
                    width=25),
    component.Field("category", {"latest", "earliest", "recent", "ancient"},
                    "In lieu of timestamp, approximate timing, e.g. recent."))


Timestamps = component.DeclareComponent(
    "Timestamps",
    "Standard times, such as ctime, atime, mtime, ...",
    component.Field("created_at", "DatetimeDescriptor", "Creation/start time.",
                    width=25),
    component.Field("destroyed_at", "DatetimeDescriptor",
                    "Deletion/destruction/stop time.", width=25),
    component.Field("accessed_at", "DatetimeDescriptor", "Access time.",
                    width=25),
    component.Field("modified_at", "DatetimeDescriptor", "Modification time.",
                    width=25),
    component.Field("backup_at", "DatetimeDescriptor", "Backup time.",
                    hidden=True, width=25))


Permissions = component.DeclareComponent(
    "Permissions", "Basic permissions and ownership.",
    component.Field("owner", entity.IdentityDescriptor(),
                    "User who owns this."),
    component.Field("group", entity.IdentityDescriptor(),
                    "Group who owns this."),
    component.Field("chmod", int, "UNIX-like permissions integer."),
    component.Field("acl", [str], "Arbitrary access control list."))


User = component.DeclareComponent(
    "User", "A user account.",
    component.Field("uid", int, "A unique user id, if any."),
    component.Field("username", str, "System username."),
    component.Alias("processes", alias="&Process/user",
                    docstring="Processes running as this user."),
    component.Field("home_dir", entity.IdentityDescriptor(),
                    "File that represents the user's home dir."),
    component.Field("real_name", str, "User's real name."))


AllocationZone = component.DeclareComponent(
    "AllocationZone", "Zone as used by zone allocators.",
    component.Field("name", str, "Name of the zone as used by kernel."),
    component.Field("type", str, "Type of thing found in the zone."),
    component.Field("count_active", int, "Count of allocated elements."),
    component.Field("count_free", int, "Count of freed elements."),
    component.Field("element_size", int, "Size per element."),
    component.Field("tracks_pages", bool,
                    "Whether the zone tracks the pages it used."),
    component.Field("max_size", int,
                    "Maximum size the zone can grow to, if any."),
    component.Field("page_count", int,
                    "Count of memory pages used by the zone."),
    component.Field("is_exhaustible", bool,
                    "Whether the zone can be exhausted/filled up."),
    component.Field("is_expandable", bool, "Whether the zone can grow."),
    component.Field("allows_foreign", bool,
                    "Does the zone allow pages from outside zalloc."),
    component.Field("is_collectable", bool,
                    "Can this zone be garbage-collected."))
