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


# The remainder of this file are component definitions:
# =====================================================


# Has to be defined first!
Entity = component.DeclareComponent(
    "Entity", "A special component that's always present.",
    component.Field("identity", "Identity", "The identity."),
    component.Field("collectors", [str],
                    "The collectors that contributed to this entity."))

Named = component.DeclareComponent(
    "Named", "Human-readable identifying information.",
    component.Field("name", str, "Human-readable name"),
    component.Field("kind", str, "Human-readable type"))


MemoryObject = component.DeclareComponent(
    "MemoryObject", "Stores base objects, mostly structs.",
    component.Field("base_object", component.BaseObjectDescriptor(),
                    "An instance of BaseObject."),
    component.Field("type", str, "Class name of the base object."),
    component.Field("state", {"freed", "allocated"},
                    "Allocation state (freed or not)."))


Buffer = component.DeclareComponent(
    "Buffer", "Stores raw memory contents at a given address.",
    component.Field("start", "Pointer",
                    "Pointer to start of the buffer."),
    component.Field("end", "Pointer",
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
    component.Field("context", "Identity",
                    "Owner of the buffer, e.g. a zone, terminal..."))


NetworkInterface = component.DeclareComponent(
    "NetworkInterface", "A network interface.",
    component.Field("name", str, "E.g. en01, tunnel, etc."),
    component.Field("addresses", [(str, str)],
                    "List of (protocol family, address)."))


Process = component.DeclareComponent(
    "Process", "A process.",
    component.Field("pid", int, "PID, on systems that have one."),
    component.Field("parent", "Identity",
                    "Process that spawned this process."),
    component.Field("user", "Identity",
                    "The user with whose credentials this is running."),
    component.Field("command", str,
                    "The path to the binary or the command that executed."),
    component.Field("arguments", [str],
                    "List of arguments."),
    component.Field("is_64bit", bool, "Is the process running in 64bit."),
    component.Field("session",
                    "Identity", "The session this process belongs to."))


Terminal = component.DeclareComponent(
    "Terminal", "A terminal (tty) session.",
    component.Field("session", "Identity", "The login session of this TTY."),
    component.Field("file", "Identity", "The file for this TTY."))


Session = component.DeclareComponent(
    "Session", "A user session.",
    component.Field("user", "Identity", "The user."),
    component.Field("sid", int, "Session ID."))


Connection = component.DeclareComponent(
    "Connection", "A network connection or a socket.",
    component.Field("src_addr", str,
                    "Source address, e.g. offset of local socket or IP."),
    component.Field("dst_addr", str,
                    "Destination address."),
    component.Field("protocols", [str],
                    "List of protocols in order (e.g. [IP, TCP])"),
    component.Field("addressing_family", str,
                    "Addressing protocol (e.g INET, or UNIX)"),
    component.Field("state", str,
                    "State of the connection, if meaningful."),
    component.Field("src_bind", str,
                    "The bind at source, such as port, or offset."),
    component.Field("dst_bind", str,
                    "The bind at destination, such as port, or offset."),
    component.Field("interface", "Identity",
                    "The network interface handling this, if any."),
    component.Field("file_bind", "Identity",
                    "UNIX sockets can bind to a file."))


Handle = component.DeclareComponent(
    "Handle", "A handle from process to file/connection/etc.",
    component.Field("resource", "Identity",
                    "The object of the handle, e.g. file or socket"),
    component.Field("process", "Identity",
                    "The process that owns this handle."),
    component.Field("fd", int, "File descriptor as known to the process."),
    component.Field("flags", None, "Arbitrary OS-level flags."))


File = component.DeclareComponent(
    "File", "A file/directory/socket with a FS path.",
    component.Field("path", str, "The filesystem path to this file."),
    component.Field("parent", "Identity",
                    "Parent file (directory, ZIP archive, etc.)"),
    component.Field("mount", "Identity", "The volume this file is on."),
    component.Field("type", {"file", "socket", "directory", "link", "other"},
                    "Is this a directory, normal file, etc."))


Event = component.DeclareComponent(
    "Event",
    "Something that happened, e.g. 'User/name=h4x0r', 'pwned', 'local/*'",
    component.Field("actor", "Identity", "Who done it."),
    component.Field("action", str,
                    "One word action, such as 'created' or 'pwned'."),
    component.Field("target", "Identity", "Unwitting (or is it) victim."),
    component.Field("description", str,
                    "What happened. Did Timmy fall down the well?"),
    component.Field("native_id", str,
                    "Native event ID, such as Windows Event ID, etc."),
    component.Field("timestamp", int, "When did this go down?"),
    component.Field("category", {"latest", "earliest", "recent", "ancient"},
                    "In lieu of timestamp, approximate timing, e.g. recent."))


Timestamps = component.DeclareComponent(
    "Timestamps",
    "Standard times, such as ctime, atime, mtime, ...",
    component.Field("created_at", int, "Creation/start time."),
    component.Field("destroyed_at", int, "Deletion/destruction/stop time."),
    component.Field("accessed_at", int, "Access time."),
    component.Field("modified_at", int, "Modification time."),
    component.Field("backup_at", int, "Backup time."))


Permissions = component.DeclareComponent(
    "Permissions", "Basic permissions and ownership.",
    component.Field("owner", "Identity", "User who owns this."),
    component.Field("group", "Identity", "Group who owns this."),
    component.Field("chmod", int, "UNIX-like permissions integer."),
    component.Field("acl", [str], "Arbitrary access control list."))


User = component.DeclareComponent(
    "User", "A user account.",
    component.Field("uid", int, "A unique user id, if any."),
    component.Field("username", str, "System username."),
    component.Field("home_dir", "Identity",
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
