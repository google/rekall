# Rekall Memory Forensics
# Copyright (C) 2011
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Michael Cohen <scudette@gmail.com>
#
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# *****************************************************

""" This module implements a class registry.

We scan the memory_plugins directory for all python files and add those classes
which should be registered into their own lookup tables. These are then ordered
as required. The rest of Rekall Memory Forensics will then call onto the
registered classes when needed.

The MetaclassRegistry automatically adds any derived class to the base
class. This means that we do not need to go through a special initializating
step, as soon as a module is imported, the plugin is registered.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

import abc


class classproperty(property):
    """A property that can be called on classes."""
    def __get__(self, cls, owner):
        return self.fget(owner)


class MetaclassRegistry(abc.ABCMeta):
    """Automatic Plugin Registration through metaclasses."""

    def __init__(cls, name, bases, env_dict):
        abc.ABCMeta.__init__(cls, name, bases, env_dict)

        # Attach the classes dict to the baseclass and have all derived classes
        # use the same one:
        for base in bases:
            try:
                cls.classes = base.classes
                cls.classes_by_name = base.classes_by_name
                cls.plugin_feature = base.plugin_feature
                cls.top_level_class = base.top_level_class
                break
            except AttributeError:
                cls.classes = {}
                cls.classes_by_name = {}
                cls.plugin_feature = cls.__name__
                # Keep a reference to the top level class
                cls.top_level_class = cls

        # The following should not be registered as they are abstract. Classes
        # are abstract if the have the __abstract attribute (note this is not
        # inheritable so each abstract class must be explicitely marked).
        abstract_attribute = "_%s__abstract" % name
        if getattr(cls, abstract_attribute, None):
            return

        if not cls.__name__.startswith("Abstract"):
            cls.classes[cls.__name__] = cls
            name = getattr(cls, "_%s__name" % cls.__name__, None)
            cls.classes_by_name[name] = cls
            try:
                if cls.top_level_class.include_plugins_as_attributes:
                    setattr(cls.top_level_class, cls.__name__, cls)
            except AttributeError:
                pass

        # Allow the class itself to initialize itself.
        cls_initializer = getattr(cls, "_class_init", None)
        if cls_initializer:
            cls_initializer()

