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


class classproperty(property):
    """A property that can be called on classes."""

    def __get__(self, cls, owner):
        return self.fget(owner)


def memoize(f):
    cache = {}

    def helper(*args):
        cached = cache.get(args, memoize)
        if cached is not memoize:
            return cached

        cached = f(*args)
        cache[args] = cached
        return cached

    return helper


class UniqueObjectIdMetaclass(type):
    """Give each object a unique ID.

    unlike id() this number will not be reused when the objects are destroyed,
    hence it can be used to identify identical objects without keeping these
    around.
    """
    ID = 0

    def __call__(cls, *args, **kwargs):
        res = super(UniqueObjectIdMetaclass, cls).__call__(*args, **kwargs)
        res._object_id = UniqueObjectIdMetaclass.ID  # pylint: disable=protected-access
        UniqueObjectIdMetaclass.ID += 1

        return res


class UniqueObjectIdMixin(object):
    __metaclass__ = UniqueObjectIdMetaclass


class MetaclassRegistry(UniqueObjectIdMetaclass):
    """Automatic Plugin Registration through metaclasses."""

    def __init__(cls, name, bases, env_dict):
        super(MetaclassRegistry, cls).__init__(name, bases, env_dict)

        cls._install_constructors(cls)

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
            if cls.__name__ in cls.classes:
                raise RuntimeError(
                    "Multiple definitions for class %s (%s)" % (
                        cls, cls.classes[cls.__name__]))

            cls.classes[cls.__name__] = cls
            name = getattr(cls, "name", None)

            # We expect that classes by name will collide, which is why each
            # value is a list of classes with that name.
            cls.classes_by_name.setdefault(name, []).append(cls)

            try:
                if cls.top_level_class.include_plugins_as_attributes:
                    setattr(cls.top_level_class, cls.__name__, cls)
            except AttributeError:
                pass

        # Allow the class itself to initialize itself.
        cls_initializer = getattr(cls, "_class_init", None)
        if cls_initializer:
            cls_initializer()

    @classmethod
    def _install_constructors(mcs, cls):
        def ByName(self, name):
            for impl in self.classes.values():
                if getattr(impl, "name", None) == name:
                    return impl

        cls.ImplementationByName = classmethod(ByName)

        def ByClass(self, name):
            return self.classes.get(name)

        cls.ImplementationByClass = classmethod(ByClass)
