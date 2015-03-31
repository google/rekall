# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
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
#

"""
The Rekall Entity Layer.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

import re

from rekall.entities import definitions

from rekall.entities.query import visitor


class Dependency(object):
    """A dependency of a query on collectors that produce specific data.

    A query can depend on either a collector that produces instances of a
    certain component (e.g. to run 'Process/pid is 5') the Process component
    definitely needs to be collected, or on collectors that also happen to
    always set a certain attribute to a specific value (e.g.
    'Struct/type is 'vnode'' will depend on collectors that declare they
    produce Struct and set the type to 'vnode').

    The latter can also be used to exclude collectors from running - for
    example, if the query is for 'Struct/type is 'vnode'' then there is no
    point running a collector that declares it will produce Struct but
    always set type to 'socket'.

    There are two subclasses: DependencySet is an implementation detail; see
    documentation for SimpleDependency for how dependencies are represented.
    """

    dependencies = ()

    def simplified(self):
        """Discards everything but the component dependency."""
        pass

    def match(self, promise):
        """Does the promise (a SimpleDependency) match this dependency?"""
        pass

    def normalize(self):
        """Generates two sets of SimpleDependency instances from self.

        Returns tuple of (include, exclude):
            include: Set of instances of SimpleDependency to be included
                when running collectors.

            exclude: Any collectors that match SimpleDependency objects in this
                set should be excluded from search.
        """
        include = set()
        exclude = set()

        for dependency in self.dependencies:
            simplified = dependency.simplified()

            if dependency.flag:
                if simplified in self.dependencies:
                    include.add(simplified)
                else:
                    include.add(dependency)
            else:
                include.add(simplified)
                exclude.add(dependency)

        return include, exclude


class DependencySet(Dependency):
    """Represents more dependency on more than one component or attribute.

    Instances of this class are not returned by the dependency solver and they
    are an implementation detail. Calling DependencySet.normalize will return
    instances of SimpleDependency which are intended for use outside of this
    module.
    """

    def __init__(self, *dependencies):
        self.dependencies = set()
        for dependency in dependencies:
            self.update(dependency)

    def match(self, promise):
        if not isinstance(promise, SimpleDependency):
            raise ValueError(
                "Promise must be a SimpleDependency; got %s." % promise)

        include, exclude = self.normalize()
        for dependency in exclude:
            if dependency.match(promise):
                return False

        for dependency in include:
            if dependency.match(promise):
                return True

        return False

    def update(self, dependency):
        """Adds dependencies from other, which is a Dependency itself."""
        self.dependencies |= dependency.dependencies

    def __repr__(self):
        return "DependencySet(%s)" % ", ".join(
            [repr(dep) for dep in self.dependencies])

    def simplified(self):
        """Simplifies all contents and returns a new DependencySet."""
        new_deps = [dep.simplified() for dep in self.dependencies]
        return DependencySet(*new_deps)


class SimpleDependency(Dependency):
    """Represents a simple dependency on component or attribute.

    Members:
        component: Depends on collectors that yield this component.
        attribute: (optional) Depends on collectors that set this attribute.
        value: (optional) Depends on collectors that set component/attribute
            to this value.
        flag: (True by default) If set to False, collectors that match this
            dependency should be excluded instead of included. This is useful
            when a query specifically asks for things that != a certain value.
    """

    SHORTHAND = re.compile(r"([A-Z][a-zA-Z0-9]+)(?:\/([a-z0-9_]+)=(.+))?")

    def __init__(self, component, attribute=None, value=None, flag=True,
                 weak=False, expression=None):
        self.component = component
        self.attribute = attribute
        self.value = value
        self.flag = flag
        self.weak = weak
        self.dependencies = set([self])
        self.expression = expression

    @classmethod
    def parse(cls, promise):
        """Parses the shorthand format used in collector promises.

        Arguments:
            promise: A string in format of 'Component/attribute=value' with
                everything after 'Component' being optional.
        """
        match = cls.SHORTHAND.match(promise)
        if not match:
            raise ValueError("Invalid promise format: %s." % promise)

        return cls(*match.groups())

    def simplified(self):
        return SimpleDependency(component=self.component,
                                expression=self.expression)

    def inverted(self):
        """Returns a SimpleDependency with the flag flipped."""
        return SimpleDependency(component=self.component, value=self.value,
                                attribute=self.attribute, flag=(not self.flag),
                                expression=self.expression)

    def astuple(self):
        return (self.component, self.attribute, self.value, self.flag)

    def normalize(self):
        if self.flag:
            return set([self]), set()

        return set([self.simplified()]), set([self])

    def match(self, promise):
        if not isinstance(promise, SimpleDependency):
            raise ValueError(
                "Promise must be a SimpleDependency; got %s." % promise)
        return self == promise or (self.attribute != promise.attribute and
                                   self.component == promise.component)

    def __eq__(self, other):
        return ((self.component, self.attribute, self.value, self.flag) ==
                (other.component, other.attribute, other.value, other.flag))

    def __repr__(self):
        return "SimpleDependency(%s, %s, %s, %s)" % self.astuple()

    def __hash__(self):
        return hash(self.astuple())


class QueryAnalyzer(visitor.QueryVisitor):
    """Given a query, find its dependencies on collectors and indices.

    In general terms, we can detect two kinds of collector dependencies:

    1) A query may depend on a specific component being populated - for example,
    'Process/pid is 5' will definitely require the Process component. The solver
    will never miss a dependency on a component, but in certain cases, it may
    do better and return more granular dependencies.

    2) A query may depend on a specific attribute being set to a constant value
    (a Literal). For example, 'Struct/type is 'socket'' will depend on
    collectors that either just declare that they collect Struct, but
    collectors that explicitly declare they set Struct/type to values
    other than 'socket' will be excluded.
    """

    include = ()
    exclude = ()

    def run(self):
        """Analyzes query for dependencies on collectors and indices.

        Returns a tuple of:
            - Set of SimpleDependency instances to be included.
            - Set of SimpleDependency instances to be excluded.
            - Set of names of attributes whose indices can speed up the query.
        """
        self.query.execute("QueryValidator")
        self.latest_indices = set()
        self._let_stack = []  # How deep are we in Let expressions?
        self.expected_components = set()
        result = self.visit(self.expression)
        if isinstance(result, Dependency):
            self.include, self.exclude = result.normalize()

        return self

    def visit_Literal(self, expr):
        return expr.value

    def visit_Binding(self, expr):
        component, attribute = expr.value.split("/", 1)
        if not self._let_stack:
            self.expected_components.add(component)

        # Certain types of fields should be considered weak dependencies, which
        # means we definitely want to depend on the component, but if we can
        # find a more specific dependency on the same component, the weak
        # dependency may be discarded under certain circumstances.
        component_cls = getattr(definitions, component)
        field = component_cls.reflect_attribute(attribute)
        if field.typedesc.type_name == "Entity":
            return SimpleDependency(component=component, attribute=attribute,
                                    weak=True, expression=expr)

        return SimpleDependency(component=component, attribute=attribute,
                                expression=expr)

    def visit_ComponentLiteral(self, expr):
        if not self._let_stack:
            self.expected_components.add(expr.value)

        return SimpleDependency(expr.value)

    def visit_Let(self, expr):
        context = expr.context.value
        ctx_component, ctx_attribute = context.split("/", 1)

        if not self._let_stack:
            self.expected_components.add(ctx_component)

        dependency = SimpleDependency(component=ctx_component,
                                      attribute=ctx_attribute,
                                      expression=expr)

        self._let_stack.append(expr)
        value = self.visit(expr.expression)
        self._let_stack.pop()

        if isinstance(value, Dependency):
            dependency = DependencySet(dependency, *value.dependencies)

        self.latest_indices.add(context)

        return dependency

    def visit_Complement(self, expr):
        # If we're dealing with simple dependencies, we can just flip the
        # flag from inclusion to exclusion (e.g. Struct/type !=
        # 'socket').
        value = self.visit(expr.value)
        if isinstance(value, SimpleDependency):
            value.flag = not value.flag
            return value

        # If the above didn't return the we can't do anything smart about this.
        return self.visit_Expression(expr)

    def _solve_Equivalence(self, dependency, value, expr):
        attribute_path = "%s/%s" % (dependency.component, dependency.attribute)

        # Suggest that the manager build an index for component/attribute.
        self.latest_indices.add(attribute_path)

        # This is a hacky special case - in case the query we're analyzing is
        # looking for a specific base object, our dependency should actually be
        # on the type of the object instead of the memory offset.
        if attribute_path == "Struct/base":
            dependency.attribute = "type"
            dependency.value = value.obj_type
        else:
            dependency.value = value

        dependency.expression = expr
        return dependency

    def visit_Equivalence(self, expr):
        # Dependency inference is only available for binary equivalence with
        # one Binding and one expression that evals to a literal value, such
        # as Literal or Addition/Union/etc. only involving literals.
        if len(expr.children) == 2:
            x = self.visit(expr.children[0])
            y = self.visit(expr.children[1])
            if (isinstance(x, SimpleDependency)
                    and not isinstance(y, Dependency)):
                return self._solve_Equivalence(x, y, expr)
            elif (isinstance(y, SimpleDependency)
                  and not isinstance(x, Dependency)):
                return self._solve_Equivalence(y, x, expr)

        # If the above doesn't return the we can't infer much here and fall
        # through to the default behavior.
        return self.visit_Expression(expr)

    def visit_Union(self, expr):
        # Add positive dependencies. Exclusions don't help us with unions and
        # neither do weak dependencies, so they'll all get simplified down to
        # a component dependency.
        seen = set()
        for child in expr.children:
            value = self.visit(child)
            if not isinstance(value, Dependency):
                continue

            for dependency in value.dependencies:
                if dependency.flag:
                    seen.add(dependency)
                else:
                    seen.discard(dependency)
                    seen.discard(dependency.inverted())
                    seen.add(dependency.simplified())

        return DependencySet(*seen)

    def visit_Intersection(self, expr):
        # Add positive dependencies. Mutually-exclusive dependencies should be
        # simplified to just the bare component dependency and weak dependencies
        # should be discarded if a more specific dependency exists.

        # This will require two passes. First pass will sort dependencies into
        # weak ones (component-only but thrown out in favor of more specific),
        # simple ones (component-only and override specific dependencies) and
        # specific (component/attribute and value).
        weak = set()
        specific = set()
        simple = set()
        for child in expr.children:
            value = self.visit(child)
            if not isinstance(value, Dependency):
                continue

            for dependency in value.dependencies:
                if dependency.weak:
                    weak.add(dependency.component)
                elif dependency.attribute:
                    inverted = dependency.inverted()
                    if inverted in specific:
                        specific.discard(inverted)
                        specific.discard(dependency)
                        simple.add(dependency.component)
                    else:
                        specific.add(dependency)
                else:
                    simple.add(dependency.component)

        # Second pass will build up a list of dependencies according to the
        # rules described above.
        results = set()
        for dependency in specific:
            component = dependency.component
            if component in simple:
                results.add(SimpleDependency(component))
                simple.discard(component)
                continue
            elif component in weak:
                weak.discard(component)

            results.add(dependency)

        for component in simple:
            results.add(SimpleDependency(component=component,
                                         expression=expr))

        for component in weak:
            results.add(SimpleDependency(component=component, weak=True,
                                         expression=expr))

        return DependencySet(*results)

    def visit_Expression(self, expr):
        # Fall-through behavior for things we can't handle - simplify to
        # components.
        seen = DependencySet()
        for child in expr.children:
            value = self.visit(child)

            if isinstance(value, Dependency):
                seen.update(value.simplified())

        return seen
