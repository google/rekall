from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest
from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.visitors import typedef_resolving_visitor


class TestTypedefResolvingVisitor(unittest.TestCase):

  def setUp(self):
    self.typedef_resolving_visitor = (
        typedef_resolving_visitor.TypedefResolvingVisitor()
    )
    self.types = {}

  def test_resolve_with_enum(self):
    node = c_ast.CEnum('attributes')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertIsNone(actual)

  def test_resolve_with_struct(self):
    node = c_ast.CStruct('content', 'attributes')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertIsNone(actual)

  def test_resolve_with_union(self):
    node = c_ast.CUnion('content', 'attributes')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertIsNone(actual)

  def test_resolve_with_array(self):
    node = c_ast.CArray(42, 'type_definition')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertIsNone(actual)

  def test_resolve_with_pointer(self):
    node = c_ast.CPointer('type_definition')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertIsNone(actual)

  def test_resolve_with_pointer_to_function(self):
    node = c_ast.CPointerToFunction()
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertIsNone(actual)

  def test_resolve_with_type_reference_with_name_not_in_types(self):
    self.types.update({
        'some_type_name': 'some_type_definition',
    })
    node = c_ast.CTypeReference('some_other_name')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertEqual(actual, node)

  def test_resolve_with_type_reference_with_unresolvable_definition(self):
    self.types.update({
        'some_type_name': c_ast.CSimpleType(33, 42),
    })
    node = c_ast.CTypeReference('some_type_name')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertEqual(actual, node)

  def test_resolve_with_type_reference_with_resolvable_definition(self):
    other_type_definition = c_ast.CTypeReference('some_other_name')
    self.types.update({
        'some_type_name': other_type_definition,
    })
    node = c_ast.CTypeReference('some_type_name')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertEqual(actual, other_type_definition)

  def test_resolve_with_typedef_with_unresolvable_type(self):
    other_type_reference = c_ast.CSimpleType(33, 42)
    node = c_ast.CTypedef(
        name='some_name',
        type_definition=other_type_reference,
    )
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertIsNone(actual)

  def test_resolve_with_typedef_with_resolvable_type(self):
    other_type_reference = c_ast.CTypeReference('some_other_name')
    node = c_ast.CTypedef(
        name='some_name',
        type_definition=other_type_reference,
    )
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertEqual(actual, other_type_reference)

  def test_resolve_with_simple_type(self):
    node = c_ast.CSimpleType(33, 42)
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertIsNone(actual)

  def test_with_chained_typedef_references_ended_by_unresolvable_type(self):
    some_type = c_ast.CSimpleType(33, 42)
    some_other_type = c_ast.CSimpleType(42, 33)
    type_1_t = c_ast.CTypedef(
        name='type_1_t',
        type_definition=c_ast.CTypeReference('some_type'),
    )
    type_2_t = c_ast.CTypedef(
        name='type_2_t',
        type_definition=c_ast.CTypeReference('type_1_t'),

    )
    type_3_t = c_ast.CTypedef(
        name='type_3_t',
        type_definition=c_ast.CTypeReference('type_2_t'),
    )
    self.types.update({
        'some_type': some_type,
        'some_other_type': some_other_type,
        'type_1_t': type_1_t,
        'type_2_t': type_2_t,
        'type_3_t': type_3_t,
    })
    node = c_ast.CTypeReference('type_3_t')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    expected = c_ast.CTypeReference('some_type')
    self.assertEqual(actual, expected)

  def test_with_chained_typedef_references_ended_by_simple_type_reference(
      self,
  ):
    some_simple_type = c_ast.CSimpleType(33, 42)
    some_type = c_ast.CTypeReference('some_simple_type')
    some_other_type = c_ast.CSimpleType(42, 33)
    type_1_t = c_ast.CTypedef(
        name='type_1_t',
        type_definition=c_ast.CTypeReference('some_type'),
    )
    type_2_t = c_ast.CTypedef(
        name='type_2_t',
        type_definition=c_ast.CTypeReference('type_1_t'),

    )
    type_3_t = c_ast.CTypedef(
        name='type_3_t',
        type_definition=c_ast.CTypeReference('type_2_t'),
    )
    self.types.update({
        'some_simple_type': some_simple_type,
        'some_type': some_type,
        'some_other_type': some_other_type,
        'type_1_t': type_1_t,
        'type_2_t': type_2_t,
        'type_3_t': type_3_t,
    })
    node = c_ast.CTypeReference('type_3_t')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertEqual(actual, some_type)

  def test_with_chained_typedef_references_ended_by_type_definition(self):
    some_type = c_ast.CTypeDefinition(
        type_name='some_type',
        type_definition='some_definition',
    )
    some_other_type = c_ast.CSimpleType(42, 33)
    type_1_t = c_ast.CTypedef(
        name='type_1_t',
        type_definition=c_ast.CTypeReference('some_type'),
    )
    type_2_t = c_ast.CTypedef(
        name='type_2_t',
        type_definition=c_ast.CTypeReference('type_1_t'),

    )
    type_3_t = c_ast.CTypedef(
        name='type_3_t',
        type_definition=c_ast.CTypeReference('type_2_t'),
    )
    self.types.update({
        'some_type': some_type,
        'some_other_type': some_other_type,
        'type_1_t': type_1_t,
        'type_2_t': type_2_t,
        'type_3_t': type_3_t,
    })
    node = c_ast.CTypeReference('type_3_t')
    actual = self.typedef_resolving_visitor.resolve(node, self.types)
    self.assertEqual(actual, some_type)
