import logging
import unittest
import pyparsing

from rekall import testlib
from rekall.plugins.tools import yara_support


class TestYaraParser(testlib.RekallBaseUnitTestCase):
    rules = [
        "rule test { condition: true }",
        "rule test { condition: true or false }",
        "rule test { condition: true and true }",
        "rule test { condition: 0x1 and 0x2}",
        "rule test { condition: false }",
        "rule test { condition: true and false }",
        "rule test { condition: false or false }",
        "rule test { condition: 2 > 1 }",
        "rule test { condition: 1 < 2 }",
        "rule test { condition: 2 >= 1 }",
        "rule test { condition: 1 <= 1 }",
        "rule test { condition: 1 == 1 }",
        "rule test { condition: 1.5 == 1.5}",
        "rule test { condition: 1.0 == 1}",
        "rule test { condition: 1.5 >= 1.0}",
        "rule test { condition: 1.5 >= 1}",
        "rule test { condition: 1.0 >= 1}",
        "rule test { condition: 0.5 < 1}",
        "rule test { condition: 0.5 <= 1}",
        "rule rest { condition: 1.0 <= 1}",
        "rule rest { condition: \"abc\" == \"abc\"}",
        "rule rest { condition: \"abc\" <= \"abc\"}",
        "rule rest { condition: \"abc\" >= \"abc\"}",
        "rule rest { condition: \"ab\" < \"abc\"}",
        "rule rest { condition: \"abc\" > \"ab\"}",
        "rule rest { condition: \"abc\" < \"abd\"}",
        "rule rest { condition: \"abd\" > \"abc\"}",
        "rule test { condition: 1 != 1}",
        "rule test { condition: 1 != 1.0}",
        "rule test { condition: 2 > 3}",
        "rule test { condition: 2.1 < 2}",
        "rule test { condition: \"abc\" != \"abc\"}",
        "rule test { condition: \"abc\" > \"abc\"}",
        "rule test { condition: \"abc\" < \"abc\"}",
        "rule test { condition: (1 + 1) * 2 == (9 - 1) \\ 2 }",
        "rule test { condition: 5 % 2 == 1 }",
        "rule test { condition: 1.5 + 1.5 == 3}",
        "rule test { condition: 3 \\ 2 == 1}",
        "rule test { condition: 3.0 \\ 2 == 1.5}",
        "rule test { condition: 1 + -1 == 0}",
        "rule test { condition: -1 + -1 == -2}",
        "rule test { condition: 4 --2 * 2 == 8}",
        "rule test { condition: -1.0 * 1 == -1.0}",
        "rule test { condition: 1-1 == 0}",
        "rule test { condition: -2.0-3.0 == -5}",
        "rule test { condition: --1 == 1}",
        "rule test { condition: 1--1 == 2}",
        "rule test { condition: -0x01 == -1}",
        "rule test { condition: 0x55 | 0xAA == 0xFF }",
        "rule test { condition: ~0xAA ^ 0x5A & 0xFF == "
        "(~0xAA) ^ (0x5A & 0xFF) }",
        "rule test { condition: ~0x55 & 0xFF == 0xAA }",
        "rule test { condition: 8 >> 2 == 2 }",
        "rule test { condition: 1 << 3 == 8 }",
        "rule test { condition: 1 | 3 ^ 3 == 1 | (3 ^ 3) }",
        "rule test { condition: ~0xAA ^ 0x5A & 0xFF == 0x0F }",
        "rule test { condition: 1 | 3 ^ 3 == (1 | 3) ^ 3}",
        "rule test { strings: $a = \"a\" $a = \"a\" condition: all of them }",
        "rule test { strings: $ = \"a\" $ = \"b\" condition: all of them }",
        "rule test { strings: $a = \"a\" condition: $a }",
        "rule test { strings: $a = \"ab\" condition: $a }",
        "rule test { strings: $a = \"abc\" condition: $a }",
        "rule test { strings: $a = \"xyz\" condition: $a }",
        "rule test { strings: $a = \"abc\" nocase fullword condition: $a }",
        "rule test { strings: $a = \"aBc\" nocase  condition: $a }",
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        "rule test { strings: $a = \"a\" fullword condition: $a }",
        "rule test { strings: $a = \"ab\" fullword condition: $a }",
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        "rule test { strings: $a = \"a\" wide condition: $a }",
        "rule test { strings: $a = \"a\" wide ascii condition: $a }",
        "rule test { strings: $a = \"ab\" wide condition: $a }",
        "rule test { strings: $a = \"ab\" wide ascii condition: $a }",
        "rule test { strings: $a = \"abc\" wide condition: $a }",
        "rule test { strings: $a = \"abc\" wide nocase fullword "
        "condition: $a }",
        "rule test { strings: $a = \"aBc\" wide nocase condition: $a }",
        "rule test { strings: $a = \"aBc\" wide ascii nocase condition: $a }",
        "rule test { strings: $a = \"---xyz\" wide nocase condition: $a }",
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        "rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }",
        "rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }",
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        "rule test { strings: $a = \"ab\" wide fullword condition: $a }",
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        "rule test {\n\
         strings:\n\
             $a = \"abcdef\"\n\
             $b = \"cdef\"\n\
             $c = \"ef\"\n\
         condition:\n\
             all of them\n\
       }",
      "rule test {\n\
         strings:\n\
             $s1 = \"abc\"\n\
             $s2 = \"xyz\"\n\
         condition:\n\
             for all of ($*) : ($)\n\
      }",
      "rule test { \
        strings: $a = { 64 01 00 00 60 01 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 64 0? 00 00 ?0 01 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 6? 01 00 00 60 0? } \
        condition: $a }",
        "rule test { \
        strings: $a = { 64 01 [1-3] 60 01 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 64 01 [1-3] (60|61) 01 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 4D 5A [-] 6A 2A [-] 58 C3} \
        condition: $a }",
        "rule test { \
        strings: $a = { 4D 5A [300-] 6A 2A [-] 58 C3} \
        condition: $a }",
        "rule test { \
        strings: $a = { 2e 7? (65 | ?""?"") 78 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 4D 5A [0-300] 6A 2A } \
        condition: $a }",
        "rule test { \
        strings: $a = { 4D 5A [0-128] 45 [0-128] 01 [0-128]  C3 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 [-] 38 39 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 [-] // Inline comment\n\
          38 39 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 /* Inline comment */ [-] 38 39 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 /* Inline multi-line\n\
                                 comment */ [-] 38 39 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 [-] 33 34 [-] 38 39 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 [1] 34 35 [2] 38 39 } \
        condition: $a }",
        "rule test {\
         strings: $a = { 31 32 [1-] 34 35 [1-] 38 39 } \
         condition: $a }",
        "rule test { \
        strings: $a = { 31 32 [0-3] 34 35 [1-] 38 39 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 [0-2] 35 [1-] 37 38 39 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 [-] 38 39 } \
        condition: all of them }",
        "rule test { \
        strings: $a = { 31 32 [-] 32 33 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 35 36 [-] 31 32 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 [2-] 34 35 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 31 32 [0-3] 37 38 } \
        condition: $a }",
        "rule test { \
        strings: $a = { 01 [0] 02 } \
        condition: $a }",
        "rule test { \
        strings: $a = { [-] 01 02 } condition: $a }",
        "rule test { \
        strings: $a = { 01 02 [-] } \
        condition: $a }",

        "rule test { \
        strings: $a = { 01 02 ([-] 03 | 04) } \
        condition: $a }",

        "rule test { \
        strings: $a = { 01 02 (03 [-] | 04) } \
        condition: $a }",

        "rule test { \
        strings: $a = { 01 02 (03 | 04 [-]) } \
        condition: $a }",

        "rule test { strings: $a = \"ssi\" condition: #a == 2 }",

        "rule test { \
        strings: $a = \"ssi\" \
        condition: $a at 2 and $a at 5 }",

        "rule test { \
        strings: $a = \"mis\" \
        condition: $a at ~0xFF & 0xFF }",
        "rule test { \
        strings: $a = { 00 00 00 00 ?? 74 65 78 74 } \
        condition: $a at 308}",
        "rule test { strings: $a = \"ssi\" condition: @a == 2 }",
        "rule test { strings: $a = \"ssi\" condition: @a == @a[1] }",
        "rule test { strings: $a = \"ssi\" condition: @a[2] == 5 }",
        "rule test { strings: $a = /m.*?ssi/ condition: !a == 5 }",
        "rule test { strings: $a = /m.*?ssi/ condition: !a[1] == 5 }",
        "rule test { strings: $a = /m.*ssi/ condition: !a == 8 }",
        "rule test { strings: $a = /m.*ssi/ condition: !a[1] == 8 }",
        "rule test { strings: $a = /ssi.*ppi/ condition: !a[1] == 9 }",
        "rule test { strings: $a = /ssi.*ppi/ condition: !a[2] == 6 }",
        "rule test { strings: $a = { 6D [1-3] 73 73 69 } condition: !a == 5}",
        "rule test { strings: $a = { 6D [-] 73 73 69 } condition: !a == 5}",
        "rule test { strings: $a = { 6D [-] 70 70 69 } condition: !a == 11}",
        "rule test { strings: $a = { 6D 69 73 73 [-] 70 69 } "
        "condition: !a == 11}",
        "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" "
        "condition: any of them }",
        "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" "
        "condition: 1 of them }",
        "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" "
        "condition: 2 of them }",
        "rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\""
        "condition: any of ($a*, $b*) }",
        "rule test { \
         strings: \
           $ = /abc/ \
           $ = /def/ \
           $ = /ghi/ \
         condition: \
           for any of ($*) : ( for any i in (1..#): (uint8(@[i] - 1) == 0x00) )\
       }",
      "rule test { \
        strings: \
          $a = \"ssi\" \
          $b = \"mis\" \
          $c = \"oops\" \
        condition: \
          all of them \
      }",
      "rule test { condition: all of ($a*) }",

      "rule test { condition: all of them }",
        "rule test { \
        strings: \
          $a = \"ssi\" \
        condition: \
          for all i in (1..#a) : (@a[i] >= 2 and @a[i] <= 5) \
      }",
      "rule test { \
        strings: \
          $a = \"ssi\" \
          $b = \"mi\" \
        condition: \
          for all i in (1..#a) : ( for all j in (1..#b) : (@a[i] >= @b[j])) \
      }",
        "rule test { \
        strings: \
        $a = \"ssi\" \
        condition: \
        for all i in (1..#a) : (@a[i] == 5) \
        }",
        "rule test { strings: $a = /ssi/ condition: $a }",
        "rule test { strings: $a = /ssi(s|p)/ condition: $a }",
        "rule test { strings: $a = /ssim*/ condition: $a }",
        "rule test { strings: $a = /ssa?/ condition: $a }",
        "rule test { strings: $a = /Miss/ nocase condition: $a }",
        "rule test { strings: $a = /(M|N)iss/ nocase condition: $a }",
        "rule test { strings: $a = /[M-N]iss/ nocase condition: $a }",
        "rule test { strings: $a = /(Mi|ssi)ssippi/ nocase condition: $a }",
        "rule test { strings: $a = /ppi\\tmi/ condition: $a }",
        "rule test { strings: $a = /ppi\\.mi/ condition: $a }",
        "rule test { strings: $a = /^mississippi/ fullword condition: $a }",
        "rule test { strings: $a = /mississippi.*mississippi$/s "
        "condition: $a }",
        "rule test { strings: $a = /^ssi/ condition: $a }",
        "rule test { strings: $a = /ssi$/ condition: $a }",
        "rule test { strings: $a = /ssissi/ fullword condition: $a }",
        "rule test { strings: $a = /^[isp]+/ condition: $a }",
        "rule test { \
        strings: $a = { 6a 2a 58 c3 } \
        condition: $a at entrypoint }",
        "rule test { \
        strings: $a = { b8 01 00 00 00 bb 2a } \
        condition: $a at entrypoint }",

      "rule test { \
        strings: $a = { b8 01 00 00 00 bb 2a } \
        condition: $a at entrypoint }",
        "rule test { condition: entrypoint >= 0 }",
    ]

    def normalize_rule(self, rule):
        """Approximate match removing whitespace."""
        rule = pyparsing.cppStyleComment.suppress().transformString(rule)
        return rule.replace("\n", "").replace(" ", "")

    def testParser(self):
        for rule in self.rules:
            parsed = yara_support.parse_yara_to_ast(rule)
            self.assertTrue(len(parsed) > 0)

            # Now check to make sure that the reconstructed rule is the same as
            # the original rule. We do not preserve comments though.
            self.assertEqual(self.normalize_rule(rule),
                             self.normalize_rule(
                                 yara_support.ast_to_yara(parsed)))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
