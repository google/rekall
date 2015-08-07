# Fix bugs in dependent libraries.

try:
    from ctypes import *
    from distorm3 import _Value, _OffsetType, _Operand
    import distorm3

    class _DInst (Structure):
        _fields_ = [
            ('imm', _Value),
            ('disp', c_uint64),    # displacement. size is according to dispSize
            ('addr',  _OffsetType),
            ('flags',  c_uint16), # -1 if invalid. See C headers for more info
            ('unusedPrefixesMask', c_uint16),
            ('usedRegistersMask', c_uint32), # used registers mask.
            ('opcode', c_uint16),  # look up in opcode table
            ('ops', _Operand*4),
            ('size', c_ubyte),
            ('segment', c_ubyte), # -1 if unused. See C headers for more info
            ('base', c_ubyte),    # base register for indirections
            ('scale', c_ubyte),   # ignore for values 0, 1 (other valid values - 2,4,8)
            ('dispSize', c_ubyte),
            ('meta', c_ubyte), # meta flags - instruction set class, etc. See C headers again...
            ('modifiedFlagsMask', c_uint16), # CPU modified (output) flags by instruction.
            ('testedFlagsMask', c_uint16), # CPU tested (input) flags by instruction.
            ('undefinedFlagsMask', c_uint16) # CPU undefined flags by instruction.
            ]

    usedRegistersMask = distorm3._DInst._fields_[5]
    if usedRegistersMask == ("usedRegistersMask", distorm3.c_uint16):
        distorm3._DInst = _DInst

except ImportError:
    pass
