from volatility import obj

## The following is a conversion of basic C99 types to python struct
## format strings. NOTE: since volatility is analysing images which
## are not necessarily the same bit size as the currently running
## platform you may not use platform specific format specifiers here
## like l or L - you must use i or I.

generic_native_types = {
    'int' : obj.Curry(obj.NativeType, theType='int', format_string='<i'),
    'long': obj.Curry(obj.NativeType, theType='long', format_string='<i'),
    'unsigned long' : obj.Curry(obj.NativeType, theType='unsigned long', format_string='<I'),
    'unsigned int' : obj.Curry(obj.NativeType, theType='unsigned int', format_string='<I'),
    'char' : obj.Curry(obj.NativeType, theType='char', format_string='<c'),
    'byte' : obj.Curry(obj.NativeType, theType='byte', format_string='<b'),
    'unsigned char' : obj.Curry(obj.NativeType, theType='unsigned char', format_string='<B'),
    'unsigned short int' : obj.Curry(obj.NativeType, theType='unsigned short int', format_string='<H'),
    'unsigned short' : obj.Curry(obj.NativeType, theType='unsigned short', format_string='<H'),
    'unsigned be short' : obj.Curry(obj.NativeType, theType='unsigned be short', format_string='>H'),
    'unsigned be int' : obj.Curry(obj.NativeType, theType='unsigned be int', format_string='>I'),
    'short' : obj.Curry(obj.NativeType, theType='short', format_string='<h'),
    'long long' : obj.Curry(obj.NativeType, theType='long long', format_string='<q'),
    'unsigned long long' : obj.Curry(obj.NativeType, theType='unsigned long long', format_string='<Q'),
    }

# These are aliases for the same things
for old, new in [['unsigned long long', 'long long unsigned int'],
                 ['unsigned short', 'short unsigned int'],
                 ]:
    generic_native_types[new] = generic_native_types[old]



x86_native_types = {
    'address' : obj.Curry(obj.NativeType, theType='address', format_string='<I'),
    }

x64_native_types = {
    'address' : obj.Curry(obj.NativeType, theType='address', format_string='<Q'),
    }
