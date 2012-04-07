import copy

## The following is a conversion of basic C99 types to python struct
## format strings. NOTE: since volatility is analysing images which
## are not necessarily the same bit size as the currently running
## platform you may not use platform specific format specifiers here
## like l or L - you must use i or I.

generic_native_types = {
    'int' : ['NativeType', dict(format_string='<i')],
    'long': ['NativeType', dict(format_string='<i')],
    'unsigned long' : ['NativeType', dict(format_string='<I')],
    'unsigned int' : ['NativeType', dict(format_string='<I')],
    'char' : ['NativeType', dict(format_string='<c')],
    'unsigned char' : ['NativeType', dict(format_string='<B')],
    'unsigned short int' : ['NativeType', dict(format_string='<H')],
    'unsigned short' : ['NativeType', dict(format_string='<H')],
    'unsigned be short' : ['NativeType', dict(format_string='>H')],
    'short' : ['NativeType', dict(format_string='<h')],
    'long long' : ['NativeType', dict(format_string='<q')],
    'unsigned long long' : ['NativeType', dict(format_string='<Q')],
    }

x86_native_types = {
    'address' : ['NativeType', dict(format_string='<I')],
    }

x64_native_types = {
    'address' : ['NativeType', dict(format_string='<Q')],
    }
