from distutils.core import setup, Extension

pyxpress = Extension('pyxpress',
                     sources = ['pyxpress.c'])

setup (name = 'PyXpress',
       version = '1.0',
       description = 'An implementation of xpress decompression algorithm in c.',
       ext_modules = [pyxpress])
