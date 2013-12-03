from distutils.core import setup, Extension

pysupport = Extension('volatility.support',
                      sources = ['src/support.c'],
                      extra_compile_args=["-O0"])

setup(name='support',
      version='0.5',
      description='Support clases for volatility.',
      ext_modules=[pysupport])
