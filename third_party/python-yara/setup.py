#
# Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys
from setuptools import setup, Extension
import os

args = sys.argv[1:]
macros = []

if '--with-profiling' in args:
  macros.append(('PROFILING_ENABLED','1'))
  args.remove('--with-profiling')


def get_sources(source):
  result = []
  exclusions = set("cuckoo.c magic.c".split())
  for directory, _, files in os.walk(source):
    for x in files:
      if x.endswith(".c") and x not in exclusions:
        result.append(os.path.join(directory, x))

  return result

sources = ["yara/yara-python/yara-python.c"]
sources += get_sources("yara/libyara/")

setup(script_args=args,
      name='yara-python',
      version='3.4.0',
      author='Victor M. Alvarez',
      author_email='plusvic@gmail.com;vmalvarez@virustotal.com',
      data_files=[
        "config.h",
      ],
      ext_modules=[Extension(
        name='yara',
        sources=sources,
        libraries = ['ssl',  'crypt'],
        include_dirs=[
          'yara/yara-python',
          'yara/libyara/include',
          'yara/libyara/',
          'yara/',
          '.',
        ],
        define_macros=macros,
        extra_compile_args=['-std=gnu99']
    )])
