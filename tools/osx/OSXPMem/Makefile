# Copyright 2012 Google Inc. All Rights Reserved.
# Author: Johannes Stüttgen (johannes.stuettgen@gmail.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

BUILDDIR=./build
KEXT_BUNDLE_NAME=pmem
PLIST_PATH=$(BUILDDIR)/$(KEXT_BUNDLE_NAME).kext/Contents/
KEXT_PATH=$(PLIST_PATH)/MacOS

SDK_PATH=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.7.sdk
FRAMEWORK_PATH=$(SDK_PATH)/System/Library/Frameworks/

KEXT_SRC=pmem/pmem.cpp pmem/pmem.h pmem/pmem_ioctls.h pmem/Info.plist \
	 pmem/pmem_info.c
IMAGER_SRC=imager/imager.c imager/imager.h pmem/pmem_ioctls.h
IMAGER_TEST_SRC=test/utest.h test/imager_test.c \
		test/imager_test_mock_api.h
IMAGER_MOCK_FS_SRC=test/imager_test_mock_fs.h test/imager_test_mock_fs.c \
	           test/imager_test_mock_api.h
TEST_IMAGES=test/test_image_elf.dump test/test_image_raw.dump \
	    test/test_image_mach.dump

CC=/usr/bin/gcc
CXX=/usr/bin/g++
ARCH=x86_64
CFLAGS=-std=gnu99 -Wall
OSX_MIN_VERSION=10.7

IMAGER_FRAMEWORKS=-framework IOKit -framework CoreFoundation

KEXT_INCLUDES=-I$(FRAMEWORK_PATH)/Kernel.framework/PrivateHeaders \
	      -I$(FRAMEWORK_PATH)/Kernel.framework/Headers \
	      -I$(FRAMEWORK_PATH)/IOKit.framework/Headers

KEXT_CXX_FLAGS=-x c++ -arch $(ARCH) -fmessage-length=0 -pipe -nostdinc \
	       -fno-builtin -Wno-trigraphs -fno-exceptions -fno-rtti \
	       -fcheck-new -force_cpusubtype_ALL -msoft-float -Os -fno-common \
	       -mkernel -finline -fno-keep-inline-functions -Wreturn-type \
	       -Wunused-variable -Wuninitialized -Wshorten-64-to-32 \
	       -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT \
	       -fapple-kext -fasm-blocks \
	       -mmacosx-version-min=$(OSX_MIN_VERSION) -gdwarf-2

INFO_CXX_FLAGS=-x c -arch $(ARCH) -fmessage-length=0 -pipe -nostdinc \
		-std=gnu99 -fno-builtin -Wno-trigraphs -force_cpusubtype_ALL \
		-msoft-float -Os -fno-common -mkernel -finline \
		-fno-keep-inline-functions -Wreturn-type -Wunused-variable \
		-Wuninitialized -Wshorten-64-to-32 -DKERNEL -DKERNEL_PRIVATE \
		-DDRIVER_PRIVATE -DAPPLE -DNeXT \
		-fasm-blocks -mmacosx-version-min=$(OSX_MIN_VERSION) -gdwarf-2

KEXT_LINKER_FLAGS=-lcpp_kext -Xlinker -kext -nostdlib \
		  -lkmodc++ $(BUILDDIR)/pmem_info.o -lkmod -lcc_kext

BUILD_KEXT=$(KEXT_CXX_FLAGS) \
	   -isysroot $(SDK_PATH) \
	   $(KEXT_INCLUDES) \
	   -c ./pmem/pmem.cpp \
	   -o $(BUILDDIR)/pmem.o

BUILD_KEXT_INFO=$(INFO_CXX_FLAGS) -isysroot $(SDK_PATH) \
		-I$(FRAMEWORK_PATH)/Kernel.framework/PrivateHeaders \
		-I$(FRAMEWORK_PATH)/Kernel.framework/Headers \
		-c ./pmem/pmem_info.c \
		-o $(BUILDDIR)/pmem_info.o

LINK_KEXT=-arch $(ARCH) -isysroot $(SDK_PATH) $(KEXT_LINKER_FLAGS)\
	  -filelist $(BUILDDIR)/pmem.LinkFileList \
	  -mmacosx-version-min=$(OSX_MIN_VERSION) \
	  -o $(BUILDDIR)/pmem

.PHONY: all imager kext prepare_test_images tests run_tests kext_bundle clean

all: clean imager kext kext_bundle

imager: $(BUILDDIR)/osxpmem

kext: $(BUILDDIR)/pmem

tests: $(BUILDDIR)/imager_mocked.o $(BUILDDIR)/imager_test

prepare_test_images: test/test_images.tar.gz
	@echo
	@if [ ! -f test/test_image_raw.dump ]; then \
		echo "extracting test images"; \
		tar xzvf test/test_images.tar.gz --directory test; \
	fi

run_tests: tests prepare_test_images
	@echo "running tests:"
	@$(BUILDDIR)/imager_test

kext_bundle: pmem/Info.plist $(BUILDDIR)/pmem
	@echo "creating bundle for kext"
	@mkdir -p $(KEXT_PATH)
	@cp pmem/Info.plist $(PLIST_PATH)/Info.plist
	@cp $(BUILDDIR)/pmem $(KEXT_PATH)/pmem
	@rm $(BUILDDIR)/pmem

$(BUILDDIR)/pmem: $(KEXT_SRC)
	@echo "building kext"
	@echo "$(BUILDDIR)/pmem.o" > $(BUILDDIR)/pmem.LinkFileList
	@$(CXX) $(BUILD_KEXT)
	@$(CC) $(BUILD_KEXT_INFO)
	@$(CXX) $(LINK_KEXT)

$(BUILDDIR)/osxpmem: $(IMAGER_SRC)
	@echo "building imager"
	@$(CC) $(CFLAGS) -o $(BUILDDIR)/osxpmem \
	       -isysroot $(SDK_PATH) \
	       -mmacosx-version-min=$(OSX_MIN_VERSION) \
	       imager/imager.c $(IMAGER_FRAMEWORKS)

$(BUILDDIR)/imager_mocked.o: $(IMAGER_SRC)
	@echo "building mocked imager"
	@$(CC) -c $(CFLAGS) -ggdb -DPMEM_IMAGER_TEST \
	       -o $(BUILDDIR)/imager_mocked.o imager/imager.c

$(BUILDDIR)/imager_mock_fs.o: $(IMAGER_MOCK_FS_SRC)
	@echo "building mock filesystem"
	@$(CC) -c $(CFLAGS) -ggdb -o $(BUILDDIR)/imager_mock_fs.o \
	       test/imager_test_mock_fs.c

$(BUILDDIR)/imager_test: $(BUILDDIR)/imager_mock_fs.o \
	                 $(BUILDDIR)/imager_mocked.o $(IMAGER_TEST_SRC)
	@echo "building imager tests"
	@$(CC) $(CFLAGS) -o $(BUILDDIR)/imager_test test/imager_test.c \
	       $(BUILDDIR)/imager_mocked.o $(BUILDDIR)/imager_mock_fs.o \
	       $(IMAGER_FRAMEWORKS) -ggdb

clean:
	@if [ ! -d $(BUILDDIR) ]; then       \
		mkdir $(BUILDDIR);           \
		echo "creating $(BUILDDIR)"; \
	else                                 \
		echo "cleaning $(BUILDDIR)"; \
		rm -rf $(BUILDDIR)/*;        \
	fi
