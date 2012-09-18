#!/bin/bash
# Script to build the kernel extension (kext) and osxpmem tool.
# Will create a tar archive for deployment.

# exit on error
set -e

# Temporary path to build the bundle.
# Must be on a local filesystem, NFS will break permissions
TMP_PATH=/tmp/pmem.$$

BUNDLE_NAME=OSXPMem
ARCHIVE_NAME=OSXPMem.tar.gz
BUILD_DIR=`pwd`/build

echo "creating temporary build directory $TMP_PATH"
(umask 077 && mkdir $TMP_PATH) || exit 1

echo "building modules"
make

echo "packaging bundle"
mkdir $TMP_PATH/$BUNDLE_NAME
cp -r $BUILD_DIR/pmem.kext $TMP_PATH/$BUNDLE_NAME/pmem.kext
cp $BUILD_DIR/osxpmem $TMP_PATH/$BUNDLE_NAME/osxpmem
cp $BUILD_DIR/../README $TMP_PATH/$BUNDLE_NAME/README

echo "adjusting permissions"
sudo chown -R root:wheel $TMP_PATH/$BUNDLE_NAME/README
sudo chown -R root:wheel $TMP_PATH/$BUNDLE_NAME/osxpmem
sudo chown -R root:wheel $TMP_PATH/$BUNDLE_NAME/pmem.kext
sudo chmod 550 $TMP_PATH/$BUNDLE_NAME/osxpmem
sudo chmod 550 $TMP_PATH/$BUNDLE_NAME/pmem.kext

echo "testing kext"
# Test it to make sure it is loadable before packaging it
sudo kextutil -t -n $TMP_PATH/$BUNDLE_NAME/pmem.kext
cd $TMP_PATH

echo "creating archive $ARCHIVE_NAME"
sudo tar czf $ARCHIVE_NAME $BUNDLE_NAME
cp $ARCHIVE_NAME $BUILD_DIR

echo "cleaning up tmp"
sudo rm -rf $TMP_PATH
