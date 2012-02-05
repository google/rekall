#!python
"""This is the user space program which is required for dumping images using the
win32dd driver.
"""
__author__ = "Michael Cohen <scudette@gmail.com>"

import win32service
import win32file
import struct
import sys
import os
import time
import optparse

parser = optparse.OptionParser()
parser.add_option("-d", "--driver",
                  help="The driver location (win32dd.sys)", metavar="FILE")

parser.add_option("-f", "--file", dest="filename",
                  help="write image to FILE", metavar="FILE")

parser.add_option("-n", "--name", default="win32dd",
                  help="The name of the device.")


def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType<<16) | (Access << 14) | (Function << 2) | Method

# IOCTLS for interacting with the driver.
RAW_DUMP = CTL_CODE(0x22, 0x1, 0, 3)
INFO_IOCTRL = CTL_CODE(0x22, 0x100, 0, 3)

class Image(object):
    """This class abstracts the image."""
    buffer_size = 1024 * 1024

    def __init__(self, fd):
        self.fd = fd
        result = win32file.DeviceIoControl(self.fd, INFO_IOCTRL, "", 1024, None)
        fmt_string = "QQl"
        self.cr3, self.kpcr, number_of_runs = struct.unpack_from(fmt_string, result)

        self.runs = []
        offset = struct.calcsize(fmt_string)
        for x in range(number_of_runs):
            self.runs.append(struct.unpack_from("QQ", result, x * 16 + offset))

    # Note that writing the image from kernel space is deprecated and will be
    # removed soon.
    def DumpRawFile(self, output_filename):
        """Dump the image from kernel space. (DEPRECATED)."""
        nt_path = "\\??\\" + output_filename
        win32file.DeviceIoControl(self.fd, RAW_DUMP,
                                  nt_path.encode("utf-16le"), 4, None)

    def DumpWithRead(self, output_filename):
        """Read the image and write all the data to a raw file."""
        with open(output_filename, "wb") as outfd:
            offset = 0
            end = self.runs[-1][0] + self.runs[-1][1]
            print "Imaging %s bytes with buffer_size %s." % (end, self.buffer_size)

            for offset in range(0, end, self.buffer_size):
                win32file.SetFilePointer(self.fd, offset, 0)
                _, data = win32file.ReadFile(self.fd, self.buffer_size)
                outfd.write(data)
                sys.stdout.write(".")
                sys.stdout.flush()


def main():
    """Load the driver and image the memory."""
    # Check the driver is somewhere
    if not FLAGS.driver or not os.access(FLAGS.driver, os.R_OK):
        print "You must specify a valid driver file."
        sys.exit(-1)

    # Must have absolute path here.
    driver = os.path.join(os.getcwd(), FLAGS.driver)
    hScm = win32service.OpenSCManager(
        None, None, win32service.SC_MANAGER_CREATE_SERVICE)

    try:
        hSvc = win32service.CreateService(
            hScm, FLAGS.name, FLAGS.name,
            win32service.SERVICE_ALL_ACCESS,
            win32service.SERVICE_KERNEL_DRIVER,
            win32service.SERVICE_DEMAND_START,
            win32service.SERVICE_ERROR_IGNORE,
            driver,
            None, 0, None, None, None)
    except win32service.error, e:
        print e
        hSvc = win32service.OpenService(hScm, FLAGS.name,
                                        win32service.SERVICE_ALL_ACCESS)

    # Make sure the service is stopped.
    try:
        win32service.ControlService(hSvc, win32service.SERVICE_CONTROL_STOP)
    except win32service.error:
        pass

    win32service.StartService(hSvc, [])
    try:
        fd = win32file.CreateFile(
            "\\\\.\\" + FLAGS.name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL,
            None)
        try:
            t = time.time()
            image = Image(fd)
            print "Imaging to %s" % FLAGS.filename
            image.DumpWithRead(FLAGS.filename)
            print "\nCompleted in %s seconds" % (time.time() - t)
        finally:
            win32file.CloseHandle(fd)
    finally:
        try:
            win32service.ControlService(hSvc, win32service.SERVICE_CONTROL_STOP)
        except win32service.error:
            pass
        win32service.DeleteService(hSvc)
        win32service.CloseServiceHandle(hSvc)

if __name__ == "__main__":
    (FLAGS, args) = parser.parse_args()
    main()
