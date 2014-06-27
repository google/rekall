#define _BSD_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "../elfrelink/elf_object.h"
#include "lkm_control.h"
#include "../log/log.h"

#define KLOGCTL_READ 3
#define KLOGCTL_GETSIZE 10

static const char *devices_path = "/proc/devices";

// `man init_module` = "Glibc does not provide a wrapper for these system calls"
// Note: man is lying ;)
extern long init_module(void *, unsigned long, const char *);
extern long delete_module(const char *, int flags);

// Scans backwards in a string and finds the next '\n'
// Allows to traverse a string line by line backwards.
//
// Args:
//  string: the string to search in
//  line: pointer of the character in the string to start in
//
// Returns:
//  Pointer to the first Character in the previous line,
//  If no previous line is found this is == string.
char *get_line_start(char *string, char *pos) {
  // line must be inside string
  if (pos <= string) {
    return string;
  }
  // now scan backwards until we find a newline
  while (pos > string) {
    pos--;
    if (*pos == '\n') {
      // We found the line terminator of the previous line,
      // return the next char which is the first of this line
      return ++pos;
    }
  }
  // If we never found '\n' this must be the first line in the string
  return string;
}

// remove any trailing \n character and end string at line end
void chomp(char *string) {
  size_t len = strlen(string);

  for (size_t i = 0; i < len; i++) {
    if (string[i] == '\n') {
      string[i] = '\0';
      break;
    }
  }
}

// Parses the kernel debug buffer and finds pmems major number
int pmem_get_major(int *major) {
  FILE *fp;
  char pmem_line[BUFSIZ];

  log_print(LL_DBG, "Getting major version");
  if ((fp = fopen(devices_path, "r")) == NULL) {
    log_print(LL_ERR, "Can't open device file '%s'", devices_path);
    return EXIT_FAILURE;
  }
  // Traverse the devices file and look for pmems major number
  while (fgets(pmem_line, sizeof(pmem_line), fp) != NULL) {
    log_print(LL_DBG, "scanning device file line: %s", pmem_line);
    if (strstr(pmem_line, " pmem") != NULL) {
      if (sscanf(pmem_line, "%d pmem", major) == 1) {
        log_print(LL_DBG, "Found pmem major: %d", *major);
        return EXIT_SUCCESS;
      }
    }
  }
  log_print(LL_ERR, "pmem major number could not be found");
  return EXIT_FAILURE;
}

// Creates a device file with a drivers major number and minor 0
int pmem_mknod(char *path, int major) {
  dev_t dev = makedev(major, 0);

  log_print(LL_DBG, "Making device node at %s for major %d", path, major);
  if (mknod(path, S_IFCHR | 0400, dev) != 0) {
    log_print(LL_ERR, "Failed to create device file for major %d", major);
    perror("[-] error: ");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Removes the device file for a module
int pmem_rmnod(char *name) {
  char dev_path[256];

  strcpy(dev_path, "/dev/");
  strncat(dev_path, name, sizeof(dev_path) - strlen(dev_path));

  if (unlink(dev_path) != 0) {
    log_print(LL_ERR, "Failed to remove device file %s", dev_path);
    perror("[-] error: ");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Calls delete_module to remove a module from the kernel
int unload_module(char *name) {
  // We don't care if this doesn't work, just try to clean up
  pmem_rmnod(name);
  // now that the device node should be gone we can unload
  if (delete_module(name, O_NONBLOCK) != 0) {
    log_print(LL_ERR, "Failed to unload module %s");
    perror("[-] error: ");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Calls init_module to load a module into the kernel
int load_module(ELF_OBJ *module, char *name) {
  int err;
  int major;
  char dev_path[256];

  if ((err = init_module(module->data, module->size, "")) != 0) {
    switch (err) {
      case ENOEXEC:
        log_print(LL_ERR, "Invalid module format");
        return EXIT_FAILURE;
      case ENOENT:
        log_print(LL_ERR, "Unknown symbol in module");
        return EXIT_FAILURE;
      case ESRCH:
        log_print(LL_ERR, "Module has wrong symbol version");
        return EXIT_FAILURE;
      case EINVAL:
        log_print(LL_ERR, "Invalid parameters");
        return EXIT_FAILURE;
      case EEXIST:
        log_print(LL_LOG, "Module already loaded");
        break;
      default:
        perror("WARNING: Module load reported unknown error, "
            "module might not work as intended, check your dmesg/syslog");
    }
  }
  log_print(LL_LOG, "Injected pmem module has been loaded");
  // Now find the major number and make a node in /dev
  if (pmem_get_major(&major) != EXIT_SUCCESS) {
    log_print(LL_ERR, "Unable to get module major number");
    return EXIT_FAILURE;
  }
  strcpy(dev_path, "/dev/");
  strncat(dev_path, name, sizeof(dev_path) - strlen(dev_path));
  if (pmem_mknod(dev_path, major) != EXIT_SUCCESS) {
    log_print(LL_ERR, "Unable to create device node %s", dev_path);
    goto error;
  }
  log_print(LL_LOG, "Created device node %s", dev_path);
  return EXIT_SUCCESS;

error:
  if (unload_module(name) != EXIT_SUCCESS) {
    log_print(LL_ERR, "Unable to unload module %s", name);
  }
  return EXIT_FAILURE;
}


