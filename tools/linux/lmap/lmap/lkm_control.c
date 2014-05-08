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
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Removes a device file from the file system
int pmem_rmnod(char *path) {
  if (unlink(path) != 0) {
    log_print(LL_ERR, "Failed to remove device file %s", path);
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Calls delete_module to remove a module from the kernel
int unload_module(char *name) {
  if (delete_module(name, O_NONBLOCK) != 0) {
    log_print(LL_ERR, "Failed to unload module %s");
    perror("unload error: ");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Calls init_module to load a module into the kernel
int load_module(ELF_OBJ *module) {
  int err;

  if ((err = init_module(module->data, module->size, "")) != 0) {
    switch (err) {
      case ENOEXEC:
        log_print(LL_ERR, "Invalid module format");
        break;
      case ENOENT:
        log_print(LL_ERR, "Unknown symbol in module");
        break;
      case ESRCH:
        log_print(LL_ERR, "Module has wrong symbol version");
        break;
      case EINVAL:
        log_print(LL_ERR, "Invalid parameters");
        break;
      default:
        perror("[-] Failed to load module: ");
    }
    return EXIT_FAILURE;
  } else {
    log_print(LL_LOG, "Injected pmem module has been loaded");
  }
  return EXIT_SUCCESS;
}


