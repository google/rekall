/*
  This module does absolutely nothings at all. We just build it with debugging
symbols and then read the DWARF symbols from it.
*/
#include "version.h"

#include <linux/module.h>

#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/utsname.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <asm/alternative.h>



struct uts_namespace uts_namespace;
struct sock sock;
struct inet_sock inet_sock;
