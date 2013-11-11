/*
  This module does absolutely nothing at all. We just build it with debugging
  symbols and then read the DWARF symbols from it.  */
#include <linux/module.h>

#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/utsname.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/udp.h>
#include <asm/alternative.h>
#include <linux/mount.h>
#include <linux/inetdevice.h>
#include <linux/fdtable.h>
#include <linux/elf.h>
#include <net/ip_fib.h>
#include <net/af_unix.h>


struct uts_namespace uts_namespace;
struct sock sock;
struct inet_sock inet_sock;
struct vfsmount vfsmount;
struct in_device in_device;
struct fib_table fib_table;
struct unix_sock unix_sock;

/* Elf structures. We use the names from the ELF standard:

http://downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf
*/
Elf64_Ehdr A1;
Elf64_Shdr A2;
Elf64_Sym A3;
Elf64_Rel A4;
Elf64_Rela A5;
Elf64_Phdr A6;
Elf64_Dyn A7;
Elf64_Nhdr A8;


/********************************************************************
The following structs are not defined in headers, so we cant import
them. Hopefully they dont change too much.
*********************************************************************/

#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <linux/compiler.h>

#define EMBEDDED_HASH_SIZE (L1_CACHE_BYTES / sizeof(struct hlist_head))

#define __rcu

struct fn_zone {
  struct fn_zone     *fz_next;       /* Next not empty zone  */
  struct hlist_head  *fz_hash;       /* Hash table pointer   */
  seqlock_t               fz_lock;
  u32                     fz_hashmask;    /* (fz_divisor - 1)     */
  u8                      fz_order;       /* Zone order (0..32)   */
  u8                      fz_revorder;    /* 32 - fz_order        */
  __be32                  fz_mask;        /* inet_make_mask(order) */

  struct hlist_head       fz_embedded_hash[EMBEDDED_HASH_SIZE];

  int                     fz_nent;        /* Number of entries    */
  int                     fz_divisor;     /* Hash size (mask+1)   */
} fn_zone;

struct fn_hash {
  struct fn_zone    *fn_zones[33];
  struct fn_zone    *fn_zone_list;
} fn_hash;


struct rt_hash_bucket {
  struct rtable __rcu     *chain;
} rt_hash_bucket;
