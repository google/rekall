# Rekall Layout Expert

Live Memory analysis on the Linux platform has traditionally been difficult to
perform. Memory analysis requires precise knowledge of struct layout information
in memory, usually obtained through debugging symbols generated at compile
time. The Linux kernel is however, highly configurable, implying that debugging
information is rarely applicable to systems other than the ones that generated
it. For incident response applications, obtaining the relevant debugging
information is currently a slow and manual process, limiting its usefulness in
rapid triaging.

## How do we analyze Linux systems right now?

The current process for generating a Rekall profile for a Linux system is
tedious:

1) You must find and install the kernel headers package for the same kernel as
the running kernel (for example `apt-get install
linux-headers-3.16.0-39-generic`).

2) Then you need to build a kernel module (`rekall/tools/linux/module.c`) on
that system to generate the debug kernel module `module_dwarf.ko`.

3) Finally on a system with Rekall installed, one needs to convert this to a
Rekall profile (using `rekall convert_profile 4.2.0-generic.zip
4.2.0-generic.json` for example).

This is hard to do in an incident response situation. Sometimes servers do not
have the required compilers, kernel headers etc. This is especially hard if the
kernel was cusom made. In that case it may be difficult to even find the
required kernel headers package (it may not have even been built with the custom
kernel). In all likelyhood you may need to copy the kernel config and System.map
off the system you want to analyze to another system (with compiler tool chains
and kernel headers installed) so you can build the profile.

This logistical issue make it difficult to do Linux live memory analysis in
practice - so you end up taking a memory image of the system for later analysis
(Then you have to deal with transferring huge images around, smear and lot of
other fun problems :-).

If you really want to be prepared, you must build a huge library of kernel
profiles in advance. For each released kernel version, you need to have every
variation released by every distribution. For example in Ubuntu, there are
generic and low latency variation (e.g. `linux-headers-3.16.0-39-generic`,
`linux-headers-3.16.0-39-lowlatency`) for each minor version). You can just
forget about having custom kernels in your library because you can not predict
in advance what config parameters someone will change!

## Is there a better way?

Have you ever found yourself uttering: "I will pay someone $1000 to find a way
to do Linux Memory forensics without building a *$@#!% profile for every #@$#%@#
kernel?" - I know I have!

In a perferct world, we would just run Rekall on any Linux system, point it at
`/proc/kcore` or `/dev/pmem` and just go without worrying about building
profiles! That would be nice.

We are not quite there, but almost :-). The Layout Expert is the small step
forward. The process using the Layout Expect is much simpler:

1) On the system you want to analyze, run the Layout Expert which will download
a single Pre-AST file for every kernel version (regardless of kernel
configuration, distribution flavour etc.).

2) Then launch the layout expert, providing it the local system's config file and
System.map:

```
$ layout_tool make_profile --config_file_path boot/config-4.2.02.0.smp \
    --system boot/System.map-4.2.02.0.smp pre_ast_4.2.0-22.json profile.json

2016-01-23 09:44:29,416 INFO     LOADING PREPROCESSOR AST FROM: pre_ast_4.2.0-22.json
2016-01-23 09:44:34,494 INFO     DONE
2016-01-23 09:44:34,495 INFO     LINKING INCLUDES
2016-01-23 09:44:34,937 INFO     LINKED
2016-01-23 09:44:34,937 INFO     EXTRACTING CONFIG FLAGS
2016-01-23 09:44:34,994 INFO     EXTRACTED
2016-01-23 09:44:35,108 INFO     PREPROCESSING
2016-01-23 09:44:50,856 INFO     PREPROCESSED
2016-01-23 09:44:50,856 INFO     Completed preprocessing pre-ast in 16 Seconds
2016-01-23 09:44:50,856 INFO     GENERATING PURE C FILE
2016-01-23 09:44:53,047 INFO     GENERATED
2016-01-23 09:44:53,048 INFO     Completed generating pure C file in 2 Seconds
2016-01-23 09:44:53,048 INFO     TRIMMING C FILE
2016-01-23 09:45:14,340 INFO     Completed trimming C file in 21 Seconds
2016-01-23 09:45:14,341 INFO     TRIMMED C FILE
2016-01-23 09:45:14,354 INFO     PARSING STRUCTS
2016-01-23 09:45:37,853 INFO     Completed parsing struct layouts in 23 Seconds
2016-01-23 09:45:37,853 INFO     PARSED
2016-01-23 09:45:37,853 INFO     GENERATING PROFILE
2016-01-23 09:45:37,949 INFO     Exporting 627 structs
2016-01-23 09:45:38,763 INFO     GENERATED
```

The Layout Expert is able to calculate the memory layout of critical kernel
structures at runtime on the target system without requiring extra tools, such
as the compiler tool-chain to be pre-installed.

## How does it work?

The main problem with memory analysis on Linux is that the Linux kernel is so
configurable and customizable. For example, in order to properly parse the
memory layout of `struct task_struct`, we can see the source:

```
struct task_struct {
        volatile long state;    /* -1 unrunnable, 0 runnable, >0 stopped */
        void *stack;
        atomic_t usage;
        unsigned int flags;     /* per process flags, defined below */
        unsigned int ptrace;

#ifdef CONFIG_SMP
        struct llist_node wake_entry;
        int on_cpu;
        struct task_struct *last_wakee;
        unsigned long wakee_flips;
        unsigned long wakee_flip_decay_ts;

        int wake_cpu;
#endif
        int on_rq;

        int prio, static_prio, normal_prio;
        unsigned int rt_priority;
        const struct sched_class *sched_class;
        struct sched_entity se;
        struct sched_rt_entity rt;
#ifdef CONFIG_CGROUP_SCHED
        struct task_group *sched_task_group;
#endif

#ifdef CONFIG_PREEMPT_NOTIFIERS
        /* list of struct preempt_notifier: */
        struct hlist_head preempt_notifiers;
#endif

....
```

Depending on kernel configuration options there will be different members
inserted in the middle of the struct - even for the same kernel version. This is
primarily why you need to compile a debug kernel module for every single kernel
configuration - even of the same version. Depending on various kernel config
options the layouts can change dramatically (sometimes if the profiles are very
close some fields will be parsed correctly by Rekall but others wont - the
familiar missing data in plugin outputs).


The Layout Expert attempts to emulate the GCC compiler chains to the extent of
being able to predict the struct layout that the compiler might decide
on. Essentially we simulate the compilation of the kernel debug module.

The GCC compiler, reads the kernel config file and then preprocesses the kernel
headers to add or remove code depending on these configuration options. In the
Layout Expert we wish to have a data structure that can be re-used for different
configurations without needing the kernel config.

Therefore, the Layout Expert first parses all the kernel headers into a
Preprocessor Abstract Syntax Tree (Pre-AST for short). The Pre-AST includes all
the possibilities of each `#ifdef` branch. This is the file which the Layout
Expert operates on.

At runtime (i.e. during system analysis), the Layout Expert combines the system
configuration with the Pre-AST to produced the Preprocessed C code. In essence,
the headers `#ifdef` directives are removed, and the different options are
combined to produce a final C file, free from preprocessing macros. In this
phase, the Layout Expert acts as a C pre-processor. The result is a huge C file
with all the code in all the headers stuck together.

Next, the Layout Expert applies trimming to this file. This is essentially a
quick once over pass to identify only structs, unions, enums and typedef
instructions. This optimization step means that we have much less code to parse
in the next step and that the code that we do need to parse is more consistent
and so easier to parse.

Finally the Layout Expert parses the structs that Rekall is actually interested
in (i.e. those structs with plugins that look at them). This parsing phase
emulates a C compiler. We then apply the GCC struct layout model to the parsed
structs in order to predict the precise memory layout of all fields in the
structs (considering attributes, e.g. ``__attribute__((packed))`,
`__attribute__((aligned(8))`).

The last step is to generate a Rekall profile ready for use.


## Preparation.

Before the profile generation can occur in the field, we need to build the
`Pre-AST` file for the specific kernel version. This is easy since it does not
require any specific configuration file or special tools (Remember that the
Pre-AST includes all branches of any `#ifdef` directives so we do not need to
evaluate any macros at this stage.).

You can use the kernel headers package for the specific kernel, or the full
kernel source. There is no need to actually compile the source (i.e. `make
depmod` etc). Note that the kernel header package does not include "private" or
non exported structs, so these will be missing from the profile, but current
Rekall does not need those.

```
$ layout_tool build_pre_ast --source_file_path ~/rekall/tools/linux/module.c \
  --linux_repository_path /usr/src/linux-headers-4.2.0-22-generic/ pre_ast_4.2.0-22.json

2016-01-23 10:38:00,493 INFO     LOADING AND PARSING HEADERS
2016-01-23 10:38:58,912 INFO     Completed built pre-ast forest in 58 Seconds
2016-01-23 10:38:58,913 INFO     LOADED AND PARSED
```

## Bugs and support

The Layout Expert is brought to you by the same people who develop Rekall, but
it is considered a separate project. It is available under an Apache license
(Check the LICENSE file). However, there is no official support or warranty; not
even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

If you think you've found a bug, please report it at:

    https://github.com/google/rekall/issues

You can also mail to the list rekall-discuss@googlegroups.com
