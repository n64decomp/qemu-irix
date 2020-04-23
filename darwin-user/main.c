/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu-version.h"
#include <sys/syscall.h>
#include <sys/resource.h>

#include "qapi/error.h"
#include "qemu.h"
#include "qemu/path.h"
#include "qemu/config-file.h"
#include "qemu/cutils.h"
#include "qemu/help_option.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "elf.h"
#include "exec/log.h"
#include "trace/control.h"
#include "target_elf.h"

char *exec_path;

int singlestep;
static const char *filename;
static const char *argv0;
static int gdbstub_port;
static envlist_t *envlist;
static const char *cpu_model;
unsigned long mmap_min_addr;
unsigned long guest_base;
int have_guest_base;

#define EXCP_DUMP(env, fmt, ...)                                        \
do {                                                                    \
    CPUState *cs = ENV_GET_CPU(env);                                    \
    fprintf(stderr, fmt , ## __VA_ARGS__);                              \
    cpu_dump_state(cs, stderr, fprintf, 0);                             \
    if (qemu_log_separate()) {                                          \
        qemu_log(fmt, ## __VA_ARGS__);                                  \
        log_cpu_state(cs, 0);                                           \
    }                                                                   \
} while (0)

/*
 * When running 32-on-64 we should make sure we can fit all of the possible
 * guest address space into a contiguous chunk of virtual host memory.
 *
 * This way we will never overlap with our own libraries or binaries or stack
 * or anything else that QEMU maps.
 *
 * Many cpus reserve the high bit (or more than one for some 64-bit cpus)
 * of the address for the kernel.  Some cpus rely on this and user space
 * uses the high bit(s) for pointer tagging and the like.  For them, we
 * must preserve the expected address space.
 */
#ifndef MAX_RESERVED_VA
# if HOST_LONG_BITS > TARGET_VIRT_ADDR_SPACE_BITS
#  if TARGET_VIRT_ADDR_SPACE_BITS == 32 && \
      (TARGET_LONG_BITS == 32 || defined(TARGET_ABI32))
/* There are a number of places where we assign reserved_va to a variable
   of type abi_ulong and expect it to fit.  Avoid the last page.  */
#   define MAX_RESERVED_VA  (0xfffffffful & TARGET_PAGE_MASK)
#  else
#   define MAX_RESERVED_VA  (1ul << TARGET_VIRT_ADDR_SPACE_BITS)
#  endif
# else
#  define MAX_RESERVED_VA  0
# endif
#endif

/* That said, reserving *too* much vm space via mmap can run into problems
   with rlimits, oom due to page table creation, etc.  We will still try it,
   if directed by the command-line option, but not by default.  */
#if HOST_LONG_BITS == 64 && TARGET_VIRT_ADDR_SPACE_BITS <= 32
unsigned long reserved_va = MAX_RESERVED_VA;
#else
unsigned long reserved_va;
#endif

static void usage(int exitcode);

static const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *qemu_uname_release;

/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
unsigned long guest_stack_size = 8 * 1024 * 1024UL;

static int silent;

void gemu_log(const char *fmt, ...)
{
    if (!silent) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
}

/***********************************************************/
/* Helper routines for implementing atomic operations.  */

/* Make sure everything is in a consistent state for calling fork().  */
void fork_start(CPUArchState *env)
{
    start_exclusive();
    mmap_fork_start();
    qemu_mutex_lock(&tb_ctx.tb_lock);
    cpu_list_lock();
}

void fork_end(CPUArchState *env, int child)
{
    mmap_fork_end(child);
    if (child) {
        CPUState *cpu, *next_cpu, *cur_cpu = ENV_GET_CPU(env);
        /* Child processes created by fork() only have a single thread.
           Discard information about the parent threads.  */
        CPU_FOREACH_SAFE(cpu, next_cpu) {
            if (cpu != cur_cpu) {
                QTAILQ_REMOVE(&cpus, cpu, node);
            }
        }
        qemu_mutex_init(&tb_ctx.tb_lock);
        qemu_init_cpu_list();
        gdbserver_fork(cur_cpu);
        /* qemu_init_cpu_list() takes care of reinitializing the
         * exclusive state, so we don't need to end_exclusive() here.
         */
    } else {
        qemu_mutex_unlock(&tb_ctx.tb_lock);
        cpu_list_unlock();
        end_exclusive();
    }
}

/* MIPS and IRIX hack code for Darwin */
#ifdef TARGET_MIPS
#if defined(TARGET_ABI_IRIX)
/* emulating the PRDA is expensive, since for every memory access the address
 * has to be examined. Do this only if the user requires it.
 */
int irix_emulate_prda;

/* 
 * The N32 ABI takes 64 bit args and return values in a 64 bit register, while
 * the O32 ABI splits these in two 32 bit registers.
 * Map 64 bit args to 32 bits here to avoid dealing with it in the syscall code.
 * Also, a 64 bit return code in 2 32 bit registers must be recombined for N32.
 *
 * N32 uses the 64 bit syscall version if one is available (e.g. getdents64)
 * Map 32 bit system calls to the 64 bit version here as well.
 *
 * Structure/union argument passing is left aligned. In N32, an object of 32 bit
 * is in that case shifted to the upper half of the 64 bit register.
 * Thus, in the special case of semsys(SEMCTL...), the 5th argument must be
 * dealt with like a 64 bit argument in N32 for the correct value to be passed.
 */
# define SYSCALL_ARGS(n,a64,r64,s)  ((n)|(a64)<<4|((r64)<<8)|((s)<<16))
# define SYSCALL_NARGS(v)           ((v)&0xf)       /* #registers, incl. padding */
# define SYSCALL_ARG64(v)           (((v)>>4)&0xf)  /* position of 64bit arg */
# define SYSCALL_RET64(v)           (((v)>>8)&0x1)  /* returns a 64bit value */
# define SYSCALL_MAP(v)             ((v)>>16)       /* N32 32bit syscall to 64bit */
# define _      0   /* for a better overview */
# define X      8   /* place holder for "don't know" for proprietary syscalls */
static const uint32_t mips_syscall_args[] = { /* see IRIX:/usr/include/sys.s */
	SYSCALL_ARGS(8, _, _, _),                   /*   0: syscall */
	SYSCALL_ARGS(1, _, _, _),                   /*   1: exit */
	SYSCALL_ARGS(0, _, _, _),                   /*   2: fork */
	SYSCALL_ARGS(3, _, _, _),                   /*   3: read */
	SYSCALL_ARGS(3, _, _, _),                   /*   4: write */
	SYSCALL_ARGS(3, _, _, _),                   /*   5: open */
	SYSCALL_ARGS(1, _, _, _),                   /*   6: close */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(2, _, _, _),                   /*   8: creat */
	SYSCALL_ARGS(2, _, _, _),                   /*   9: link */
	SYSCALL_ARGS(1, _, _, _),                   /*  10: unlink */
	SYSCALL_ARGS(2, _, _, _),                   /*  11: execv */
	SYSCALL_ARGS(1, _, _, _),                   /*  12: chdir */
	SYSCALL_ARGS(0, _, _, _),                   /*  13: time */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(2, _, _, _),                   /*  15: chmod */
	SYSCALL_ARGS(3, _, _, _),                   /*  16: chown */
	SYSCALL_ARGS(1, _, _, _),                   /*  17: brk */
	SYSCALL_ARGS(2, _, _, _),                   /*  18: stat */
	SYSCALL_ARGS(3, _, _, TARGET_NR_lseek64),   /*  19: lseek */
	SYSCALL_ARGS(0, _, _, _),                   /*  20: getpid */
	SYSCALL_ARGS(6, _, _, _),                   /*  21: mount */
	SYSCALL_ARGS(1, _, _, _),                   /*  22: umount */
	SYSCALL_ARGS(1, _, _, _),                   /*  23: setuid */
	SYSCALL_ARGS(0, _, _, _),                   /*  24: getuid */
	SYSCALL_ARGS(1, _, _, _),                   /*  25: stime */
	SYSCALL_ARGS(4, _, _, _),                   /*  26: ptrace */
	SYSCALL_ARGS(1, _, _, _),                   /*  27: alarm */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(0, _, _, _),                   /*  29: pause */
	SYSCALL_ARGS(2, _, _, _),                   /*  30: utime */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(2, _, _, _),                   /*  33: access */
	SYSCALL_ARGS(1, _, _, _),                   /*  34: nice */
	SYSCALL_ARGS(4, _, _, _),                   /*  35: statfs */
	SYSCALL_ARGS(0, _, _, _),                   /*  36: sync */
	SYSCALL_ARGS(2, _, _, _),                   /*  37: kill */
	SYSCALL_ARGS(4, _, _, _),                   /*  38: fstatfs */
	SYSCALL_ARGS(1, _, _, _),                   /*  39: pgrpsys */
	SYSCALL_ARGS(X, _, _, _),                   /*  40: syssgi */
	SYSCALL_ARGS(1, _, _, _),                   /*  41: dup */
	SYSCALL_ARGS(0, _, _, _),                   /*  42: pipe */
	SYSCALL_ARGS(1, _, _, _),                   /*  43: times */
	SYSCALL_ARGS(4, _, _, _),                   /*  44: profil */
	SYSCALL_ARGS(1, _, _, _),                   /*  45: plock */
	SYSCALL_ARGS(1, _, _, _),                   /*  46: setgid */
	SYSCALL_ARGS(0, _, _, _),                   /*  47: getgid */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(6, _, _, _),                   /*  49: msgsys */
	SYSCALL_ARGS(4, _, _, _),                   /*  50: sysmips */
	SYSCALL_ARGS(1, _, _, _),                   /*  51: acct */
	SYSCALL_ARGS(5, _, _, _),                   /*  52: shmsys */
	SYSCALL_ARGS(5, 5, _, _),                   /*  53: semsys */
	SYSCALL_ARGS(3, _, _, _),                   /*  54: ioctl */
	SYSCALL_ARGS(3, _, _, _),                   /*  55: uadmin */
	SYSCALL_ARGS(X, _, _, _),                   /*  56: sysmp */
	SYSCALL_ARGS(3, _, _, _),                   /*  57: utssys */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(3, _, _, _),                   /*  59: execve */
	SYSCALL_ARGS(1, _, _, _),                   /*  60: umask */
	SYSCALL_ARGS(1, _, _, _),                   /*  61: chroot */
	SYSCALL_ARGS(3, _, _, _),                   /*  62: fcntl */
	SYSCALL_ARGS(2, _, _, _),                   /*  63: ulimit */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(2, _, _, _),                   /*  75: getrlimit64 */
	SYSCALL_ARGS(2, _, _, _),                   /*  76: setrlimit64 */
	SYSCALL_ARGS(2, _, _, _),                   /*  77: nanosleep */
	SYSCALL_ARGS(5, 2, 1, _),                   /*  78: lseek64 */
	SYSCALL_ARGS(1, _, _, _),                   /*  79: rmdir */
	SYSCALL_ARGS(2, _, _, _),                   /*  80: mkdir */
	SYSCALL_ARGS(3, _, _, TARGET_NR_getdents64),/*  81: getdents */
	SYSCALL_ARGS(1, _, _, _),                   /*  82: sginap */
	SYSCALL_ARGS(3, _, _, _),                   /*  83: sgikopt */
	SYSCALL_ARGS(3, _, _, _),                   /*  84: sysfs */
	SYSCALL_ARGS(4, _, _, _),                   /*  85: getmsg */
	SYSCALL_ARGS(4, _, _, _),                   /*  86: putmsg */
	SYSCALL_ARGS(3, _, _, _),                   /*  87: poll */
	SYSCALL_ARGS(3, _, _, _),                   /*  88: sigreturn */
	SYSCALL_ARGS(3, _, _, _),                   /*  89: accept */
	SYSCALL_ARGS(3, _, _, _),                   /*  90: bind */
	SYSCALL_ARGS(3, _, _, _),                   /*  91: connect */
	SYSCALL_ARGS(0, _, _, _),                   /*  92: gethostid */
	SYSCALL_ARGS(3, _, _, _),                   /*  93: getpeername */
	SYSCALL_ARGS(3, _, _, _),                   /*  94: getsockname */
	SYSCALL_ARGS(5, _, _, _),                   /*  95: getsockopt */
	SYSCALL_ARGS(2, _, _, _),                   /*  96: listen */
	SYSCALL_ARGS(4, _, _, _),                   /*  97: recv */
	SYSCALL_ARGS(6, _, _, _),                   /*  98: recvfrom */
	SYSCALL_ARGS(3, _, _, _),                   /*  99: recvmsg */
	SYSCALL_ARGS(5, _, _, _),                   /* 100: select */
	SYSCALL_ARGS(4, _, _, _),                   /* 101: send */
	SYSCALL_ARGS(3, _, _, _),                   /* 102: sendmsg */
	SYSCALL_ARGS(6, _, _, _),                   /* 103: sendto */
	SYSCALL_ARGS(1, _, _, _),                   /* 104: sethostid */
	SYSCALL_ARGS(5, _, _, _),                   /* 105: setsockopt */
	SYSCALL_ARGS(2, _, _, _),                   /* 106: shutdown */
	SYSCALL_ARGS(3, _, _, _),                   /* 107: socket */
	SYSCALL_ARGS(2, _, _, _),                   /* 108: gethostname */
	SYSCALL_ARGS(2, _, _, _),                   /* 109: sethostname */
	SYSCALL_ARGS(2, _, _, _),                   /* 110: getdomainname */
	SYSCALL_ARGS(2, _, _, _),                   /* 111: setdomainname */
	SYSCALL_ARGS(2, _, _, TARGET_NR_truncate64),/* 112: truncate */
	SYSCALL_ARGS(2, _, _, TARGET_NR_ftruncate64),/* 113: ftruncate */
	SYSCALL_ARGS(2, _, _, _),                   /* 114: rename */
	SYSCALL_ARGS(2, _, _, _),                   /* 115: symlink */
	SYSCALL_ARGS(3, _, _, _),                   /* 116: readlink */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(X, _, _, _),                   /* 119: nfssvc */
	SYSCALL_ARGS(X, _, _, _),                   /* 120: getfh */
	SYSCALL_ARGS(X, _, _, _),                   /* 121: async_daemon */
	SYSCALL_ARGS(X, _, _, _),                   /* 122: exportfs */
	SYSCALL_ARGS(2, _, _, _),                   /* 123: setregid */
	SYSCALL_ARGS(2, _, _, _),                   /* 123: setreuid */
	SYSCALL_ARGS(2, _, _, _),                   /* 125: getitimer */
	SYSCALL_ARGS(3, _, _, _),                   /* 126: setitimer */
	SYSCALL_ARGS(2, _, _, _),                   /* 127: adjtime */
	SYSCALL_ARGS(1, _, _, _),                   /* 128: gettimeofday */
	SYSCALL_ARGS(3, _, _, _),                   /* 129: sproc */
	SYSCALL_ARGS(3, _, _, _),                   /* 130: prctl */
	SYSCALL_ARGS(3, _, _, _),                   /* 131: procblk */
	SYSCALL_ARGS(5, _, _, _),                   /* 132: sprocsp */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(6, _, _, TARGET_NR_mmap64),    /* 134: mmap */
	SYSCALL_ARGS(2, _, _, _),                   /* 135: munmap */
	SYSCALL_ARGS(3, _, _, _),                   /* 136: mprotect */
	SYSCALL_ARGS(3, _, _, _),                   /* 137: msync */
	SYSCALL_ARGS(3, _, _, _),                   /* 138: madvise */
	SYSCALL_ARGS(3, _, _, _),                   /* 139: pagelock */
	SYSCALL_ARGS(0, _, _, _),                   /* 140: getpagesize */
	SYSCALL_ARGS(4, _, _, _),                   /* 141: quotactl */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(1, _, _, _),                   /* 143: getpgid */
	SYSCALL_ARGS(2, _, _, _),                   /* 144: setpgid */
	SYSCALL_ARGS(0, _, _, _),                   /* 145: vhangup */
	SYSCALL_ARGS(1, _, _, _),                   /* 146: fsync */
	SYSCALL_ARGS(1, _, _, _),                   /* 147: fchdir */
	SYSCALL_ARGS(2, _, _, TARGET_NR_getrlimit64),/* 148: getrlimit */
	SYSCALL_ARGS(2, _, _, TARGET_NR_setrlimit64),/* 149: setrlimit */
	SYSCALL_ARGS(3, _, _, _),                   /* 150: cacheflush */
	SYSCALL_ARGS(3, _, _, _),                   /* 151: cachectl */
	SYSCALL_ARGS(3, _, _, _),                   /* 152: fchown */
	SYSCALL_ARGS(2, _, _, _),                   /* 153: fchmod */
	SYSCALL_ARGS(_, _, _, _),
	SYSCALL_ARGS(4, _, _, _),                   /* 155: socketpair */
	SYSCALL_ARGS(3, _, _, _),                   /* 156: sysinfo */
	SYSCALL_ARGS(1, _, _, _),                   /* 157: uname */
	SYSCALL_ARGS(3, _, _, _),                   /* 158: xstat */
	SYSCALL_ARGS(3, _, _, _),                   /* 159: lxstat */
	SYSCALL_ARGS(3, _, _, _),                   /* 160: fxstat */
	SYSCALL_ARGS(4, _, _, _),                   /* 161: xmknod */
	SYSCALL_ARGS(4, _, _, _),                   /* 162: sigaction */
	SYSCALL_ARGS(1, _, _, _),                   /* 163: sigpending */
	SYSCALL_ARGS(3, _, _, _),                   /* 164: sigprocmask */
	SYSCALL_ARGS(1, _, _, _),                   /* 165: sigsuspend */
	SYSCALL_ARGS(3, _, _, _),                   /* 166: sigpoll */
	SYSCALL_ARGS(2, _, _, _),                   /* 167: swapctl */
	SYSCALL_ARGS(1, _, _, _),                   /* 168: getcontext */
	SYSCALL_ARGS(1, _, _, _),                   /* 169: setcontext */
	SYSCALL_ARGS(5, _, _, _),                   /* 170: waitsys */
	SYSCALL_ARGS(2, _, _, _),                   /* 171: sigstack */
	SYSCALL_ARGS(2, _, _, _),                   /* 172: sigaltstack */
	SYSCALL_ARGS(2, _, _, _),                   /* 173: sigsendset */
	SYSCALL_ARGS(2, _, _, TARGET_NR_statvfs64), /* 174: statvfs */
	SYSCALL_ARGS(2, _, _, TARGET_NR_fstatvfs64),/* 175: fstatvfs */
	SYSCALL_ARGS(5, _, _, _),                   /* 176: getpmsg */
	SYSCALL_ARGS(5, _, _, _),                   /* 177: putpmsg */
	SYSCALL_ARGS(3, _, _, _),                   /* 178: lchown */
	SYSCALL_ARGS(0, _, _, _),                   /* 179: priocntl */
	SYSCALL_ARGS(X, _, _, _),                   /* 180: ksigqueue */
	SYSCALL_ARGS(3, _, _, _),                   /* 181: readv */
	SYSCALL_ARGS(3, _, _, _),                   /* 182: writev */
	SYSCALL_ARGS(4, 2, _, _),                   /* 183: truncate64 */
	SYSCALL_ARGS(4, 2, _, _),                   /* 184: ftruncate64 */
	SYSCALL_ARGS(8, 6, _, _),                   /* 185: mmap64 */
	SYSCALL_ARGS(X, _, _, _),                   /* 186: dmi */
	SYSCALL_ARGS(6, 4, _, _),                   /* 187: pread64 */
	SYSCALL_ARGS(6, 4, _, _),                   /* 188: pwrite64 */
	SYSCALL_ARGS(1, _, _, _),                   /* 189: fdatasync */
	SYSCALL_ARGS(X, _, _, _),                   /* 190: sgifastpath */
	SYSCALL_ARGS(5, _, _, _),                   /* 191: attr_get */
	SYSCALL_ARGS(5, _, _, _),                   /* 192: attr_getf */
	SYSCALL_ARGS(5, _, _, _),                   /* 193: attr_set */
	SYSCALL_ARGS(5, _, _, _),                   /* 194: attr_setf */
	SYSCALL_ARGS(3, _, _, _),                   /* 195: attr_remove */
	SYSCALL_ARGS(3, _, _, _),                   /* 196: attr_removef */
	SYSCALL_ARGS(5, _, _, _),                   /* 197: attr_list */
	SYSCALL_ARGS(5, _, _, _),                   /* 198: attr_listf */
	SYSCALL_ARGS(4, _, _, _),                   /* 199: attr_multi */
	SYSCALL_ARGS(4, _, _, _),                   /* 200: attr_multif */
	SYSCALL_ARGS(2, _, _, _),                   /* 201: statvfs64 */
	SYSCALL_ARGS(2, _, _, _),                   /* 202: fstatvfs64 */
	SYSCALL_ARGS(2, _, _, _),                   /* 203: getmountid */
	SYSCALL_ARGS(5, _, _, _),                   /* 204: nsproc */
	SYSCALL_ARGS(3, _, _, _),                   /* 205: getdents64 */
	SYSCALL_ARGS(X, _, _, _),                   /* 206: afs_syscall */
	SYSCALL_ARGS(4, _, _, TARGET_NR_ngetdents64),/* 207: ngetdents */
	SYSCALL_ARGS(4, _, _, _),                   /* 208: ngetdents64 */
	SYSCALL_ARGS(X, _, _, _),                   /* 209: sgi_sesmgr */
	SYSCALL_ARGS(X, _, _, _),                   /* 210: pidsprocsp */
	SYSCALL_ARGS(X, _, _, _),                   /* 211: rexec */
	SYSCALL_ARGS(3, _, _, _),                   /* 212: timer_create */
	SYSCALL_ARGS(1, _, _, _),                   /* 213: timer_delete */
	SYSCALL_ARGS(4, _, _, _),                   /* 214: timer_settime */
	SYSCALL_ARGS(2, _, _, _),                   /* 215: timer_gettime */
	SYSCALL_ARGS(1, _, _, _),                   /* 216: timer_getoverrun */
	SYSCALL_ARGS(2, _, _, _),                   /* 217: sched_rr_get_interval */
	SYSCALL_ARGS(0, _, _, _),                   /* 218: sched_yield */
	SYSCALL_ARGS(1, _, _, _),                   /* 219: sched_getscheduler */
	SYSCALL_ARGS(3, _, _, _),                   /* 220: sched_setscheduler */
	SYSCALL_ARGS(2, _, _, _),                   /* 221: sched_getparam */
	SYSCALL_ARGS(2, _, _, _),                   /* 222: sched_setparam */
	SYSCALL_ARGS(2, _, _, _),                   /* 223: usync_cntl */
	SYSCALL_ARGS(5, _, _, _),                   /* 224: psema_cntl */
	SYSCALL_ARGS(X, _, _, _),                   /* 225: restartreturn */
	SYSCALL_ARGS(5, _, _, _),                   /* 226: sysget */
	SYSCALL_ARGS(3, _, _, _),                   /* 227: xpg4_recvmsg */
	SYSCALL_ARGS(X, _, _, _),                   /* 228: umfscall */
	SYSCALL_ARGS(X, _, _, _),                   /* 229: nsproctid */
	SYSCALL_ARGS(X, _, _, _),                   /* 230: rexec_complete */
	SYSCALL_ARGS(2, _, _, _),                   /* 231: xpg4_sigaltstack */
	SYSCALL_ARGS(5, _, _, _),                   /* 232: xpg4_select */
	SYSCALL_ARGS(2, _, _, _),                   /* 233: xpg4_setregid */
	SYSCALL_ARGS(2, _, _, _),                   /* 234: linkfollow */
};
// TODO: undef SYSCALL_ARGS, etc.
# else /* !defined(TARGET_ABI_IRIX)*/
#  define MIPS_SYS(name, args)        args,
#  define SYSCALL_NARGS(v)            (v)
static const uint8_t mips_syscall_args[] = {
	MIPS_SYS(sys_syscall	, 8)	/* 4000 */
	MIPS_SYS(sys_exit	, 1)
	MIPS_SYS(sys_fork	, 0)
	MIPS_SYS(sys_read	, 3)
	MIPS_SYS(sys_write	, 3)
	MIPS_SYS(sys_open	, 3)	/* 4005 */
	MIPS_SYS(sys_close	, 1)
	MIPS_SYS(sys_waitpid	, 3)
	MIPS_SYS(sys_creat	, 2)
	MIPS_SYS(sys_link	, 2)
	MIPS_SYS(sys_unlink	, 1)	/* 4010 */
	MIPS_SYS(sys_execve	, 0)
	MIPS_SYS(sys_chdir	, 1)
	MIPS_SYS(sys_time	, 1)
	MIPS_SYS(sys_mknod	, 3)
	MIPS_SYS(sys_chmod	, 2)	/* 4015 */
	MIPS_SYS(sys_lchown	, 3)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_stat */
	MIPS_SYS(sys_lseek	, 3)
	MIPS_SYS(sys_getpid	, 0)	/* 4020 */
	MIPS_SYS(sys_mount	, 5)
	MIPS_SYS(sys_umount	, 1)
	MIPS_SYS(sys_setuid	, 1)
	MIPS_SYS(sys_getuid	, 0)
	MIPS_SYS(sys_stime	, 1)	/* 4025 */
	MIPS_SYS(sys_ptrace	, 4)
	MIPS_SYS(sys_alarm	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_fstat */
	MIPS_SYS(sys_pause	, 0)
	MIPS_SYS(sys_utime	, 2)	/* 4030 */
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_access	, 2)
	MIPS_SYS(sys_nice	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4035 */
	MIPS_SYS(sys_sync	, 0)
	MIPS_SYS(sys_kill	, 2)
	MIPS_SYS(sys_rename	, 2)
	MIPS_SYS(sys_mkdir	, 2)
	MIPS_SYS(sys_rmdir	, 1)	/* 4040 */
	MIPS_SYS(sys_dup		, 1)
	MIPS_SYS(sys_pipe	, 0)
	MIPS_SYS(sys_times	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_brk		, 1)	/* 4045 */
	MIPS_SYS(sys_setgid	, 1)
	MIPS_SYS(sys_getgid	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was signal(2) */
	MIPS_SYS(sys_geteuid	, 0)
	MIPS_SYS(sys_getegid	, 0)	/* 4050 */
	MIPS_SYS(sys_acct	, 0)
	MIPS_SYS(sys_umount2	, 2)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_ioctl	, 3)
	MIPS_SYS(sys_fcntl	, 3)	/* 4055 */
	MIPS_SYS(sys_ni_syscall	, 2)
	MIPS_SYS(sys_setpgid	, 2)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_olduname	, 1)
	MIPS_SYS(sys_umask	, 1)	/* 4060 */
	MIPS_SYS(sys_chroot	, 1)
	MIPS_SYS(sys_ustat	, 2)
	MIPS_SYS(sys_dup2	, 2)
	MIPS_SYS(sys_getppid	, 0)
	MIPS_SYS(sys_getpgrp	, 0)	/* 4065 */
	MIPS_SYS(sys_setsid	, 0)
	MIPS_SYS(sys_sigaction	, 3)
	MIPS_SYS(sys_sgetmask	, 0)
	MIPS_SYS(sys_ssetmask	, 1)
	MIPS_SYS(sys_setreuid	, 2)	/* 4070 */
	MIPS_SYS(sys_setregid	, 2)
	MIPS_SYS(sys_sigsuspend	, 0)
	MIPS_SYS(sys_sigpending	, 1)
	MIPS_SYS(sys_sethostname	, 2)
	MIPS_SYS(sys_setrlimit	, 2)	/* 4075 */
	MIPS_SYS(sys_getrlimit	, 2)
	MIPS_SYS(sys_getrusage	, 2)
	MIPS_SYS(sys_gettimeofday, 2)
	MIPS_SYS(sys_settimeofday, 2)
	MIPS_SYS(sys_getgroups	, 2)	/* 4080 */
	MIPS_SYS(sys_setgroups	, 2)
	MIPS_SYS(sys_ni_syscall	, 0)	/* old_select */
	MIPS_SYS(sys_symlink	, 2)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_lstat */
	MIPS_SYS(sys_readlink	, 3)	/* 4085 */
	MIPS_SYS(sys_uselib	, 1)
	MIPS_SYS(sys_swapon	, 2)
	MIPS_SYS(sys_reboot	, 3)
	MIPS_SYS(old_readdir	, 3)
	MIPS_SYS(old_mmap	, 6)	/* 4090 */
	MIPS_SYS(sys_munmap	, 2)
	MIPS_SYS(sys_truncate	, 2)
	MIPS_SYS(sys_ftruncate	, 2)
	MIPS_SYS(sys_fchmod	, 2)
	MIPS_SYS(sys_fchown	, 3)	/* 4095 */
	MIPS_SYS(sys_getpriority	, 2)
	MIPS_SYS(sys_setpriority	, 3)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_statfs	, 2)
	MIPS_SYS(sys_fstatfs	, 2)	/* 4100 */
	MIPS_SYS(sys_ni_syscall	, 0)	/* was ioperm(2) */
	MIPS_SYS(sys_socketcall	, 2)
	MIPS_SYS(sys_syslog	, 3)
	MIPS_SYS(sys_setitimer	, 3)
	MIPS_SYS(sys_getitimer	, 2)	/* 4105 */
	MIPS_SYS(sys_newstat	, 2)
	MIPS_SYS(sys_newlstat	, 2)
	MIPS_SYS(sys_newfstat	, 2)
	MIPS_SYS(sys_uname	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4110 was iopl(2) */
	MIPS_SYS(sys_vhangup	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_idle() */
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_vm86 */
	MIPS_SYS(sys_wait4	, 4)
	MIPS_SYS(sys_swapoff	, 1)	/* 4115 */
	MIPS_SYS(sys_sysinfo	, 1)
	MIPS_SYS(sys_ipc		, 6)
	MIPS_SYS(sys_fsync	, 1)
	MIPS_SYS(sys_sigreturn	, 0)
	MIPS_SYS(sys_clone	, 6)	/* 4120 */
	MIPS_SYS(sys_setdomainname, 2)
	MIPS_SYS(sys_newuname	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* sys_modify_ldt */
	MIPS_SYS(sys_adjtimex	, 1)
	MIPS_SYS(sys_mprotect	, 3)	/* 4125 */
	MIPS_SYS(sys_sigprocmask	, 3)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was create_module */
	MIPS_SYS(sys_init_module	, 5)
	MIPS_SYS(sys_delete_module, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4130	was get_kernel_syms */
	MIPS_SYS(sys_quotactl	, 0)
	MIPS_SYS(sys_getpgid	, 1)
	MIPS_SYS(sys_fchdir	, 1)
	MIPS_SYS(sys_bdflush	, 2)
	MIPS_SYS(sys_sysfs	, 3)	/* 4135 */
	MIPS_SYS(sys_personality	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* for afs_syscall */
	MIPS_SYS(sys_setfsuid	, 1)
	MIPS_SYS(sys_setfsgid	, 1)
	MIPS_SYS(sys_llseek	, 5)	/* 4140 */
	MIPS_SYS(sys_getdents	, 3)
	MIPS_SYS(sys_select	, 5)
	MIPS_SYS(sys_flock	, 2)
	MIPS_SYS(sys_msync	, 3)
	MIPS_SYS(sys_readv	, 3)	/* 4145 */
	MIPS_SYS(sys_writev	, 3)
	MIPS_SYS(sys_cacheflush	, 3)
	MIPS_SYS(sys_cachectl	, 3)
	MIPS_SYS(sys_sysmips	, 4)
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4150 */
	MIPS_SYS(sys_getsid	, 1)
	MIPS_SYS(sys_fdatasync	, 0)
	MIPS_SYS(sys_sysctl	, 1)
	MIPS_SYS(sys_mlock	, 2)
	MIPS_SYS(sys_munlock	, 2)	/* 4155 */
	MIPS_SYS(sys_mlockall	, 1)
	MIPS_SYS(sys_munlockall	, 0)
	MIPS_SYS(sys_sched_setparam, 2)
	MIPS_SYS(sys_sched_getparam, 2)
	MIPS_SYS(sys_sched_setscheduler, 3)	/* 4160 */
	MIPS_SYS(sys_sched_getscheduler, 1)
	MIPS_SYS(sys_sched_yield	, 0)
	MIPS_SYS(sys_sched_get_priority_max, 1)
	MIPS_SYS(sys_sched_get_priority_min, 1)
	MIPS_SYS(sys_sched_rr_get_interval, 2)	/* 4165 */
	MIPS_SYS(sys_nanosleep,	2)
	MIPS_SYS(sys_mremap	, 5)
	MIPS_SYS(sys_accept	, 3)
	MIPS_SYS(sys_bind	, 3)
	MIPS_SYS(sys_connect	, 3)	/* 4170 */
	MIPS_SYS(sys_getpeername	, 3)
	MIPS_SYS(sys_getsockname	, 3)
	MIPS_SYS(sys_getsockopt	, 5)
	MIPS_SYS(sys_listen	, 2)
	MIPS_SYS(sys_recv	, 4)	/* 4175 */
	MIPS_SYS(sys_recvfrom	, 6)
	MIPS_SYS(sys_recvmsg	, 3)
	MIPS_SYS(sys_send	, 4)
	MIPS_SYS(sys_sendmsg	, 3)
	MIPS_SYS(sys_sendto	, 6)	/* 4180 */
	MIPS_SYS(sys_setsockopt	, 5)
	MIPS_SYS(sys_shutdown	, 2)
	MIPS_SYS(sys_socket	, 3)
	MIPS_SYS(sys_socketpair	, 4)
	MIPS_SYS(sys_setresuid	, 3)	/* 4185 */
	MIPS_SYS(sys_getresuid	, 3)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_query_module */
	MIPS_SYS(sys_poll	, 3)
	MIPS_SYS(sys_nfsservctl	, 3)
	MIPS_SYS(sys_setresgid	, 3)	/* 4190 */
	MIPS_SYS(sys_getresgid	, 3)
	MIPS_SYS(sys_prctl	, 5)
	MIPS_SYS(sys_rt_sigreturn, 0)
	MIPS_SYS(sys_rt_sigaction, 4)
	MIPS_SYS(sys_rt_sigprocmask, 4)	/* 4195 */
	MIPS_SYS(sys_rt_sigpending, 2)
	MIPS_SYS(sys_rt_sigtimedwait, 4)
	MIPS_SYS(sys_rt_sigqueueinfo, 3)
	MIPS_SYS(sys_rt_sigsuspend, 0)
	MIPS_SYS(sys_pread64	, 6)	/* 4200 */
	MIPS_SYS(sys_pwrite64	, 6)
	MIPS_SYS(sys_chown	, 3)
	MIPS_SYS(sys_getcwd	, 2)
	MIPS_SYS(sys_capget	, 2)
	MIPS_SYS(sys_capset	, 2)	/* 4205 */
	MIPS_SYS(sys_sigaltstack	, 2)
	MIPS_SYS(sys_sendfile	, 4)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_mmap2	, 6)	/* 4210 */
	MIPS_SYS(sys_truncate64	, 4)
	MIPS_SYS(sys_ftruncate64	, 4)
	MIPS_SYS(sys_stat64	, 2)
	MIPS_SYS(sys_lstat64	, 2)
	MIPS_SYS(sys_fstat64	, 2)	/* 4215 */
	MIPS_SYS(sys_pivot_root	, 2)
	MIPS_SYS(sys_mincore	, 3)
	MIPS_SYS(sys_madvise	, 3)
	MIPS_SYS(sys_getdents64	, 3)
	MIPS_SYS(sys_fcntl64	, 3)	/* 4220 */
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_gettid	, 0)
	MIPS_SYS(sys_readahead	, 5)
	MIPS_SYS(sys_setxattr	, 5)
	MIPS_SYS(sys_lsetxattr	, 5)	/* 4225 */
	MIPS_SYS(sys_fsetxattr	, 5)
	MIPS_SYS(sys_getxattr	, 4)
	MIPS_SYS(sys_lgetxattr	, 4)
	MIPS_SYS(sys_fgetxattr	, 4)
	MIPS_SYS(sys_listxattr	, 3)	/* 4230 */
	MIPS_SYS(sys_llistxattr	, 3)
	MIPS_SYS(sys_flistxattr	, 3)
	MIPS_SYS(sys_removexattr	, 2)
	MIPS_SYS(sys_lremovexattr, 2)
	MIPS_SYS(sys_fremovexattr, 2)	/* 4235 */
	MIPS_SYS(sys_tkill	, 2)
	MIPS_SYS(sys_sendfile64	, 5)
	MIPS_SYS(sys_futex	, 6)
	MIPS_SYS(sys_sched_setaffinity, 3)
	MIPS_SYS(sys_sched_getaffinity, 3)	/* 4240 */
	MIPS_SYS(sys_io_setup	, 2)
	MIPS_SYS(sys_io_destroy	, 1)
	MIPS_SYS(sys_io_getevents, 5)
	MIPS_SYS(sys_io_submit	, 3)
	MIPS_SYS(sys_io_cancel	, 3)	/* 4245 */
	MIPS_SYS(sys_exit_group	, 1)
	MIPS_SYS(sys_lookup_dcookie, 3)
	MIPS_SYS(sys_epoll_create, 1)
	MIPS_SYS(sys_epoll_ctl	, 4)
	MIPS_SYS(sys_epoll_wait	, 3)	/* 4250 */
	MIPS_SYS(sys_remap_file_pages, 5)
	MIPS_SYS(sys_set_tid_address, 1)
	MIPS_SYS(sys_restart_syscall, 0)
	MIPS_SYS(sys_fadvise64_64, 7)
	MIPS_SYS(sys_statfs64	, 3)	/* 4255 */
	MIPS_SYS(sys_fstatfs64	, 2)
	MIPS_SYS(sys_timer_create, 3)
	MIPS_SYS(sys_timer_settime, 4)
	MIPS_SYS(sys_timer_gettime, 2)
	MIPS_SYS(sys_timer_getoverrun, 1)	/* 4260 */
	MIPS_SYS(sys_timer_delete, 1)
	MIPS_SYS(sys_clock_settime, 2)
	MIPS_SYS(sys_clock_gettime, 2)
	MIPS_SYS(sys_clock_getres, 2)
	MIPS_SYS(sys_clock_nanosleep, 4)	/* 4265 */
	MIPS_SYS(sys_tgkill	, 3)
	MIPS_SYS(sys_utimes	, 2)
	MIPS_SYS(sys_mbind	, 4)
	MIPS_SYS(sys_ni_syscall	, 0)	/* sys_get_mempolicy */
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4270 sys_set_mempolicy */
	MIPS_SYS(sys_mq_open	, 4)
	MIPS_SYS(sys_mq_unlink	, 1)
	MIPS_SYS(sys_mq_timedsend, 5)
	MIPS_SYS(sys_mq_timedreceive, 5)
	MIPS_SYS(sys_mq_notify	, 2)	/* 4275 */
	MIPS_SYS(sys_mq_getsetattr, 3)
	MIPS_SYS(sys_ni_syscall	, 0)	/* sys_vserver */
	MIPS_SYS(sys_waitid	, 4)
	MIPS_SYS(sys_ni_syscall	, 0)	/* available, was setaltroot */
	MIPS_SYS(sys_add_key	, 5)
	MIPS_SYS(sys_request_key, 4)
	MIPS_SYS(sys_keyctl	, 5)
	MIPS_SYS(sys_set_thread_area, 1)
	MIPS_SYS(sys_inotify_init, 0)
	MIPS_SYS(sys_inotify_add_watch, 3) /* 4285 */
	MIPS_SYS(sys_inotify_rm_watch, 2)
	MIPS_SYS(sys_migrate_pages, 4)
	MIPS_SYS(sys_openat, 4)
	MIPS_SYS(sys_mkdirat, 3)
	MIPS_SYS(sys_mknodat, 4)	/* 4290 */
	MIPS_SYS(sys_fchownat, 5)
	MIPS_SYS(sys_futimesat, 3)
	MIPS_SYS(sys_fstatat64, 4)
	MIPS_SYS(sys_unlinkat, 3)
	MIPS_SYS(sys_renameat, 4)	/* 4295 */
	MIPS_SYS(sys_linkat, 5)
	MIPS_SYS(sys_symlinkat, 3)
	MIPS_SYS(sys_readlinkat, 4)
	MIPS_SYS(sys_fchmodat, 3)
	MIPS_SYS(sys_faccessat, 3)	/* 4300 */
	MIPS_SYS(sys_pselect6, 6)
	MIPS_SYS(sys_ppoll, 5)
	MIPS_SYS(sys_unshare, 1)
	MIPS_SYS(sys_splice, 6)
	MIPS_SYS(sys_sync_file_range, 7) /* 4305 */
	MIPS_SYS(sys_tee, 4)
	MIPS_SYS(sys_vmsplice, 4)
	MIPS_SYS(sys_move_pages, 6)
	MIPS_SYS(sys_set_robust_list, 2)
	MIPS_SYS(sys_get_robust_list, 3) /* 4310 */
	MIPS_SYS(sys_kexec_load, 4)
	MIPS_SYS(sys_getcpu, 3)
	MIPS_SYS(sys_epoll_pwait, 6)
	MIPS_SYS(sys_ioprio_set, 3)
	MIPS_SYS(sys_ioprio_get, 2)
        MIPS_SYS(sys_utimensat, 4)
        MIPS_SYS(sys_signalfd, 3)
        MIPS_SYS(sys_ni_syscall, 0)     /* was timerfd */
        MIPS_SYS(sys_eventfd, 1)
        MIPS_SYS(sys_fallocate, 6)      /* 4320 */
        MIPS_SYS(sys_timerfd_create, 2)
        MIPS_SYS(sys_timerfd_gettime, 2)
        MIPS_SYS(sys_timerfd_settime, 4)
        MIPS_SYS(sys_signalfd4, 4)
        MIPS_SYS(sys_eventfd2, 2)       /* 4325 */
        MIPS_SYS(sys_epoll_create1, 1)
        MIPS_SYS(sys_dup3, 3)
        MIPS_SYS(sys_pipe2, 2)
        MIPS_SYS(sys_inotify_init1, 1)
        MIPS_SYS(sys_preadv, 5)         /* 4330 */
        MIPS_SYS(sys_pwritev, 5)
        MIPS_SYS(sys_rt_tgsigqueueinfo, 4)
        MIPS_SYS(sys_perf_event_open, 5)
        MIPS_SYS(sys_accept4, 4)
        MIPS_SYS(sys_recvmmsg, 5)       /* 4335 */
        MIPS_SYS(sys_fanotify_init, 2)
        MIPS_SYS(sys_fanotify_mark, 6)
        MIPS_SYS(sys_prlimit64, 4)
        MIPS_SYS(sys_name_to_handle_at, 5)
        MIPS_SYS(sys_open_by_handle_at, 3) /* 4340 */
        MIPS_SYS(sys_clock_adjtime, 2)
        MIPS_SYS(sys_syncfs, 1)
        MIPS_SYS(sys_sendmmsg, 4)
        MIPS_SYS(sys_setns, 2)
        MIPS_SYS(sys_process_vm_readv, 6) /* 345 */
        MIPS_SYS(sys_process_vm_writev, 6)
        MIPS_SYS(sys_kcmp, 5)
        MIPS_SYS(sys_finit_module, 3)
        MIPS_SYS(sys_sched_setattr, 2)
        MIPS_SYS(sys_sched_getattr, 3)  /* 350 */
        MIPS_SYS(sys_renameat2, 5)
        MIPS_SYS(sys_seccomp, 3)
        MIPS_SYS(sys_getrandom, 3)
        MIPS_SYS(sys_memfd_create, 2)
        MIPS_SYS(sys_bpf, 3)            /* 355 */
        MIPS_SYS(sys_execveat, 5)
        MIPS_SYS(sys_userfaultfd, 1)
        MIPS_SYS(sys_membarrier, 2)
        MIPS_SYS(sys_mlock2, 3)
        MIPS_SYS(sys_copy_file_range, 6) /* 360 */
        MIPS_SYS(sys_preadv2, 6)
        MIPS_SYS(sys_pwritev2, 6)
};
#  undef MIPS_SYS
# endif /* TARGET_ABI_IRIX */
#define NUM_SYSCALLS    (sizeof(mips_syscall_args) / sizeof(*mips_syscall_args))

static int do_store_exclusive(CPUMIPSState *env)
{
    target_ulong addr;
    target_ulong page_addr;
    target_ulong val;
    int flags;
    int segv = 0;
    int reg;
    int d;

    addr = env->lladdr;
    page_addr = addr & TARGET_PAGE_MASK;
    start_exclusive();
    mmap_lock();
    flags = page_get_flags(page_addr);
    if ((flags & PAGE_READ) == 0) {
        segv = 1;
    } else {
        reg = env->llreg & 0x1f;
        d = (env->llreg & 0x20) != 0;
        if (d) {
            segv = get_user_s64(val, addr);
        } else {
            segv = get_user_s32(val, addr);
        }
        if (!segv) {
            if (val != env->llval) {
                env->active_tc.gpr[reg] = 0;
            } else {
                if (d) {
                    segv = put_user_u64(env->llnewval, addr);
                } else {
                    segv = put_user_u32(env->llnewval, addr);
                }
                if (!segv) {
                    env->active_tc.gpr[reg] = 1;
                }
            }
        }
    }
    env->lladdr = -1;
    if (!segv) {
        env->active_tc.PC += 4;
    }
    mmap_unlock();
    end_exclusive();
    return segv;
}

/* Break codes */
enum {
    BRK_OVERFLOW = 6,
    BRK_DIVZERO = 7
};

static int do_break(CPUMIPSState *env, target_siginfo_t *info,
                    unsigned int code)
{
    int ret = -1;

    switch (code) {
    case BRK_OVERFLOW:
    case BRK_DIVZERO:
        info->si_signo = TARGET_SIGFPE;
        info->si_errno = 0;
        info->si_code = (code == BRK_OVERFLOW) ? FPE_INTOVF : FPE_INTDIV;
        queue_signal(env, info->si_signo, QEMU_SI_FAULT, &*info);
        ret = 0;
        break;
    default:
        info->si_signo = TARGET_SIGTRAP;
        info->si_errno = 0;
        queue_signal(env, info->si_signo, QEMU_SI_FAULT, &*info);
        ret = 0;
        break;
    }

    return ret;
}

#if defined(TARGET_ABI_IRIX) && defined(TARGET_ABI_MIPSN32)
/* split the arg64'th arg, which is a 64 bit arg in a 64 bit register, into an
 * even/odd 32 bit register pair, moving the other args up as necessary. This is
 * needed because the syscall ABI for TARGET_ABI32 only knows about 32 bit args.
 */
static void get_args_n32(target_ulong *regs, int arg64, int num, abi_ulong args[8])
{
    int i, j;

    /* what a nuisance, and all this just for a few of the syscalls :-( */
    if (arg64) {
        for (i = 0; i < arg64-1; i++)
            args[i] = regs[i];
        args[i] = 0; i += (i & 1); /* align to even register */
        args[i++] = regs[arg64-1] >> 32;
        args[i++] = regs[arg64-1];
        /* at most <num> registers are needed for the expanded args */
        for (j = arg64; i < num; j++)
            args[i++] = regs[j];
    } else {
        for (i = 0; i < num; i++)
            args[i] = regs[i];
    }
}
#endif /* TARGET_ABI_IRIX && TARGET_ABI_MIPSN32 */

void cpu_loop(CPUMIPSState *env)
{
    CPUState *cs = CPU(mips_env_get_cpu(env));
    target_siginfo_t info;
    int trapnr;
    abi_long ret;
    unsigned int syscall_num;
    int offset = 0;
# ifdef TARGET_ABI_IRIX
    TaskState *ts = cs->opaque;

    __put_user(ts->ts_tid, (abi_int *)&ts->prda[0xe00]);
    __put_user(ts->ts_tid, (abi_int *)&ts->prda[0xe40]);
# endif /* TARGET_ABI_IRIX */

    for(;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch(trapnr) {
        case EXCP_SYSCALL:
            env->active_tc.PC += 4;
            syscall_num = env->active_tc.gpr[2] - TARGET_NR_Linux;

# ifdef TARGET_ABI_IRIX
            /* handle indirect syscalls here, else N32 64 bit args are passed incorrectly */
            offset = (syscall_num == TARGET_NR_syscall - TARGET_NR_Linux);
            if (offset) {
                syscall_num = env->active_tc.gpr[4] - TARGET_NR_Linux;
            }
# endif /* TARGET_ABI_IRIX */

            if (syscall_num >= sizeof(mips_syscall_args)) {
                ret = -TARGET_ENOSYS;
            } else {
# ifdef TARGET_ABI_MIPSO32
                int nb_args;
                abi_ulong sp_reg;
                abi_ulong arg4 = 0, arg5 = 0, arg6 = 0, arg7 = 0, arg8 = 0;

                nb_args = SYSCALL_NARGS(mips_syscall_args[syscall_num]);
                sp_reg = env->active_tc.gpr[29] + 4*offset;
                switch (nb_args) {
                /* these arguments are taken from the stack */
                case 8:
                    if ((ret = get_user_ual(arg8, sp_reg + 28)) != 0) {
                        goto done_syscall;
                    }
                case 7:
                    if ((ret = get_user_ual(arg7, sp_reg + 24)) != 0) {
                        goto done_syscall;
                    }
                case 6:
                    if ((ret = get_user_ual(arg6, sp_reg + 20)) != 0) {
                        goto done_syscall;
                    }
                case 5:
                    if ((ret = get_user_ual(arg5, sp_reg + 16)) != 0) {
                        goto done_syscall;
                    }
                case 4:
                    if (offset && (ret = get_user_ual(arg4, sp_reg + 12)) != 0) {
                        goto done_syscall;
                    }
                default:
                    break;
                }
                ret = do_syscall(env, syscall_num + TARGET_NR_Linux,
                                 env->active_tc.gpr[4+offset],
                                 env->active_tc.gpr[5+offset],
                                 env->active_tc.gpr[6+offset],
                                 offset ? arg4 : env->active_tc.gpr[7],
                                 arg5, arg6, arg7, arg8);
done_syscall:   ;
# else /* !TARGET_ABI_MIPSO32 */
#  if defined TARGET_ABI_IRIX && defined TARGET_ABI_MIPSN32
                /* split 64 bit args into 2 32 bit args for N32 */
                int nb_args;
                int arg64;
                abi_ulong args[8];

                /* map certain syscalls to their 64 bit version */
                if (SYSCALL_MAP(mips_syscall_args[syscall_num]))
                    syscall_num = SYSCALL_MAP(mips_syscall_args[syscall_num]) - TARGET_NR_Linux;
                nb_args = SYSCALL_NARGS(mips_syscall_args[syscall_num]);
                arg64 = SYSCALL_ARG64(mips_syscall_args[syscall_num]);
                get_args_n32(&env->active_tc.gpr[4+offset], arg64, nb_args, args);
#  else
                target_ulong *args = &env->active_tc.gpr[4+offset];
#  endif
                ret = do_syscall(env, syscall_num + TARGET_NR_Linux,
                                 args[0], args[1], args[2], args[3],
                                 args[4], args[5], args[6], args[7]);
# endif /* TARGET_ABI_MIPSO32 */
            }
            if (ret == -TARGET_ERESTARTSYS) {
                env->active_tc.PC -= 4;
                break;
            }
            if (ret == -TARGET_QEMU_ESIGRETURN) {
                /* Returning from a successful sigreturn syscall.
                   Avoid clobbering register state.  */
                break;
            }
            /* on return: gpr7 = error flag, gpr2/3 = value(s) or error code */
# if defined TARGET_ABI_IRIX
#  if defined TARGET_ABI_MIPSN32
            /* restore a 64 bit retval for N32 */
            if (SYSCALL_RET64(mips_syscall_args[syscall_num])) {
                target_ulong tret = ((target_ulong)ret << 32) | env->active_tc.gpr[3];
                env->active_tc.gpr[7] = (tret >= (target_ulong)-1700);
                env->active_tc.gpr[2] = (env->active_tc.gpr[7] ? -tret : tret);
            } else
#  endif /* TARGET_ABI_MIPSN32 */
            {
                env->active_tc.gpr[7] = (ret >= (abi_ulong)-1700);
                env->active_tc.gpr[2] = (env->active_tc.gpr[7] ? -ret : ret);
            }
# else /* !TARGET_ABI_IRIX */
            if ((abi_ulong)ret >= (abi_ulong)-1133) {
                env->active_tc.gpr[7] = 1; /* error flag */
                env->active_tc.gpr[2] = -ret;
            } else {
                env->active_tc.gpr[7] = 0; /* error flag */
                env->active_tc.gpr[2] = ret;
            }
# endif /* TARGET_ABI_IRIX */
            break;
        case EXCP_TLBL:
        case EXCP_TLBS:
        case EXCP_AdEL:
        case EXCP_AdES:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            /* XXX: check env->error_code */
            info.si_code = TARGET_SEGV_MAPERR;
            info._sifields._sigfault._addr = env->CP0_BadVAddr;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_CpU:
        case EXCP_RI:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = 0;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
#ifdef TARGET_ABI_IRIX
        case EXCP_FPE:
            info.si_signo = TARGET_SIGFPE;
            info.si_errno = 0;
            info.si_code = 0;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
#endif /* TARGET_ABI_IRIX */
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
        case EXCP_SC:
            if (do_store_exclusive(env)) {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = env->active_tc.PC;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_DSPDIS:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPC;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        /* The code below was inspired by the MIPS Linux kernel trap
         * handling code in arch/mips/kernel/traps.c.
         */
        case EXCP_BREAK:
            {
                abi_ulong trap_instr;
                unsigned int code;

                if (env->hflags & MIPS_HFLAG_M16) {
                    if (env->insn_flags & ASE_MICROMIPS) {
                        /* microMIPS mode */
                        ret = get_user_u16(trap_instr, env->active_tc.PC);
                        if (ret != 0) {
                            goto error;
                        }

                        if ((trap_instr >> 10) == 0x11) {
                            /* 16-bit instruction */
                            code = trap_instr & 0xf;
                        } else {
                            /* 32-bit instruction */
                            abi_ulong instr_lo;

                            ret = get_user_u16(instr_lo,
                                               env->active_tc.PC + 2);
                            if (ret != 0) {
                                goto error;
                            }
                            trap_instr = (trap_instr << 16) | instr_lo;
                            code = ((trap_instr >> 6) & ((1 << 20) - 1));
                            /* Unfortunately, microMIPS also suffers from
                               the old assembler bug...  */
                            if (code >= (1 << 10)) {
                                code >>= 10;
                            }
                        }
                    } else {
                        /* MIPS16e mode */
                        ret = get_user_u16(trap_instr, env->active_tc.PC);
                        if (ret != 0) {
                            goto error;
                        }
                        code = (trap_instr >> 6) & 0x3f;
                    }
                } else {
                    ret = get_user_u32(trap_instr, env->active_tc.PC);
                    if (ret != 0) {
                        goto error;
                    }

                    /* As described in the original Linux kernel code, the
                     * below checks on 'code' are to work around an old
                     * assembly bug.
                     */
                    code = ((trap_instr >> 6) & ((1 << 20) - 1));
                    if (code >= (1 << 10)) {
                        code >>= 10;
                    }
                }

                if (do_break(env, &info, code) != 0) {
                    goto error;
                }
            }
            break;
        case EXCP_TRAP:
            {
                abi_ulong trap_instr;
                unsigned int code = 0;

                if (env->hflags & MIPS_HFLAG_M16) {
                    /* microMIPS mode */
                    abi_ulong instr[2];

                    ret = get_user_u16(instr[0], env->active_tc.PC) ||
                          get_user_u16(instr[1], env->active_tc.PC + 2);

                    trap_instr = (instr[0] << 16) | instr[1];
                } else {
                    ret = get_user_u32(trap_instr, env->active_tc.PC);
                }

                if (ret != 0) {
                    goto error;
                }

                /* The immediate versions don't provide a code.  */
                if (!(trap_instr & 0xFC000000)) {
                    if (env->hflags & MIPS_HFLAG_M16) {
                        /* microMIPS mode */
                        code = ((trap_instr >> 12) & ((1 << 4) - 1));
                    } else {
                        code = ((trap_instr >> 6) & ((1 << 10) - 1));
                    }
                }

                if (do_break(env, &info, code) != 0) {
                    goto error;
                }
            }
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
error:
            EXCP_DUMP(env, "qemu: unhandled CPU exception 0x%x - aborting\n", trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}
#endif /* TARGET_MIPS */


__thread CPUState *thread_cpu;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

void qemu_cpu_kick(CPUState *cpu)
{
    cpu_exit(cpu);
}

void task_settid(TaskState *ts)
{
    //ts->ts_tid = (pid_t)syscall(SYS_gettid);
    uint64_t tid64;
    pthread_threadid_np(NULL, &tid64);
    pid_t tid = (pid_t)tid64;
    ts->ts_tid = tid;
}

void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    ts->used = 1;

#ifdef TARGET_ABI_IRIX
    pthread_mutex_init(&ts->procblk_mutex, NULL);
    pthread_cond_init(&ts->procblk_cond, NULL);
#endif
}

TaskState *find_task_state(pid_t tid)
{
    CPUState *cpu;
    TaskState *ts = NULL;

    for (cpu = first_cpu; cpu; cpu = CPU_NEXT(cpu)) {
        ts = cpu->opaque;
        if (ts->ts_tid == tid)
            break;
    }

    return ts;
}

CPUState *find_cpu_state(pid_t tid)
{
    CPUState *cpu;
    TaskState *ts;

    for (cpu = first_cpu; cpu; cpu = CPU_NEXT(cpu)) {
        ts = cpu->opaque;
        if (ts->ts_tid == tid)
            break;
    }

    return cpu;
}

CPUArchState *cpu_copy(CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    CPUState *new_cpu = cpu_init(cpu_model);
    CPUArchState *new_env = new_cpu->env_ptr;
    CPUBreakpoint *bp;
    CPUWatchpoint *wp;

    /* Reset non arch specific state */
    cpu_reset(new_cpu);

    memcpy(new_env, env, sizeof(CPUArchState));

    /* Clone all break/watchpoints.
       Note: Once we support ptrace with hw-debug register access, make sure
       BP_CPU break/watchpoints are handled correctly on clone. */
    QTAILQ_INIT(&new_cpu->breakpoints);
    QTAILQ_INIT(&new_cpu->watchpoints);
    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        cpu_breakpoint_insert(new_cpu, bp->pc, bp->flags, NULL);
    }
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        cpu_watchpoint_insert(new_cpu, wp->vaddr, wp->len, wp->flags, NULL);
    }

    return new_env;
}

static void handle_arg_help(const char *arg)
{
    usage(EXIT_SUCCESS);
}

static void handle_arg_log(const char *arg)
{
    int mask;

    mask = qemu_str_to_log_mask(arg);
    if (!mask) {
        qemu_print_log_usage(stdout);
        exit(EXIT_FAILURE);
    }
    qemu_log_needs_buffers();
    qemu_set_log(mask);
}

static void handle_arg_dfilter(const char *arg)
{
    qemu_set_dfilter_ranges(arg, NULL);
}

static void handle_arg_log_filename(const char *arg)
{
    qemu_set_log_filename(arg, &error_fatal);
}

static void handle_arg_set_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_setenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_unset_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_unsetenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_argv0(const char *arg)
{
    argv0 = strdup(arg);
}

static void handle_arg_stack_size(const char *arg)
{
    char *p;
    guest_stack_size = strtoul(arg, &p, 0);
    if (guest_stack_size == 0) {
        usage(EXIT_FAILURE);
    }

    if (*p == 'M') {
        guest_stack_size *= 1024 * 1024;
    } else if (*p == 'k' || *p == 'K') {
        guest_stack_size *= 1024;
    }
}

static void handle_arg_ld_prefix(const char *arg)
{
    interp_prefix = strdup(arg);
}

static void handle_arg_pagesize(const char *arg)
{
    qemu_host_page_size = atoi(arg);
    if (qemu_host_page_size == 0 ||
        (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
        fprintf(stderr, "page size must be a power of two\n");
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_randseed(const char *arg)
{
    unsigned long long seed;

    if (parse_uint_full(arg, &seed, 0) != 0 || seed > UINT_MAX) {
        fprintf(stderr, "Invalid seed number: %s\n", arg);
        exit(EXIT_FAILURE);
    }
    srand(seed);
}

static void handle_arg_gdb(const char *arg)
{
    gdbstub_port = atoi(arg);
}

static void handle_arg_uname(const char *arg)
{
    qemu_uname_release = strdup(arg);
}

static void handle_arg_cpu(const char *arg)
{
    cpu_model = strdup(arg);
    if (cpu_model == NULL || is_help_option(cpu_model)) {
        /* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
        cpu_list(stdout, &fprintf);
#endif
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_guest_base(const char *arg)
{
    guest_base = strtol(arg, NULL, 0);
    have_guest_base = 1;
}

static void handle_arg_reserved_va(const char *arg)
{
    char *p;
    int shift = 0;
    reserved_va = strtoul(arg, &p, 0);
    switch (*p) {
    case 'k':
    case 'K':
        shift = 10;
        break;
    case 'M':
        shift = 20;
        break;
    case 'G':
        shift = 30;
        break;
    }
    if (shift) {
        unsigned long unshifted = reserved_va;
        p++;
        reserved_va <<= shift;
        if (reserved_va >> shift != unshifted
            || (MAX_RESERVED_VA && reserved_va > MAX_RESERVED_VA)) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(EXIT_FAILURE);
        }
    }
    if (*p) {
        fprintf(stderr, "Unrecognised -R size suffix '%s'\n", p);
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_singlestep(const char *arg)
{
    singlestep = 1;
}

static void handle_arg_strace(const char *arg)
{
    do_strace = 1;
}

static void handle_arg_version(const char *arg)
{
    printf("qemu-" TARGET_NAME " version " QEMU_VERSION QEMU_PKGVERSION
           "\n" QEMU_COPYRIGHT "\n");
    exit(EXIT_SUCCESS);
}

static void handle_arg_silent(const char *arg)
{
    silent = 1;
}

static char *trace_file;
static void handle_arg_trace(const char *arg)
{
    g_free(trace_file);
    trace_file = trace_opt_parse(arg);
}

struct qemu_argument {
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] = {
    {"h",          "",                 false, handle_arg_help,
     "",           "print this help"},
    {"help",       "",                 false, handle_arg_help,
     "",           ""},
    {"g",          "QEMU_GDB",         true,  handle_arg_gdb,
     "port",       "wait gdb connection to 'port'"},
    {"L",          "QEMU_LD_PREFIX",   true,  handle_arg_ld_prefix,
     "path",       "set the elf interpreter prefix to 'path'"},
    {"s",          "QEMU_STACK_SIZE",  true,  handle_arg_stack_size,
     "size",       "set the stack size to 'size' bytes"},
    {"cpu",        "QEMU_CPU",         true,  handle_arg_cpu,
     "model",      "select CPU (-cpu help for list)"},
    {"E",          "QEMU_SET_ENV",     true,  handle_arg_set_env,
     "var=value",  "sets targets environment variable (see below)"},
    {"U",          "QEMU_UNSET_ENV",   true,  handle_arg_unset_env,
     "var",        "unsets targets environment variable (see below)"},
    {"0",          "QEMU_ARGV0",       true,  handle_arg_argv0,
     "argv0",      "forces target process argv[0] to be 'argv0'"},
    {"r",          "QEMU_UNAME",       true,  handle_arg_uname,
     "uname",      "set qemu uname release string to 'uname'"},
    {"B",          "QEMU_GUEST_BASE",  true,  handle_arg_guest_base,
     "address",    "set guest_base address to 'address'"},
    {"R",          "QEMU_RESERVED_VA", true,  handle_arg_reserved_va,
     "size",       "reserve 'size' bytes for guest virtual address space"},
    {"d",          "QEMU_LOG",         true,  handle_arg_log,
     "item[,...]", "enable logging of specified items "
     "(use '-d help' for a list of items)"},
    {"dfilter",    "QEMU_DFILTER",     true,  handle_arg_dfilter,
     "range[,...]","filter logging based on address range"},
    {"D",          "QEMU_LOG_FILENAME", true, handle_arg_log_filename,
     "logfile",     "write logs to 'logfile' (default stderr)"},
    {"p",          "QEMU_PAGESIZE",    true,  handle_arg_pagesize,
     "pagesize",   "set the host page size to 'pagesize'"},
    {"singlestep", "QEMU_SINGLESTEP",  false, handle_arg_singlestep,
     "",           "run in singlestep mode"},
    {"strace",     "QEMU_STRACE",      false, handle_arg_strace,
     "",           "log system calls"},
    {"seed",       "QEMU_RAND_SEED",   true,  handle_arg_randseed,
     "",           "Seed for pseudo-random number generator"},
    {"trace",      "QEMU_TRACE",       true,  handle_arg_trace,
     "",           "[[enable=]<pattern>][,events=<file>][,file=<file>]"},
    {"version",    "QEMU_VERSION",     false, handle_arg_version,
     "",           "display version information and exit"},
    {"silent",     "",                 false, handle_arg_silent,
     "",           "silence all logging"},
    {NULL, NULL, false, NULL, NULL, NULL}
};

static void usage(int exitcode)
{
    const struct qemu_argument *arginfo;
    int maxarglen;
    int maxenvlen;

    printf("usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "Darwin CPU emulator (compiled for " TARGET_NAME " emulation)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n");

    /* Calculate column widths. We must always have at least enough space
     * for the column header.
     */
    maxarglen = strlen("Argument");
    maxenvlen = strlen("Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        int arglen = strlen(arginfo->argv);
        if (arginfo->has_arg) {
            arglen += strlen(arginfo->example) + 1;
        }
        if (strlen(arginfo->env) > maxenvlen) {
            maxenvlen = strlen(arginfo->env);
        }
        if (arglen > maxarglen) {
            maxarglen = arglen;
        }
    }

    printf("%-*s %-*s Description\n", maxarglen+1, "Argument",
            maxenvlen, "Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->has_arg) {
            printf("-%s %-*s %-*s %s\n", arginfo->argv,
                   (int)(maxarglen - strlen(arginfo->argv) - 1),
                   arginfo->example, maxenvlen, arginfo->env, arginfo->help);
        } else {
            printf("-%-*s %-*s %s\n", maxarglen, arginfo->argv,
                    maxenvlen, arginfo->env,
                    arginfo->help);
        }
    }

    printf("\n"
           "Defaults:\n"
           "QEMU_LD_PREFIX  = %s\n"
           "QEMU_STACK_SIZE = %ld byte\n",
           interp_prefix,
           guest_stack_size);

    printf("\n"
           "You can use -E and -U options or the QEMU_SET_ENV and\n"
           "QEMU_UNSET_ENV environment variables to set and unset\n"
           "environment variables for the target process.\n"
           "It is possible to provide several variables by separating them\n"
           "by commas in getsubopt(3) style. Additionally it is possible to\n"
           "provide the -E and -U options multiple times.\n"
           "The following lines are equivalent:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "    -E var1=val2,var2=val2 -U LD_PRELOAD,LD_DEBUG\n"
           "    QEMU_SET_ENV=var1=val2,var2=val2 QEMU_UNSET_ENV=LD_PRELOAD,LD_DEBUG\n"
           "Note that if you provide several changes to a single variable\n"
           "the last change will stay in effect.\n"
           "\n"
           QEMU_HELP_BOTTOM "\n");

    exit(exitcode);
}

static int parse_args(int argc, char **argv)
{
    const char *r;
    int optind;
    const struct qemu_argument *arginfo;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->env == NULL) {
            continue;
        }

        r = getenv(arginfo->env);
        if (r != NULL) {
            arginfo->handle_opt(r);
        }
    }

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        r = argv[optind];
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        }
        /* Treat --foo the same as -foo.  */
        if (r[0] == '-') {
            r++;
        }

        for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        (void) fprintf(stderr,
                            "qemu: missing argument for option '%s'\n", r);
                        exit(EXIT_FAILURE);
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        /* no option matched the current argv */
        if (arginfo->handle_opt == NULL) {
            (void) fprintf(stderr, "qemu: unknown option '%s'\n", r);
            exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        (void) fprintf(stderr, "qemu: no user program specified\n");
        exit(EXIT_FAILURE);
    }

    filename = argv[optind];
    exec_path = argv[optind];

    return optind;
}

// args to pass to child instances of QEMU when spawning a child process
int qemu_argc;
char **qemu_argv;
// declare for macOS
extern char **environ;

int main(int argc, char **argv, char **envp)
{
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;
    int optind;
    char **target_environ, **wrk;
    char **target_argv;
    int target_argc;
    int i;
    int ret;
    int execfd;

    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    envlist = envlist_create();

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    /* Read the stack limit from the kernel.  If it's "unlimited",
       then we can do little else besides use the default.  */
    {
        struct rlimit lim;
        if (getrlimit(RLIMIT_STACK, &lim) == 0
            && lim.rlim_cur != RLIM_INFINITY
            && lim.rlim_cur == (target_long)lim.rlim_cur) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;

    srand(time(NULL));

    qemu_add_opts(&qemu_trace_opts);

    optind = parse_args(argc, argv);

    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file(trace_file);

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    init_qemu_uname_release();

    execfd = qemu_getauxval(AT_EXECFD);
    if (execfd == 0) {
        execfd = open(filename, O_RDONLY);
        if (execfd < 0) {
            printf("Error while loading %s: %s\n", filename, strerror(errno));
            _exit(EXIT_FAILURE);
        }
    }

    if (cpu_model == NULL) {
        cpu_model = cpu_get_model(get_elf_eflags(execfd));
    }
    tcg_exec_init(0);
    /* NOTE: we need to init the CPU at this stage to get
       qemu_host_page_size */
    cpu = cpu_init(cpu_model);
    env = cpu->env_ptr;
    cpu_reset(cpu);

    thread_cpu = cpu;

    if (getenv("QEMU_STRACE")) {
        do_strace = 1;
    }

    if (getenv("QEMU_RAND_SEED")) {
        handle_arg_randseed(getenv("QEMU_RAND_SEED"));
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

    /*
     * Now that page sizes are configured in cpu_init() we can do
     * proper page alignment for guest_base.
     */
    guest_base = HOST_PAGE_ALIGN(guest_base);

    if (reserved_va || have_guest_base) {
        guest_base = init_guest_space(guest_base, reserved_va, 0,
                                      have_guest_base);
        if (guest_base == (unsigned long)-1) {
            fprintf(stderr, "Unable to reserve 0x%lx bytes of virtual address "
                    "space for use as guest address space (check your virtual "
                    "memory ulimit setting or reserve less using -R option)\n",
                    reserved_va);
            exit(EXIT_FAILURE);
        }

        if (reserved_va) {
            mmap_next_start = reserved_va;
        }
    }

    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1) {
                mmap_min_addr = tmp;
                qemu_log_mask(CPU_LOG_PAGE, "host mmap_min_addr=0x%lx\n", mmap_min_addr);
            }
            fclose(fp);
        }
    }

    /*
     * Prepare copy of argv vector for target.
     */
    target_argc = argc - optind;
    target_argv = calloc(target_argc + 1, sizeof (char *));
    if (target_argv == NULL) {
	(void) fprintf(stderr, "Unable to allocate memory for target_argv\n");
	exit(EXIT_FAILURE);
    }

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */
    i = 0;
    if (argv0 != NULL) {
        target_argv[i++] = strdup(argv0);
    }
    for (; i < target_argc; i++) {
        target_argv[i] = strdup(argv[optind + i]);
    }
    target_argv[target_argc] = NULL;

    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    cpu->opaque = ts;
    task_settid(ts);

    ret = loader_exec(execfd, filename, target_argv, target_environ, regs,
        info, &bprm);
    if (ret != 0) {
        printf("Error while loading %s: %s\n", filename, strerror(-ret));
        _exit(EXIT_FAILURE);
    }

    for (wrk = target_environ; *wrk; wrk++) {
        g_free(*wrk);
    }

    g_free(target_environ);

    if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
        qemu_log("guest_base  0x%lx\n", guest_base);
        log_page_dump();

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n", info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n", info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n", info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
        qemu_log("argv_start  0x" TARGET_ABI_FMT_lx "\n", info->arg_start);
        qemu_log("env_start   0x" TARGET_ABI_FMT_lx "\n",
                 info->arg_end + (abi_ulong)sizeof(abi_ulong));
        qemu_log("auxv_start  0x" TARGET_ABI_FMT_lx "\n", info->saved_auxv);
    }

    target_set_brk(info->brk);
    syscall_init();
    signal_init(env);

    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(tcg_ctx);
    tcg_region_init();

#if defined(TARGET_MIPS)
    {
        int i;

        for(i = 0; i < 32; i++) {
            env->active_tc.gpr[i] = regs->regs[i];
        }
        env->active_tc.PC = regs->cp0_epc & ~(target_ulong)1;
        if (regs->cp0_epc & 1) {
            env->hflags |= MIPS_HFLAG_M16;
        }
        if (((info->elf_flags & EF_MIPS_NAN2008) != 0) !=
            ((env->active_fpu.fcr31 & (1 << FCR31_NAN2008)) != 0)) {
            if ((env->active_fpu.fcr31_rw_bitmask &
                  (1 << FCR31_NAN2008)) == 0) {
                fprintf(stderr, "ELF binary's NaN mode not supported by CPU\n");
                exit(1);
            }
            if ((info->elf_flags & EF_MIPS_NAN2008) != 0) {
                env->active_fpu.fcr31 |= (1 << FCR31_NAN2008);
            } else {
                env->active_fpu.fcr31 &= ~(1 << FCR31_NAN2008);
            }
            restore_snan_bit_mode(env);
        }
# if defined TARGET_ABI_IRIX && !defined TARGET_ABI_MIPSO32
        /* TODO: is this OK? */
        if ((info->elf_flags & EF_MIPS_ARCH) == EF_MIPS_ARCH_4) {
            /* enable MIPS IV COP1X instructions for N32 and N64 */
            env->CP0_Status |= (1 << CP0St_CU3);
            env->hflags |= MIPS_HFLAG_COP1X;
        }
        /* check if PRDA emulation is requested */
        if (getenv("QEMU_IRIXPRDA"))
            irix_emulate_prda = 1;
# endif
    }

#else
#error unsupported target CPU
#endif /* TARGET_MIPS */


    if (gdbstub_port) {
        if (gdbserver_start(gdbstub_port) < 0) {
            fprintf(stderr, "qemu: could not open gdbserver on port %d\n",
                    gdbstub_port);
            exit(EXIT_FAILURE);
        }
        gdb_handlesig(cpu, 0);
    }

    qemu_argc = optind;
    qemu_argv = argv;

    cpu_loop(env);
    /* never exits */
    return 0;
}
