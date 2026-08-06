#ifndef IRIX_TARGET_SYSCALL_H
#define IRIX_TARGET_SYSCALL_H

#include "cpu.h"

/* this struct defines the way the registers are stored on the
   stack during a system call. */

struct target_pt_regs {
	/* Saved main processor registers. */
	target_ulong regs[32];

	/* Saved special registers. */
	target_ulong cp0_status;
	target_ulong lo;
	target_ulong hi;
	target_ulong cp0_badvaddr;
	target_ulong cp0_cause;
	target_ulong cp0_epc;
};

#define UNAME_MACHINE "irix"
#define UNAME_MINIMUM_RELEASE "2.6.32"

#define TARGET_FORCE_SHMLBA

static inline abi_ulong target_shmlba(CPUMIPSState *env)
{
    return 0x40000;
}

/* IRIX sys/types.h */
typedef uint32_t target_ino_t;
typedef abi_long target_off_t;

/* IRIX sys/dirent.h */
struct target_dirent {
	target_ino_t d_ino;
	target_off_t d_off;
	abi_ushort d_reclen;
	char d_name[1];
};
/* size of struct target_dirent without the name array */
#define TARGET_DIRENT_LEN (offsetof(struct target_dirent, d_name))

/* IRIX sys/types.h */
typedef uint64_t target_ino64_t;
typedef uint64_t target_off64_t;

/* IRIX sys/dirent.h */
struct target_dirent64 {
	target_ino64_t d_ino;
	target_off64_t d_off;
	abi_ushort d_reclen;
	char d_name[1];
};
/* size of struct target_dirent without the name array */
#define TARGET_DIRENT64_LEN (offsetof(struct target_dirent64, d_name))

#endif
