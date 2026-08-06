#ifndef IRIX_TARGET_SIGNAL_H
#define IRIX_TARGET_SIGNAL_H

#include "cpu.h"

/* this struct defines a stack used during syscall handling */

typedef struct target_sigaltstack {
#ifdef TARGET_ABI32
	abi_uint ss_sp;
#else
	abi_ulong ss_sp;
#endif
	uint32_t ss_size;
	abi_int ss_flags;
} target_stack_t;


/*
 * sigaltstack controls
 */
#define TARGET_SS_ONSTACK     1
#define TARGET_SS_DISABLE     2

#define TARGET_MINSIGSTKSZ    2048
#define TARGET_SIGSTKSZ       8192

static inline target_ulong get_sp_from_cpustate(CPUMIPSState *state)
{
    return state->active_tc.gpr[29];
}

struct target_mcontext32 {
        uint32_t gregs[36];
        double fregs[16];
        uint32_t fpcsr;
};

struct target_mcontext64 {
        uint64_t gregs[37];
        double fregs[32];
        uint32_t fpcsr;
};

struct target_mcontext {
        union {
	    struct target_mcontext32 _32;
	    struct target_mcontext64 _64;
	} mc;
};

struct target_ucontext {
        abi_ulong           tuc_flags;
#ifdef TARGET_ABI32
        abi_uint            tuc_link;
#else
        abi_ulong           tuc_link;
#endif
        target_sigset_t     tuc_sigmask;
        struct target_sigaltstack  tuc_stack;
        struct target_mcontext tuc_mcontext;
};

int save_context(CPUMIPSState *regs, struct target_mcontext *sc, int setret);
int restore_context(CPUMIPSState *regs, struct target_mcontext *sc);
#endif /* TARGET_SIGNAL_H */
