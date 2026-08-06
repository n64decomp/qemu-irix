/*
 * IRIX PRDA access helper functions for QEMU
 *
 * Copyright (c) 2015  Kai-Uwe Bloem <derkub@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cpu_ldst.h"
#include "exec/helper-proto.h"


#ifdef TARGET_ABI_IRIX
/* argh, ugly! need TaskState here to access PRDA storage */
#ifdef CONFIG_DARWIN_USER
#include <darwin-user/qemu.h>
#else
#include <linux-user/qemu.h>
#endif

#define DEBUG(x)    //x

static inline void *prda_ptr(CPUMIPSState *env, target_ulong addr)
{
    TaskState *ts = ENV_GET_CPU(env)->opaque;
    return &ts->prda[addr-0x200000];
}

uint64_t helper_irix_prda_ld_8(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = ldub_p(prda_ptr(env, addr));
    DEBUG(printf("ld8(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}

uint64_t helper_irix_prda_ld_16(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = lduw_p(prda_ptr(env, addr));
    DEBUG(printf("ld16(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}
uint64_t helper_irix_prda_ld_32(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = (uint32_t)ldl_p(prda_ptr(env, addr));
    DEBUG(printf("ld32(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}
uint64_t helper_irix_prda_ld_64(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = ldq_p(prda_ptr(env, addr));
    DEBUG(printf("ld64(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}

uint64_t helper_irix_prda_ld_8s(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = ldsb_p(prda_ptr(env, addr));
    DEBUG(printf("ld8s(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}

uint64_t helper_irix_prda_ld_16s(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = ldsw_p(prda_ptr(env, addr));
    DEBUG(printf("ld16s(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}
uint64_t helper_irix_prda_ld_32s(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = (int32_t)ldl_p(prda_ptr(env, addr));
    DEBUG(printf("ld32s(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}

uint64_t helper_irix_prda_ld_16b(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = lduw_be_p(prda_ptr(env, addr));
    DEBUG(printf("ld16b(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}
uint64_t helper_irix_prda_ld_32b(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = (uint32_t)ldl_be_p(prda_ptr(env, addr));
    DEBUG(printf("ld32b(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}
uint64_t helper_irix_prda_ld_64b(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = ldq_be_p(prda_ptr(env, addr));
    DEBUG(printf("ld64b(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}
uint64_t helper_irix_prda_ld_16sb(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = ldsw_be_p(prda_ptr(env, addr));
    DEBUG(printf("ld16sb(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}
uint64_t helper_irix_prda_ld_32sb(target_ulong addr, CPUMIPSState *env)
{
    uint64_t ret;
    ret = (int32_t)ldl_be_p(prda_ptr(env, addr));
    DEBUG(printf("ld32sb(%p) addr=%lx val=%lx\n",env,(long)addr,(long)ret));
    return ret;
}


void helper_irix_prda_st_8(uint64_t val, target_ulong addr, CPUMIPSState *env)
{
    DEBUG(printf("st8(%p) addr=%lx val=%lx\n",env,(long)addr,(long)val));
    stb_p(prda_ptr(env, addr), val);
}
void helper_irix_prda_st_16(uint64_t val, target_ulong addr, CPUMIPSState *env)
{
    DEBUG(printf("st16(%p) addr=%lx val=%lx\n",env,(long)addr,(long)val));
    stw_p(prda_ptr(env, addr), val);
}
void helper_irix_prda_st_32(uint64_t val, target_ulong addr, CPUMIPSState *env)
{
    DEBUG(printf("st32(%p) addr=%lx val=%lx\n",env,(long)addr,(long)val));
    stl_p(prda_ptr(env, addr), val);
}
void helper_irix_prda_st_64(uint64_t val, target_ulong addr, CPUMIPSState *env)
{
    DEBUG(printf("st64(%p) addr=%lx val=%lx\n",env,(long)addr,(long)val));
    stq_p(prda_ptr(env, addr), val);
}
void helper_irix_prda_st_16b(uint64_t val, target_ulong addr, CPUMIPSState *env)
{
    DEBUG(printf("st16b(%p) addr=%lx val=%lx\n",env,(long)addr,(long)val));
    stw_be_p(prda_ptr(env, addr), val);
}
void helper_irix_prda_st_32b(uint64_t val, target_ulong addr, CPUMIPSState *env)
{
    DEBUG(printf("st32b(%p) addr=%lx val=%lx\n",env,(long)addr,(long)val));
    stl_be_p(prda_ptr(env, addr), val);
}
void helper_irix_prda_st_64b(uint64_t val, target_ulong addr, CPUMIPSState *env)
{
    DEBUG(printf("st64b(%p) addr=%lx val=%lx\n",env,(long)addr,(long)val));
    stq_be_p(prda_ptr(env, addr), val);
}

#endif
