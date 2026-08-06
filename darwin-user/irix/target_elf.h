/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation, or (at your option) any
 * later version. See the COPYING file in the top-level directory.
 */

#ifndef MIPS_TARGET_ELF_H
#define MIPS_TARGET_ELF_H
static inline const char *cpu_get_model(uint32_t eflags)
{
    /* O32 is MIPS I and MIPS II ISA, N32/N64 is MIPS III and MIPS IV ISA */
    if ((eflags & EF_MIPS_ARCH) == EF_MIPS_ARCH_1 ||
        (eflags & EF_MIPS_ARCH) == EF_MIPS_ARCH_2) {
      return "24Kf"; // MIPS32
//    return "R4000";
    }
    return "5Kf"; // MIPS64
}
#endif
