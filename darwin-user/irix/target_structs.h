/*
 * MIPS specific structures for linux-user
 *
 * Copyright (c) 2013 Fabrice Bellard
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
#ifndef IRIX_TARGET_STRUCTS_H
#define IRIX_TARGET_STRUCTS_H

struct target_ipc_perm {
    abi_uint uid;                       /* Owner's user ID.  */
    abi_uint gid;                       /* Owner's group ID.  */
    abi_uint cuid;                      /* Creator's user ID.  */
    abi_uint cgid;                      /* Creator's group ID.  */
    abi_uint mode;                      /* Read/write permission.  */
    abi_ulong __seq;                    /* Sequence number.  */
    abi_int __key;                      /* Key.  */
    abi_ulong __pad1[4];
};

struct target_shmid_ds {
    struct target_ipc_perm shm_perm;    /* operation permission struct */
#ifdef TARGET_ABI32
    abi_int shm_segsz;                  /* size of segment in bytes */
    abi_ulong shm_amp;
    short shm_lkcnt;
    short __pad0;
#else
    abi_int shm_osegsz;
    abi_long shm_segsz;                  /* size of segment in bytes */
    abi_int __pad0;
#endif
    abi_int shm_lpid;                   /* pid of last shmop */
    abi_int shm_cpid;                   /* pid of creator */
    abi_ulong shm_nattch;               /* number of current attaches */
    abi_ulong shm_cnattch;              /* number of current attaches */
    abi_ulong shm_atime;                /* time of last shmat() */
    abi_ulong shm_dtime;                /* time of last shmdt() */
    abi_ulong shm_ctime;                /* time of last change by shmctl() */
    abi_ulong __pad1[4];
};

#endif
