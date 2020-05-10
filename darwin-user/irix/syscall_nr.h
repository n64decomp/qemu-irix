/*
 * IRIX syscalls are in the range from 1000 to 1999.
 */
#define TARGET_NR_Linux		1000

/* syscalls as per IRIX /usr/include/sys.s */
#define TARGET_NR_syscall               (0+TARGET_NR_Linux)
#define TARGET_NR_exit                  (1+TARGET_NR_Linux)
#define TARGET_NR_fork                  (2+TARGET_NR_Linux)
#define TARGET_NR_read                  (3+TARGET_NR_Linux)
#define TARGET_NR_write                 (4+TARGET_NR_Linux)
#define TARGET_NR_open                  (5+TARGET_NR_Linux)
#define TARGET_NR_close                 (6+TARGET_NR_Linux)
#define TARGET_NR_creat                 (8+TARGET_NR_Linux)
#define TARGET_NR_link                  (9+TARGET_NR_Linux)
#define TARGET_NR_unlink                (10+TARGET_NR_Linux)
#define TARGET_NR_execv                 (11+TARGET_NR_Linux)
#define TARGET_NR_chdir                 (12+TARGET_NR_Linux)
#define TARGET_NR_time                  (13+TARGET_NR_Linux)
#define TARGET_NR_chmod                 (15+TARGET_NR_Linux)
#define TARGET_NR_chown                 (16+TARGET_NR_Linux)
#define TARGET_NR_brk                   (17+TARGET_NR_Linux)
#define TARGET_NR_stat                  (18+TARGET_NR_Linux)
#define TARGET_NR_lseek                 (19+TARGET_NR_Linux)
#define TARGET_NR_getpid                (20+TARGET_NR_Linux)
#define TARGET_NR_mount                 (21+TARGET_NR_Linux)
#define TARGET_NR_umount                (22+TARGET_NR_Linux)
#define TARGET_NR_setuid                (23+TARGET_NR_Linux)
#define TARGET_NR_getuid                (24+TARGET_NR_Linux)
#define TARGET_NR_stime                 (25+TARGET_NR_Linux)
#define TARGET_NR_ptrace                (26+TARGET_NR_Linux)
#define TARGET_NR_alarm                 (27+TARGET_NR_Linux)
#define TARGET_NR_pause                 (29+TARGET_NR_Linux)
#define TARGET_NR_utime                 (30+TARGET_NR_Linux)
#define TARGET_NR_access                (33+TARGET_NR_Linux)
#define TARGET_NR_nice                  (34+TARGET_NR_Linux)
#define TARGET_NR_statfs                (35+TARGET_NR_Linux)
#define TARGET_NR_sync                  (36+TARGET_NR_Linux)
#define TARGET_NR_kill                  (37+TARGET_NR_Linux)
#define TARGET_NR_fstatfs               (38+TARGET_NR_Linux)
#define TARGET_NR_pgrpsys               (39+TARGET_NR_Linux)
#define	TARGET_NR_syssgi                (40+TARGET_NR_Linux)
#define TARGET_NR_dup                   (41+TARGET_NR_Linux)
#define TARGET_NR_pipe                  (42+TARGET_NR_Linux)
#define TARGET_NR_times                 (43+TARGET_NR_Linux)
#define TARGET_NR_profil                (44+TARGET_NR_Linux)
#define TARGET_NR_plock                 (45+TARGET_NR_Linux)
#define TARGET_NR_setgid                (46+TARGET_NR_Linux)
#define TARGET_NR_getgid                (47+TARGET_NR_Linux)
#define TARGET_NR_msgsys                (49+TARGET_NR_Linux)
#define TARGET_NR_sysmips               (50+TARGET_NR_Linux)
#define TARGET_NR_acct                  (51+TARGET_NR_Linux)
#define TARGET_NR_shmsys                (52+TARGET_NR_Linux)
#define TARGET_NR_semsys                (53+TARGET_NR_Linux)
#define TARGET_NR_ioctl                 (54+TARGET_NR_Linux)
#define TARGET_NR_uadmin                (55+TARGET_NR_Linux)
#define TARGET_NR_sysmp                 (56+TARGET_NR_Linux)
#define TARGET_NR_utssyssgi             (57+TARGET_NR_Linux)
#define TARGET_NR_execve                (59+TARGET_NR_Linux)
#define TARGET_NR_umask                 (60+TARGET_NR_Linux)
#define TARGET_NR_chroot                (61+TARGET_NR_Linux)
#define TARGET_NR_fcntl                 (62+TARGET_NR_Linux)
#define TARGET_NR_ulimit                (63+TARGET_NR_Linux)
#define	TARGET_NR_getrlimit64           (75+TARGET_NR_Linux)
#define	TARGET_NR_setrlimit64           (76+TARGET_NR_Linux)
#define	TARGET_NR_nanosleep             (77+TARGET_NR_Linux)
#define	TARGET_NR_lseek64               (78+TARGET_NR_Linux)
#define TARGET_NR_rmdir                 (79+TARGET_NR_Linux)
#define TARGET_NR_mkdir                 (80+TARGET_NR_Linux)
#define TARGET_NR_getdents              (81+TARGET_NR_Linux)
#define	TARGET_NR_sginap                (82+TARGET_NR_Linux)
#define	TARGET_NR_sgikopt               (83+TARGET_NR_Linux)
#define TARGET_NR_sysfs                 (84+TARGET_NR_Linux)
#define TARGET_NR_getmsg                (85+TARGET_NR_Linux)
#define TARGET_NR_putmsg                (86+TARGET_NR_Linux)
#define TARGET_NR_poll                  (87+TARGET_NR_Linux)
#define TARGET_NR_sigreturn             (88+TARGET_NR_Linux)
#define TARGET_NR_accept                (89+TARGET_NR_Linux)
#define TARGET_NR_bind                  (90+TARGET_NR_Linux)
#define TARGET_NR_connect               (91+TARGET_NR_Linux)
#define TARGET_NR_gethostid             (92+TARGET_NR_Linux)
#define TARGET_NR_getpeername           (93+TARGET_NR_Linux)
#define TARGET_NR_getsockname           (94+TARGET_NR_Linux)
#define TARGET_NR_getsockopt            (95+TARGET_NR_Linux)
#define TARGET_NR_listen                (96+TARGET_NR_Linux)
#define TARGET_NR_recv                  (97+TARGET_NR_Linux)
#define TARGET_NR_recvfrom              (98+TARGET_NR_Linux)
#define TARGET_NR_recvmsg               (99+TARGET_NR_Linux)
#define TARGET_NR_select                (100+TARGET_NR_Linux)
#define TARGET_NR_send                  (101+TARGET_NR_Linux)
#define TARGET_NR_sendmsg               (102+TARGET_NR_Linux)
#define TARGET_NR_sendto                (103+TARGET_NR_Linux)
#define TARGET_NR_sethostid             (104+TARGET_NR_Linux)
#define TARGET_NR_setsockopt            (105+TARGET_NR_Linux)
#define TARGET_NR_shutdown              (106+TARGET_NR_Linux)
#define TARGET_NR_socket                (107+TARGET_NR_Linux)
#define TARGET_NR_gethostname           (108+TARGET_NR_Linux)
#define TARGET_NR_sethostname           (109+TARGET_NR_Linux)
#define TARGET_NR_getdomainname         (110+TARGET_NR_Linux)
#define TARGET_NR_setdomainname         (111+TARGET_NR_Linux)
#define TARGET_NR_truncate              (112+TARGET_NR_Linux)
#define TARGET_NR_ftruncate             (113+TARGET_NR_Linux)
#define TARGET_NR_rename                (114+TARGET_NR_Linux)
#define	TARGET_NR_symlink               (115+TARGET_NR_Linux)
#define	TARGET_NR_readlink              (116+TARGET_NR_Linux)
#define	TARGET_NR_nfssvc                (119+TARGET_NR_Linux)
#define	TARGET_NR_getfh                 (120+TARGET_NR_Linux)
#define	TARGET_NR_async_daemons         (121+TARGET_NR_Linux)
#define	TARGET_NR_exportfs              (122+TARGET_NR_Linux)
#define TARGET_NR_setregid              (123+TARGET_NR_Linux)
#define TARGET_NR_setreuid              (124+TARGET_NR_Linux)
#define TARGET_NR_getitimer             (125+TARGET_NR_Linux)
#define TARGET_NR_setitimer             (126+TARGET_NR_Linux)
#define	TARGET_NR_adjtime               (127+TARGET_NR_Linux)
#define	TARGET_NR_gettimeofday          (128+TARGET_NR_Linux)
#define	TARGET_NR_sproc                 (129+TARGET_NR_Linux)
#define	TARGET_NR_sgiprctl              (130+TARGET_NR_Linux)
#define	TARGET_NR_procblk               (131+TARGET_NR_Linux)
#define	TARGET_NR_sprocsp               (132+TARGET_NR_Linux)
#define	TARGET_NR_mmap                  (134+TARGET_NR_Linux)
#define	TARGET_NR_munmap                (135+TARGET_NR_Linux)
#define	TARGET_NR_mprotect              (136+TARGET_NR_Linux)
#define	TARGET_NR_msync                 (137+TARGET_NR_Linux)
#define	TARGET_NR_madvise               (138+TARGET_NR_Linux)
#define	TARGET_NR_pagelock              (139+TARGET_NR_Linux)
#define	TARGET_NR_getpagesize           (140+TARGET_NR_Linux)
#define TARGET_NR_quotactl              (141+TARGET_NR_Linux)
#define TARGET_NR_getpgid               (143+TARGET_NR_Linux)
#define TARGET_NR_setpgid               (144+TARGET_NR_Linux)
#define TARGET_NR_vhangup               (145+TARGET_NR_Linux)
#define TARGET_NR_fsync                 (146+TARGET_NR_Linux)
#define TARGET_NR_fchdir                (147+TARGET_NR_Linux)
#define TARGET_NR_getrlimit             (148+TARGET_NR_Linux)
#define TARGET_NR_setrlimit             (149+TARGET_NR_Linux)
#define TARGET_NR_cacheflush            (150+TARGET_NR_Linux)
#define TARGET_NR_cachectl              (151+TARGET_NR_Linux)
#define TARGET_NR_fchown                (152+TARGET_NR_Linux)
#define TARGET_NR_fchmod                (153+TARGET_NR_Linux)
#define TARGET_NR_socketpair            (155+TARGET_NR_Linux)
#define TARGET_NR_sysinfosgi            (156+TARGET_NR_Linux)
#define TARGET_NR_uname                 (157+TARGET_NR_Linux)
#define TARGET_NR_xstat                 (158+TARGET_NR_Linux)
#define TARGET_NR_lxstat                (159+TARGET_NR_Linux)
#define TARGET_NR_fxstat                (160+TARGET_NR_Linux)
#define TARGET_NR_xmknod                (161+TARGET_NR_Linux)
#define TARGET_NR_sigaction             (162+TARGET_NR_Linux)
#define TARGET_NR_sigpending            (163+TARGET_NR_Linux)
#define TARGET_NR_sigprocmask           (164+TARGET_NR_Linux)
#define TARGET_NR_sigsuspend            (165+TARGET_NR_Linux)
#define TARGET_NR_sigpoll               (166+TARGET_NR_Linux)
#define TARGET_NR_swapctl               (167+TARGET_NR_Linux)
#define TARGET_NR_getcontext            (168+TARGET_NR_Linux)
#define TARGET_NR_setcontext            (169+TARGET_NR_Linux)
#define TARGET_NR_waitid                (170+TARGET_NR_Linux)
#define TARGET_NR_sigstack              (171+TARGET_NR_Linux)
#define TARGET_NR_sigaltstack           (172+TARGET_NR_Linux)
#define TARGET_NR_sigsendset            (173+TARGET_NR_Linux)
#define TARGET_NR_statvfs               (174+TARGET_NR_Linux)
#define TARGET_NR_fstatvfs              (175+TARGET_NR_Linux)
#define TARGET_NR_getpmsg               (176+TARGET_NR_Linux)
#define TARGET_NR_putpmsg               (177+TARGET_NR_Linux)
#define TARGET_NR_lchown                (178+TARGET_NR_Linux)
#define TARGET_NR_priocntl              (179+TARGET_NR_Linux)
#define TARGET_NR_ksigqueue             (180+TARGET_NR_Linux)
#define TARGET_NR_readv                 (181+TARGET_NR_Linux)
#define TARGET_NR_writev                (182+TARGET_NR_Linux)
#define	TARGET_NR_truncate64            (183+TARGET_NR_Linux)
#define	TARGET_NR_ftruncate64           (184+TARGET_NR_Linux)
#define	TARGET_NR_mmap64                (185+TARGET_NR_Linux)
#define	TARGET_NR_dmi                   (186+TARGET_NR_Linux)
#define	TARGET_NR_pread64               (187+TARGET_NR_Linux)
#define	TARGET_NR_pwrite64              (188+TARGET_NR_Linux)
#define	TARGET_NR_fdatasync             (189+TARGET_NR_Linux)
#define	TARGET_NR_sgifastpath           (190+TARGET_NR_Linux)
#define	TARGET_NR_attr_get              (191+TARGET_NR_Linux)
#define	TARGET_NR_attr_getf             (192+TARGET_NR_Linux)
#define	TARGET_NR_attr_set              (193+TARGET_NR_Linux)
#define	TARGET_NR_attr_setf             (194+TARGET_NR_Linux)
#define	TARGET_NR_attr_remove           (195+TARGET_NR_Linux)
#define	TARGET_NR_attr_removef          (196+TARGET_NR_Linux)
#define	TARGET_NR_attr_list             (197+TARGET_NR_Linux)
#define	TARGET_NR_attr_listf            (198+TARGET_NR_Linux)
#define	TARGET_NR_attr_multi            (199+TARGET_NR_Linux)
#define	TARGET_NR_attr_multif           (200+TARGET_NR_Linux)
#define	TARGET_NR_statvfs64             (201+TARGET_NR_Linux)
#define	TARGET_NR_fstatvfs64            (202+TARGET_NR_Linux)
#define	TARGET_NR_getmountid            (203+TARGET_NR_Linux)
#define	TARGET_NR_nsproc                (204+TARGET_NR_Linux)
#define	TARGET_NR_getdents64            (205+TARGET_NR_Linux)
#define	TARGET_NR_afs_syscall           (206+TARGET_NR_Linux)
#define	TARGET_NR_ngetdents             (207+TARGET_NR_Linux)
#define	TARGET_NR_ngetdents64           (208+TARGET_NR_Linux)
#define TARGET_NR_sgi_sesmgr            (209+TARGET_NR_Linux)
#define	TARGET_NR_pidsprocsp            (210+TARGET_NR_Linux)
#define TARGET_NR_rexec                 (211+TARGET_NR_Linux)
#define	TARGET_NR_timer_create          (212+TARGET_NR_Linux)
#define	TARGET_NR_timer_delete          (213+TARGET_NR_Linux)
#define	TARGET_NR_timer_settime         (214+TARGET_NR_Linux)
#define	TARGET_NR_timer_gettime         (215+TARGET_NR_Linux)
#define	TARGET_NR_timer_getoverrun      (216+TARGET_NR_Linux)
#define	TARGET_NR_sched_rr_get_interval (217+TARGET_NR_Linux)
#define	TARGET_NR_sched_yield           (218+TARGET_NR_Linux)
#define	TARGET_NR_sched_getscheduler    (219+TARGET_NR_Linux)
#define	TARGET_NR_sched_setscheduler    (220+TARGET_NR_Linux)
#define	TARGET_NR_sched_getparam        (221+TARGET_NR_Linux)
#define	TARGET_NR_sched_setparam        (222+TARGET_NR_Linux)
#define	TARGET_NR_usync_cntl            (223+TARGET_NR_Linux)
#define	TARGET_NR_psema_cntl            (224+TARGET_NR_Linux)
#define	TARGET_NR_restartreturn         (225+TARGET_NR_Linux)
#define TARGET_NR_sysget                (226+TARGET_NR_Linux)
#define TARGET_NR_xpg4_recvmsg          (227+TARGET_NR_Linux)
#define TARGET_NR_umfscall              (228+TARGET_NR_Linux)
#define	TARGET_NR_nsproctid             (229+TARGET_NR_Linux)
#define TARGET_NR_rexec_complete        (230+TARGET_NR_Linux)
#define TARGET_NR_xpg4_sigaltstack      (231+TARGET_NR_Linux)
#define TARGET_NR_xpg4_select           (232+TARGET_NR_Linux)
#define TARGET_NR_xpg4_setregid         (233+TARGET_NR_Linux)
#define	TARGET_NR_linkfollow            (234+TARGET_NR_Linux)


/* msgsys(cmd, ...), same as solaris... */
#define TARGET_NR_msgsys_msgget		0
#define TARGET_NR_msgsys_msgctl		1
#define TARGET_NR_msgsys_msgrcv		2
#define TARGET_NR_msgsys_msgsnd		3


/* shmsys(cmd, ...), same as solaris... */
#define TARGET_NR_shmsys_shmat		0
#define TARGET_NR_shmsys_shmctl		1
#define TARGET_NR_shmsys_shmdt		2
#define TARGET_NR_shmsys_shmget		3


/* semsys(cmd, ...), same as solaris... */
#define TARGET_NR_semsys_semctl		0
#define TARGET_NR_semsys_semget		1
#define TARGET_NR_semsys_semop		2


/* pgrpsys(cmd), same as solaris... */
#define TARGET_NR_pgrpsys_getpgrp	0
#define TARGET_NR_pgrpsys_setpgrp	1


/* syssgi(cmd, ...) */
#define TARGET_NR_syssgi_setsid       (20)
#define TARGET_NR_syssgi_setpgid      (21)
#define TARGET_NR_syssgi_sysconf      (22)
#define TARGET_NR_syssgi_pathconf     (23)
#define TARGET_NR_syssgi_setgroups    (40)
#define TARGET_NR_syssgi_getgroups    (41)
#define TARGET_NR_syssgi_settimeofday (52)
#define TARGET_NR_syssgi_rusage       (56)
#define TARGET_NR_syssgi_sigaltstack  (60)
#define TARGET_NR_syssgi_getpgid      (64)
#define TARGET_NR_syssgi_getsid       (65)
/* SGI specific syssgi calls */
#define TARGET_NR_syssgi_sysid        (1)
#define TARGET_NR_syssgi_elfmap       (68)
#define TARGET_NR_syssgi_getprocattr  (85)
#define TARGET_NR_syssgi_rldenv       (92)
#define TARGET_NR_syssgi_tosstsave    (108)
#define TARGET_NR_syssgi_fdhi         (109)
#define TARGET_NR_syssgi_fpbcopy      (129)
#define TARGET_NR_syssgi_getust       (130)


/* syssgi(sysconf, cmd, ...) */
#define TARGET_NR_sysconf_childmax (2)
#define TARGET_NR_sysconf_clktick  (3)
#define TARGET_NR_sysconf_openmax  (5)
#define TARGET_NR_sysconf_pagesize (11)
#define TARGET_NR_sysconf_nprocs   (14)
#define TARGET_NR_sysconf_acl      (25)
#define TARGET_NR_sysconf_mac      (28)
#define TARGET_NR_sysconf_cap      (29)


/* sysmp(cmd, ...) */
#define TARGET_NR_sysmp_nprocs  (1)
#define TARGET_NR_sysmp_naprocs (2)
#define TARGET_NR_sysmp_pgsize  (14)


/* prctl(cmd, ...) */
#define TARGET_NR_prctl_isblocked   (2)
#define TARGET_NR_prctl_maxpprocs   (5)
#define TARGET_NR_prctl_unblkonexec (6)
#define TARGET_NR_prctl_setexitsig  (8)
#define TARGET_NR_prctl_termchild   (12)
#define TARGET_NR_prctl_getnshare   (14)
#define TARGET_NR_prctl_initthreads (20)
#define TARGET_NR_prctl_threadctl   (21)
#define TARGET_NR_prctl_lastshexit  (22)


/* prctl(TARGET_NR_prctl_threadctl, cmd, ...) */
#define TARGET_NR_prctl_thread_exit    (1)
#define TARGET_NR_prctl_thread_block   (2)
#define TARGET_NR_prctl_thread_unblock (3)
#define TARGET_NR_prctl_thread_kill    (4)
#define TARGET_NR_prctl_thread_sched   (5)


/* procblk(cmd, ...) */
#define TARGET_NR_procblk_block         (0)
#define TARGET_NR_procblk_unblock       (1)
#define TARGET_NR_procblk_count         (2)


/* usync_cntl(cmd, ...), list from netbsd 5.2 */
#define TARGET_NR_usync_block           (1)
#define TARGET_NR_usync_intr_block      (2)
#define TARGET_NR_usync_unblock_all     (3)
#define TARGET_NR_usync_unblock         (4)
#define TARGET_NR_usync_notify_register (5)
#define TARGET_NR_usync_notify          (6)
#define TARGET_NR_usync_notify_delete   (7)
#define TARGET_NR_usync_notify_clear    (8)
#define TARGET_NR_usync_get_state       (11)
#define TARGET_NR_usync_handoff         (12)


/* psema_cntl(cmd, ...), list from /usr/sbin/par */
#define TARGET_NR_psema_open            (1)
#define TARGET_NR_psema_close           (2)
#define TARGET_NR_psema_unlink          (3)
#define TARGET_NR_psema_post            (4)
#define TARGET_NR_psema_wait            (5)
#define TARGET_NR_psema_trywait         (6)
#define TARGET_NR_psema_getvalue        (7)
#define TARGET_NR_psema_wait2           (9)


/* swapctl(cmd, arg) */
#define TARGET_NR_swapctl_getfree       (103)


/* sysinfosgi(cmd, buf, size) */
#define TARGET_NR_sysinfo_gethostname   2
#define TARGET_NR_sysinfo_sethostname   258
#define TARGET_NR_sysinfo_getsrpcdomain 9
#define TARGET_NR_sysinfo_setsrpcdomain 265
#define TARGET_NR_sysinfo_sysname       1
#define TARGET_NR_sysinfo_release       3
#define TARGET_NR_sysinfo_version       4
#define TARGET_NR_sysinfo_machine       5
#define TARGET_NR_sysinfo_cpuarch       6
#define TARGET_NR_sysinfo_hwserial      7
#define TARGET_NR_sysinfo_hwproducer    8

#define TARGET_NR_sysinfo_mips_vendor          100 /* return system provider */
#define TARGET_NR_sysinfo_mips_osprovider      101 /* return OS manufacturer */
#define TARGET_NR_sysinfo_mips_osname          102 /* return OS name */
#define TARGET_NR_sysinfo_mips_hwname          103 /* return system name */
#define TARGET_NR_sysinfo_mips_numprocessor    104 /* return number of processors */
#define TARGET_NR_sysinfo_mips_hostid          105 /* return hostid */
#define TARGET_NR_sysinfo_mips_osrelmaj        106 /* return OS major release number */
#define TARGET_NR_sysinfo_mips_osrelmin        107 /* return OS minor release number */
#define TARGET_NR_sysinfo_mips_osrelpatch      108 /* return OS release number */
#define TARGET_NR_sysinfo_mips_processors      109 /* return CPU revison id */
#define TARGET_NR_sysinfo_mips_availprocessors 110 /* return number of available processors */

/* utssyssgi(obuf, ibuf, cmd) */
#define TARGET_NR_utssys_uname          (0)
