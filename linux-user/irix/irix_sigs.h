#ifndef IRIX_SIGS_H
#define IRIX_SIGS_H

#define	IRIX_SIGHUP	1	/* hangup */
#define	IRIX_SIGINT	2	/* interrupt (rubout) */
#define	IRIX_SIGQUIT	3	/* quit (ASCII FS) */
#define	IRIX_SIGILL	4	/* illegal instruction (not reset when caught)*/
#define	IRIX_SIGTRAP	5	/* trace trap (not reset when caught) */
#define	IRIX_SIGIOT	6	/* IOT instruction */
#define SIGABRT 6	/* used by abort, replace SIGIOT in the  future */
#define	IRIX_SIGEMT	7	/* EMT instruction */
#define	IRIX_SIGFPE	8	/* floating point exception */
#define	IRIX_SIGKILL	9	/* kill (cannot be caught or ignored) */
#define	IRIX_SIGBUS	10	/* bus error */
#define	IRIX_SIGSEGV	11	/* segmentation violation */
#define	IRIX_SIGSYS	12	/* bad argument to system call */
#define	IRIX_SIGPIPE	13	/* write on a pipe with no one to read it */
#define	IRIX_SIGALRM	14	/* alarm clock */
#define	IRIX_SIGTERM	15	/* software termination signal from kill */
#define	IRIX_SIGUSR1	16	/* user defined signal 1 */
#define	IRIX_SIGUSR2	17	/* user defined signal 2 */
#define	IRIX_SIGCLD	18	/* death of a child */
#define IRIX_SIGCHLD SIGCLD	/* 4.3BSD's name */
#define	IRIX_SIGPWR	19	/* power-fail restart */

/* 4.3BSD job control */
#define	IRIX_SIGSTOP	20	/* sendable stop signal not from tty */
#define	IRIX_SIGTSTP	21	/* stop signal from tty */

#define IRIX_SIGPOLL 22	/* pollable event occurred */

/* 4.3BSD signals */
#define	IRIX_SIGIO	23	/* input/output possible signal */
#define	IRIX_SIGURG	24	/* urgent condition on IO channel */
#define	IRIX_SIGWINCH 25	/* window size changes */
#define IRIX_SIGVTALRM 26	/* virtual time alarm */
#define IRIX_SIGPROF	27	/* profiling alarm */

/* 4.3BSD job control */
#define	IRIX_SIGCONT	28	/* continue a stopped process */
#define	IRIX_SIGTTIN	29	/* to readers pgrp upon background tty read */
#define	IRIX_SIGTTOU	30	/* like TTIN for output if (tp->t_local&LTOSTOP) */

/* 4.3BSD CPU- and Filesize-limit signals */
#define IRIX_SIGXCPU	31	/* Cpu time limit exceeded */
#define IRIX_SIGXFSZ	32	/* Filesize limit exceeded */

#endif /* IRIX_SIGS_H */
