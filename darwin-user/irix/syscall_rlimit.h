/* Irix resource limit values from sys/resource.h
 * included in syscall_defs.h
 * */

#define	TARGET_RLIMIT_CPU    0     /* cpu time in milliseconds */
#define	TARGET_RLIMIT_FSIZE  1     /* maximum file size */
#define	TARGET_RLIMIT_DATA   2     /* data size */
#define	TARGET_RLIMIT_STACK  3     /* stack size */
#define	TARGET_RLIMIT_CORE   4     /* core file size */
#define TARGET_RLIMIT_NOFILE 5     /* file descriptors */
#define TARGET_RLIMIT_VMEM   6     /* maximum mapped memory */
#define	TARGET_RLIMIT_RSS    7     /* resident set size */
#define TARGET_RLIMIT_AS     TARGET_RLIMIT_VMEM

#define	TARGETRLIM_NLIMITS  8     /* number of resource limits */

// TODO: set these according to bits in long (32 vs 64)?
#define	TARGET_RLIM_INFINITY    0x7fffffff
#define TARGET_RLIM64_INFINITY  0x7fffffffffffffffull
