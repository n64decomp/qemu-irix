#include <sys/types.h>
#include <pthread.h>

#include <shim_gettid.h>


/* Implement this syscall based on:
 * http://elliotth.blogspot.com/2012/04/gettid-on-mac-os.html
 * Linux macro: 
 *   #define __NR_sys_gettid __NR_gettid
 *   _syscall0(int, sys_gettid)
 * */
int shim_gettid(void) {
    uintptr_t tid = (uintptr_t)pthread_self();

    return (int)tid;
}
