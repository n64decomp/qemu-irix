/** Shim for macOS lack of POSIX `timer_*` functions and types
 * Right now, the timers don't seem to match IRIX anyways, so
 * these are all stub functions.
 * 
 * The irix timer_t function is a struct, but `tagert_timer_t` is
 * defined for Linux qemu-irix as an int...
 * 
 * For later: 
 *  https://nitschinger.at/Scheduling-Timers-on-OS-X-with-Rust-and-Kqueue/
 *  https://pubs.opengroup.org/onlinepubs/9699919799/functions/timer_getoverrun.html
 */

#include <errno.h>
#include <time.h>
#include <sys/signal.h>

#include "shim_timers.h"


int timer_create(clockid_t clockid, struct sigevent *evp, timer_t *timerid) {
    errno = EINVAL;
    return -1;
}

int timer_delete(timer_t timerid) {
    return 0;
}

int timer_getoverrun(timer_t timerid) {
    errno = EINVAL;
    return -1;
}

int timer_gettime(timer_t timerid, struct itimerspec *value) {
    errno = EINVAL;
    return -1;
}

int timer_settime(
    timer_t timerid, 
    int flags, 
    const struct itimerspec *value,
    struct itimerspec *ovalue
){
    errno = EINVAL;
    return -1;
}
