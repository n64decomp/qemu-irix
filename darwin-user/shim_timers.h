#ifndef SHIM_TIMERS_H
#define SHIM_TIMERS_H

#include <sys/types.h>
#include <time.h>

struct itimerspec {
    struct timespec it_interval;    /* timer period */
    struct timespec it_value;       /* timer expiration */
};

typedef int timer_t;

int timer_create(clockid_t, struct sigevent *, timer_t *);
int timer_delete(timer_t);
int timer_getoverrun(timer_t);
int timer_gettime(timer_t, struct itimerspec *);
int timer_settime(timer_t, int, const struct itimerspec *, struct itimerspec *);

#endif /* SHIM_TIMERS_H */
