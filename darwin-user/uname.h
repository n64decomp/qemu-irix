#ifndef UNAME_H
#define UNAME_H

#include <sys/utsname.h>

const char *cpu_to_uname_machine(void *cpu_env);
int sys_uname(struct utsname *buf);

#endif /* UNAME_H */
