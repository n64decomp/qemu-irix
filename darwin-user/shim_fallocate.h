#ifndef SHIM_FALLOCATE_H
#define SHIM_FALLOCATE_H

#include <sys/types.h>

int shim_fallocate(int fd, int mode, off_t offset, off_t len);

enum FALLOCATE_SHIM_MODES {
    SHIM_FALLOC_DEFAULT = 0,
    SHIM_FALLOC_FL_PUNCH_HOLE
};

#endif /* SHIM_FALLOCATE_H */