/** Shim for macOS lack of `fallocate`
 * Based on:
 * https://stackoverflow.com/questions/11497567/fallocate-command-equivalent-in-os-x
 */

#include <fcntl.h>

#include "shim_fallocate.h"

/** This emulates the Linux fallocate, so the errno is set, not returned
 * as in Posix
 */ 
int shim_fallocate(int fd, int mode, off_t offset, off_t len) {
    if (mode == SHIM_FALLOC_DEFAULT) {
        fstore_t store = {F_ALLOCATECONTIG | F_ALLOCATEALL, F_PEOFPOSMODE, 0, len, 0};
        // Try to get a continous chunk of disk space
        int ret = fcntl(fd, F_PREALLOCATE, &store);
        // If too fragmented, allocated non-continous
        if (ret == -1) {
            store.fst_flags = F_ALLOCATEALL;
            ret = fcntl(fd, F_PREALLOCATE, &store);
        }

        return ret;
    } else if (mode == SHIM_FALLOC_FL_PUNCH_HOLE) {
        fpunchhole_t hole = {0, 0, offset, len};
        int ret = fcntl(fd, F_PUNCHHOLE, &hole);

        return ret;
    } else {
        // TODO: set errno EINVAL, but this should be unreachable
        return -1;
    }
}
