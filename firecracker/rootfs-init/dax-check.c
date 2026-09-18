#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct statx result;
    if (argc != 4 || (strcmp(argv[1], "dax") && strcmp(argv[1], "exec"))) {
        fprintf(stderr, "usage: dax-check <dax|exec> <root> <guest-file>\n");
        return 2;
    }
    // Resolve absolute symlinks (notably /sbin/init) inside the target root.
    if (chroot(argv[2]) || chdir("/")) {
        perror("enter Guest root");
        return 1;
    }
    if (statx(AT_FDCWD, argv[3], AT_STATX_SYNC_AS_STAT, STATX_BASIC_STATS,
              &result) != 0) {
        perror("statx lower");
        return 1;
    }
    if (!S_ISREG(result.stx_mode) || !(result.stx_mode & 0111)) {
        fprintf(stderr, "Guest init is not an executable regular file: %s\n", argv[3]);
        return 1;
    }
    if (!strcmp(argv[1], "dax") && (!(result.stx_attributes_mask & STATX_ATTR_DAX) ||
        !(result.stx_attributes & STATX_ATTR_DAX))) {
        fprintf(stderr, "lower file does not have STATX_ATTR_DAX: %s\n", argv[3]);
        return 1;
    }
    return 0;
}
