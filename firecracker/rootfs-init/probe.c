/* Guest PID 1 for the opt-in pmem/OverlayFS lifecycle integration test. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned generation;
static int original;
static unsigned char *mapping;
static size_t mapping_size;
static unsigned char *private_mapping, *shared_mapping;

static void fail(const char *message)
{
    printf("P0_FAIL: %s: %s\n", message, strerror(errno));
    exit(1);
}

static void expect_file(const char *path, const char *expected)
{
    char buffer[128] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0 || read(fd, buffer, sizeof(buffer) - 1) < 0)
        fail(path);
    close(fd);
    if (strcmp(buffer, expected))
        fail("unexpected file contents");
}

static void report(void)
{
    char expected[64], original_bytes[64] = {0};
    uint64_t entry, region;
    FILE *resource = fopen("/sys/bus/nd/devices/region0/resource", "r");
    if (!resource || fscanf(resource, "%" SCNx64, &region) != 1)
        fail("pmem resource");
    fclose(resource);
    int pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap < 0)
        fail("pagemap");
    if (generation)
        snprintf(expected, sizeof(expected), "generation-%u\n", generation);
    else
        snprintf(expected, sizeof(expected), "original\n");
    if (pread(original, original_bytes, sizeof(original_bytes) - 1, 0) < 0 ||
        strcmp(original_bytes, expected))
        fail("open descriptor does not follow file contents");
    if (generation) {
        snprintf(expected, sizeof(expected), "generation-%u\n", generation);
        expect_file("/sample", expected);
        expect_file("/sample-link", expected);
        if (access("/deleted", F_OK) == 0 || access("/renamed/child", F_OK) != 0)
            fail("whiteout or directory redirect lost");
    } else {
        expect_file("/sample", "original\n");
        expect_file("/deleted", "delete-me\n");
    }
    expect_file("/sample-symlink", expected);
    char appended[64] = "base";
    for (unsigned i = 0; i < generation; i++)
        appended[4 + i] = '+';
    expect_file("/append", appended);
    unsigned char private_byte, shared_byte;
    int private_fd = open("/mmap-private", O_RDONLY);
    int shared_fd = open("/mmap-shared", O_RDONLY);
    if (private_fd < 0 || shared_fd < 0 ||
        read(private_fd, &private_byte, 1) != 1 || read(shared_fd, &shared_byte, 1) != 1)
        fail("read mapped files");
    close(private_fd);
    close(shared_fd);
    if (private_byte != 'P' || private_mapping[0] != (generation ? 'a' + generation : 'P') ||
        shared_byte != '0' + generation || shared_mapping[0] != shared_byte)
        fail("private/shared mmap state or persistence");
    if (generation && (access("/opaque/old", F_OK) == 0 ||
        access("/.e2b-rootfs/lower/opaque/old", F_OK) != 0))
        fail("opaque directory lost or lower changed");
    struct statx st;
    if (statx(AT_FDCWD, "/.e2b-rootfs/lower/bin/busybox", 0, STATX_BASIC_STATS, &st) ||
        !(st.stx_attributes & STATX_ATTR_DAX))
        fail("lower binary is not DAX");
    volatile unsigned char checksum = 0;
    for (size_t offset = 0; offset < mapping_size; offset += 4096)
        checksum ^= mapping[offset];
    printf("P0_STATE: {\"generation\":%u,\"region_start\":%" PRIu64
           ",\"checksum\":%u,\"gfns\":[", generation, region, checksum);
    for (size_t offset = 0; offset < mapping_size; offset += 4096) {
        off_t index = ((uintptr_t)(mapping + offset) / 4096) * 8;
        if (pread(pagemap, &entry, sizeof(entry), index) != sizeof(entry) || !(entry >> 63))
            fail("nonresident guest mapping");
        printf("%s%" PRIu64, offset ? "," : "", entry & ((UINT64_C(1) << 55) - 1));
    }
    puts("]}");
    close(pagemap);
}

static void mutate(void)
{
    char data[64];
    generation++;
    int fd = open("/sample", O_WRONLY | O_TRUNC);
    int length = snprintf(data, sizeof(data), "generation-%u\n", generation);
    if (fd < 0 || write(fd, data, length) != length || fsync(fd))
        fail("copy-up write");
    close(fd);
    fd = open("/append", O_WRONLY | O_APPEND);
    if (fd < 0 || write(fd, "+", 1) != 1 || fsync(fd))
        fail("append");
    close(fd);
    private_mapping[0] = 'a' + generation;
    shared_mapping[0] = '0' + generation;
    if (msync(shared_mapping, 4096, MS_SYNC))
        fail("flush shared mmap");
    if (generation == 1 && (unlink("/deleted") || rename("/directory", "/renamed")))
        fail("whiteout/rename");
    if (generation == 1 && (unlink("/opaque/old") || rmdir("/opaque") || mkdir("/opaque", 0755)))
        fail("replace lower directory with opaque directory");
    sync();
    report();
}

int main(void)
{
    char command[32];
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    original = open("/sample", O_RDONLY);
    int binary = open("/bin/busybox", O_RDONLY);
    struct stat info;
    if (original < 0 || binary < 0 || fstat(binary, &info))
        fail("open fixture");
    mapping_size = info.st_size;
    mapping = mmap(NULL, mapping_size, PROT_READ, MAP_PRIVATE, binary, 0);
    if (mapping == MAP_FAILED)
        fail("mmap busybox through overlay");
    close(binary);
    int private_fd = open("/mmap-private", O_RDONLY);
    int shared_fd = open("/mmap-shared", O_RDWR);
    if (private_fd < 0 || shared_fd < 0)
        fail("open mmap fixtures");
    private_mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, private_fd, 0);
    shared_mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);
    if (private_mapping == MAP_FAILED || shared_mapping == MAP_FAILED)
        fail("writable private/shared mmap through overlay");
    close(private_fd);
    close(shared_fd);
    pid_t child = fork();
    if (child < 0)
        fail("fork");
    if (!child) {
        execl("/bin/busybox", "busybox", "echo", "P0_EXEC_OK", NULL);
        _exit(127);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        fail("execute lower binary");
    report();
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "state\n"))
            report();
        else if (!strcmp(command, "mutate\n"))
            mutate();
        else
            fail("unknown command");
    }
    fail("console closed");
}
