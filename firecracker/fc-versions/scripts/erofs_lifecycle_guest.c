// SPDX-License-Identifier: Apache-2.0
// Minimal PID 1 for the opt-in Go EROFS lifecycle integration test. O_DIRECT
// reads verify the restored disk backend rather than a surviving guest cache.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sys/sysmacros.h>
#include <stdint.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void fail(const char *message)
{
	perror(message);
	for (;;) pause();
}

static void enter_cgroup(const char *name)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", name);
	if (mkdir(path, 0755) && errno != EEXIST) fail("create cgroup");
	snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.procs", name);
	int fd = open(path, O_WRONLY);
	if (fd < 0 || write(fd, "0", 1) != 1) fail("enter cgroup");
	close(fd);
}

static int check_filesystem(int mutate)
{
    const uint32_t capability[5] = {0x02000001, 1U << 13, 0, 0, 0};
    struct acl_entry { uint16_t tag, perm; uint32_t id; };
    const struct { uint32_t version; struct acl_entry entry[5]; } acl = {
        2, {{1,7,UINT32_MAX},{2,4,1001},{4,1,UINT32_MAX},{16,1,UINT32_MAX},{32,1,UINT32_MAX}}
    };
    if (mutate) {
        int protected_fd = open("/flag-immutable", O_CREAT | O_EXCL | O_RDWR, 0644);
        if (protected_fd < 0 || write(protected_fd, "fixed", 5) != 5 || link("/flag-immutable", "/flag-hard")) return 0;
        long flags = 0;
        if (ioctl(protected_fd, FS_IOC_GETFLAGS, &flags)) return 0;
        flags |= FS_IMMUTABLE_FL;
        if (ioctl(protected_fd, FS_IOC_SETFLAGS, &flags) || close(protected_fd)) return 0;
        protected_fd = open("/flag-append", O_CREAT | O_EXCL | O_RDWR, 0644);
        if (protected_fd < 0 || write(protected_fd, "base", 4) != 4 || ioctl(protected_fd, FS_IOC_GETFLAGS, &flags)) return 0;
        flags |= FS_APPEND_FL;
        if (ioctl(protected_fd, FS_IOC_SETFLAGS, &flags) || close(protected_fd)) return 0;
        if (chmod("/", 0711) || setxattr("/", "user.root-test", "root", 4, 0) ||
            setxattr("/", "system.posix_acl_access", &acl, sizeof(acl), 0)) return 0;
        int fd = open("/hard-a", O_WRONLY | O_TRUNC);
        if (fd < 0 || write(fd, "copied-up", 9) != 9 || fsync(fd) || close(fd)) return 0;
        if (unlink("/remove-me") || rename("/dir-before", "/dir-after")) return 0;
        fd = open("/export-cap", O_CREAT | O_EXCL | O_WRONLY, 0755);
        if (fd < 0 || write(fd, "fixture", 7) != 7 || close(fd)) return 0;
        if (setxattr("/export-cap", "security.capability", capability, sizeof(capability), 0)) return 0;
        if (setxattr("/export-cap", "user.e2b-test", "xattr", 5, 0)) return 0;
        if (mknod("/export-device", S_IFCHR | 0600, makedev(1, 3))) return 0;
        fd = open("/export-sparse", O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd < 0 || pwrite(fd, "tail", 4, 32 << 20) != 4 || fsync(fd) || close(fd)) return 0;
    }
    int protected_fd = open("/flag-immutable", O_RDONLY);
    long flags = 0;
    if (protected_fd < 0 || ioctl(protected_fd, FS_IOC_GETFLAGS, &flags) || !(flags & FS_IMMUTABLE_FL) || close(protected_fd)) return 0;
    errno = 0;
    protected_fd = open("/flag-immutable", O_WRONLY);
    if (protected_fd >= 0) { close(protected_fd); return 0; }
    if (errno != EPERM) return 0;
    protected_fd = open("/flag-append", O_RDONLY);
    if (protected_fd < 0 || ioctl(protected_fd, FS_IOC_GETFLAGS, &flags) || !(flags & FS_APPEND_FL) || close(protected_fd)) return 0;
    struct stat a, b, st;
    if (stat("/flag-immutable", &a) || stat("/flag-hard", &b) || a.st_ino != b.st_ino || a.st_dev != b.st_dev) return 0;
    char rootacl[sizeof(acl)], rootattr[4];
    if (stat("/", &st) || (st.st_mode & 07777) != 0711 ||
        getxattr("/", "user.root-test", rootattr, sizeof(rootattr)) != 4 || memcmp(rootattr, "root", 4) ||
        getxattr("/", "system.posix_acl_access", rootacl, sizeof(rootacl)) != sizeof(acl) || memcmp(rootacl, &acl, sizeof(acl))) return 0;
    if (stat("/hard-a", &a) || stat("/hard-b", &b) || a.st_dev != b.st_dev || a.st_ino != b.st_ino) return 0;
    char bytes[64] = {0};
    int fd = open("/hard-b", O_RDONLY);
    if (fd < 0 || read(fd, bytes, 9) != 9 || memcmp(bytes, "copied-up", 9) || close(fd)) return 0;
    if (!access("/remove-me", F_OK) || !access("/dir-before", F_OK) || access("/dir-after/child", R_OK)) return 0;
    uint32_t got[5];
    if (getxattr("/export-cap", "security.capability", got, sizeof(got)) != sizeof(got) || memcmp(got, capability, sizeof(got))) return 0;
    if (getxattr("/export-cap", "user.e2b-test", bytes, sizeof(bytes)) != 5 || memcmp(bytes, "xattr", 5)) return 0;
    if (stat("/export-device", &st) || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 3)) return 0;
    if (stat("/export-sparse", &st) || st.st_size != (32 << 20) + 4 || st.st_blocks * 512 > (1 << 20)) return 0;
    fd = open("/export-sparse", O_RDONLY);
    if (fd < 0 || pread(fd, bytes, 4, 32 << 20) != 4 || memcmp(bytes, "tail", 4) || close(fd)) return 0;
    return 1;
}

int main(void)
{
	setbuf(stdout, NULL);
	int pmem = access("/.e2b-rootfs/layout.json", R_OK) == 0 || access("/.e2b/rootfs/layout.json", R_OK) == 0;
	if (!pmem) {
		if (mount(NULL, "/", NULL, MS_REMOUNT, NULL)) fail("remount root writable");
		if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) && errno != EBUSY) fail("mount devtmpfs");
	} else {
		/* initramfs already moved dev/proc/sys into this root. Keep envd's
		 * control files off the upper we freeze during native capture. */
		if (mount("tmpfs", "/run", "tmpfs", 0, "mode=0755")) fail("mount run");
		if (mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, NULL)) fail("mount cgroup2");
	}
	if (access("/envd", X_OK) == 0) {
		if (!pmem) {
			if (mount("proc", "/proc", "proc", 0, NULL)) fail("mount proc");
			if (mount("sysfs", "/sys", "sysfs", 0, NULL)) fail("mount sysfs");
		}
		pid_t child = fork();
		if (child < 0) fail("fork envd");
		if (child == 0) {
			if (pmem) {
				enter_cgroup("envd");
				execl("/envd", "/envd", "--verbose", NULL);
				fail("exec pmem envd");
			}
			execl("/envd", "/envd", "--no-cgroups", "--verbose", NULL);
			fail("exec envd");
		}
	}
	if (pmem) {
		pid_t child = fork();
		if (child < 0) fail("fork workload");
		if (child > 0) {
			for (;;) { if (wait(NULL) < 0 && errno != EINTR) pause(); }
		}
		enter_cgroup("workload");
	}
	unsigned char *ram, *buffer;
	if (posix_memalign((void **)&ram, 4096, 3 * 4096) ||
	    posix_memalign((void **)&buffer, 4096, 3 * 4096)) fail("allocate pages");
	memset(ram, 0x31, 4096);
	memset(ram + 4096, 0x42, 4096);
	memset(ram + 8192, 0x53, 4096);
	memcpy(buffer, ram, 3 * 4096);
	int disk = open("/state.bin", O_CREAT | O_RDWR | O_DIRECT | O_SYNC, 0600);
	if (disk < 0 || pwrite(disk, buffer, 3 * 4096, 0) != 3 * 4096 || fsync(disk))
		fail("initialize disk");
	int root = open("/", O_RDONLY | O_DIRECTORY);
	if (root < 0 || fsync(root)) fail("sync root directory");
	close(root);
	int server = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	if (server < 0 || setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) fail("socket");
	struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(8080), .sin_addr.s_addr = INADDR_ANY};
	if (bind(server, (struct sockaddr *)&address, sizeof(address)) || listen(server, 8)) fail("listen");
	puts("EROFS-LIFECYCLE-READY");
	int generation = 0;
	for (;;) {
		int client = accept(server, NULL, NULL);
		if (client < 0) continue;
		char request[4096] = {0}, path[256] = {0};
		if (read(client, request, sizeof(request) - 1) <= 0) { close(client); continue; }
		sscanf(request, "GET %255s", path);
        if (!strcmp(path, "/fs/mutate") || !strcmp(path, "/fs/check")) {
            int ok = check_filesystem(!strcmp(path, "/fs/mutate"));
            const char *reply = ok ? "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nFS_OK\n" : "HTTP/1.1 500 Error\r\nContent-Length: 8\r\nConnection: close\r\n\r\nFS_FAIL\n";
            if (send(client, reply, strlen(reply), MSG_NOSIGNAL) < 0) perror("send fs result");
            close(client); continue;
        }

		if (!strcmp(path, "/write/1")) {
			memset(ram, 0xa6, 4096);
			memset(ram + 4096, 0, 4096);
			memcpy(buffer, ram, 8192);
			if (pwrite(disk, buffer, 8192, 0) != 8192) fail("write first generation");
			generation = 1;
		} else if (!strcmp(path, "/write/2") || !strcmp(path, "/write/b")) {
			unsigned char value = path[7] == 'b' ? 0xc8 : 0xb7;
			memset(ram + 8192, value, 4096);
			memset(buffer, value, 512);
			if (pwrite(disk, buffer, 512, 8192 + 512) != 512) fail("write partial block");
			generation = path[7] == 'b' ? 3 : 2;
		}
		if (fsync(disk)) fail("sync disk");
		if (pread(disk, buffer, 3 * 4096, 0) != 3 * 4096) fail("read disk directly");
		char body[256], response[512];
		int bytes = snprintf(body, sizeof(body),
			"{\"generation\":%d,\"memory\":[%u,%u,%u],\"disk\":[%u,%u,%u],\"partial\":%u}\n",
			generation, ram[0], ram[4096], ram[8192], buffer[0], buffer[4096], buffer[8192], buffer[8192 + 512]);
		int length = snprintf(response, sizeof(response),
			"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", bytes, body);
		if (send(client, response, length, MSG_NOSIGNAL) < 0) perror("send response");
		close(client);
	}
}
