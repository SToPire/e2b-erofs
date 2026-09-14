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
#include <unistd.h>

static void fail(const char *message)
{
	perror(message);
	for (;;) pause();
}

int main(void)
{
	setbuf(stdout, NULL);
	if (mount(NULL, "/", NULL, MS_REMOUNT, NULL)) fail("remount root writable");
	if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) && errno != EBUSY) fail("mount devtmpfs");
	if (access("/envd", X_OK) == 0) {
		if (mount("proc", "/proc", "proc", 0, NULL)) fail("mount proc");
		if (mount("sysfs", "/sys", "sysfs", 0, NULL)) fail("mount sysfs");
		pid_t child = fork();
		if (child < 0) fail("fork envd");
		if (child == 0) {
			execl("/envd", "/envd", "--no-cgroups", "--verbose", NULL);
			fail("exec envd");
		}
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
		(void)write(client, response, length);
		close(client);
	}
}
