// SPDX-License-Identifier: Apache-2.0
// Minimal initramfs PID 1 for validate_native_memory.py. Physical pages are
// reserved with memmap= so Linux never allocates or modifies these test pages.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <termios.h>
#include <unistd.h>

static void fail(const char *message)
{
	perror(message);
	puts("NATIVE-FAIL");
	for (;;) pause();
}

static unsigned char *page(int fd, uint64_t address)
{
	void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, address);
	if (p == MAP_FAILED) fail("mmap reserved RAM");
	return p;
}

static void expect(unsigned char *p, unsigned char byte)
{
	for (int i = 0; i < 4096; ++i)
		if (p[i] != byte) fail("RAM contents mismatch");
}

static char command(void)
{
	char ch;
	if (read(0, &ch, 1) != 1) fail("read command");
	return ch;
}

int main(void)
{
	setbuf(stdout, NULL);
	if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL)) fail("mount /dev");
	int console = open("/dev/ttyS0", O_RDWR);
	if (console < 0) fail("open console");
	struct termios settings;
	if (tcgetattr(console, &settings)) fail("tcgetattr");
	cfmakeraw(&settings);
	if (tcsetattr(console, TCSANOW, &settings)) fail("tcsetattr");
	for (int i = 0; i < 3; ++i)
		if (dup2(console, i) < 0) fail("dup console");
	int fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) fail("open /dev/mem");
	unsigned char *low = page(fd, 0x40000000ULL);
	unsigned char *tail = page(fd, 0xbffff000ULL);
	unsigned char *high = page(fd, 0x100000000ULL);
	unsigned char *zero = page(fd, 0x100001000ULL);
	unsigned char *inherited = page(fd, 0x100002000ULL);
	memset(low, 0x31, 4096);
	memset(tail, 0x42, 4096);
	memset(high, 0x53, 4096);
	memset(zero, 0x64, 4096);
	memset(inherited, 0x75, 4096);
	puts("NATIVE-READY-0");
	command();
	memset(high, 0xa6, 4096);
	memset(zero, 0, 4096);
	int rng = open("/dev/hwrng", O_RDONLY);
	if (rng < 0) fail("open virtio-rng");
	unsigned char entropy[4096];
	if (read(rng, entropy, sizeof(entropy)) <= 0) fail("read virtio-rng");
	close(rng);
	puts("NATIVE-READY-1");
	char branch = command();
	expect(low, 0x31);
	expect(tail, 0x42);
	expect(high, 0xa6);
	expect(zero, 0);
	expect(inherited, 0x75);
	unsigned char inherited_byte = branch == 'b' ? 0xc8 : 0xb7;
	memset(inherited, inherited_byte, 4096);
	puts(branch == 'b' ? "NATIVE-BRANCH-READY-2" : "NATIVE-READY-2");
	command();
	expect(low, 0x31);
	expect(tail, 0x42);
	expect(high, 0xa6);
	expect(zero, 0);
	expect(inherited, inherited_byte);
	puts("NATIVE-PASS");
	for (;;) pause();
}
