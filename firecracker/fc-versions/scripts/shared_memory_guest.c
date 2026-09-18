// SPDX-License-Identifier: Apache-2.0
// PID 1 for validate_shared_memory.py; reserve 64M at GPA 1G with memmap=.
#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <termios.h>
#include <unistd.h>

#define SIZE (64UL << 20)
#define WORDS (SIZE / sizeof(uint64_t))
#define PAGE_WORDS (4096 / sizeof(uint64_t))

static void fail(const char *message)
{
	perror(message);
	puts("NATIVE-FAIL");
	for (;;) pause();
}

static uint64_t next(uint64_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 7;
	*state ^= *state << 17;
	return *state;
}

int main(void)
{
	setbuf(stdout, NULL);
	if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL)) fail("mount /dev");
	int console = open("/dev/ttyS0", O_RDWR);
	if (console < 0) fail("console");
	struct termios settings;
	if (tcgetattr(console, &settings)) fail("tcgetattr");
	cfmakeraw(&settings);
	if (tcsetattr(console, TCSANOW, &settings)) fail("tcsetattr");
	for (int i = 0; i < 3; ++i)
		if (dup2(console, i) < 0) fail("dup2");
	int fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) fail("/dev/mem");
	volatile uint64_t *memory = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
		MAP_SHARED, fd, 0x40000000ULL);
	if (memory == MAP_FAILED) fail("mmap reserved RAM");
	close(fd);
	// Reproducible pseudorandom words: every page differs; no zero pages.
	uint64_t state = UINT64_C(0x739a21d6bc850ef1);
	for (size_t i = 0; i < WORDS; ++i) memory[i] = next(&state);
	if (mprotect((void *)memory, SIZE, PROT_READ)) fail("read-only RAM");
	puts("SHARED-READY");
	int mutated = 0;
	for (unsigned sequence = 1;; ++sequence) {
		char command;
		if (read(0, &command, 1) != 1) fail("command");
		if (command == 'w' && !mutated) {
			if (mprotect((void *)memory, SIZE, PROT_READ | PROT_WRITE)) fail("writable RAM");
			for (size_t i = 0; i < WORDS; i += 16 * PAGE_WORDS)
				memory[i] ^= UINT64_C(0xff);
			if (mprotect((void *)memory, SIZE, PROT_READ)) fail("read-only RAM");
			mutated = 1;
		} else if (command != 'r') {
			fail("unexpected command");
		}
		state = UINT64_C(0x739a21d6bc850ef1);
		uint64_t sum = 0;
		for (size_t i = 0; i < WORDS; ++i) {
			uint64_t expected = next(&state);
			if (mutated && i % (16 * PAGE_WORDS) == 0) expected ^= UINT64_C(0xff);
			uint64_t actual = memory[i]; // Actual guest reads populate KVM/EPT mappings.
			if (actual != expected) fail("reserved RAM mismatch");
			sum += actual;
		}
		printf("SHARED-DONE-%u %016" PRIx64 "\n", sequence, sum);
	}
}
