#!/usr/bin/env python3
"""Measure Guest memory used by attaching pmem, without a filesystem workload.

Run separately from Agent measurements. Uses the pinned FC/kernel/BusyBox,
identical initramfs/RAM/vCPU for control and pmem guests, and empty sparse
backing files. No mounts, NBD, network or model calls on the Host.
"""
import argparse
import gzip
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import time


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


def archive(entries):
    result = bytearray()
    for ino, (name, mode, data) in enumerate(entries + [('TRAILER!!!', 0, b'')], 1):
        name = name.encode() + b'\0'
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
        result += b'070701' + ''.join(f'{v:08x}' for v in fields).encode() + name
        result += b'\0' * (-len(result) % 4)
        result += data
        result += b'\0' * (-len(result) % 4)
    return bytes(result)


INIT = b'''#!/bin/busybox sh
set -eu
BB=/bin/busybox
$BB mount -t proc proc /proc
$BB mount -t sysfs sysfs /sys
$BB mount -t devtmpfs devtmpfs /dev
# Fixed settling time in both arms; includes asynchronous namespace discovery.
$BB sleep 5
echo E2B_METADATA_MEMINFO_BEGIN
$BB cat /proc/meminfo
echo E2B_METADATA_MEMINFO_END
echo E2B_METADATA_PMEM_SIZE_BEGIN
if test -e /sys/block/pmem0/size; then $BB cat /sys/block/pmem0/size; else echo 0; fi
echo E2B_METADATA_PMEM_SIZE_END
echo E2B_METADATA_DMESG_BEGIN
$BB dmesg
echo E2B_METADATA_DONE
while true; do $BB sleep 3600; done
'''


def run(args, name, size):
    directory = args.out / name
    directory.mkdir()
    sock = directory / 'api'
    if len(os.fsencode(sock)) >= 104:
        raise ValueError('output path exceeds Unix socket limit')
    if size:
        with (directory / 'pmem.raw').open('xb') as backing:
            backing.truncate(size)
    log = directory / 'console.log'
    started = time.monotonic()
    with log.open('xb') as output:
        process = subprocess.Popen([str(args.firecracker), '--api-sock', str(sock)],
                                   stdout=output, stderr=subprocess.STDOUT)
        try:
            def api(path, data):
                client = UnixHTTP(str(sock), timeout=10)
                try:
                    client.request('PUT', path, json.dumps(data), {'Content-Type': 'application/json'})
                    response = client.getresponse()
                    content = response.read()
                    if response.status != 204:
                        raise RuntimeError(f'{path}: {response.status}: {content!r}')
                finally:
                    client.close()
            deadline = time.monotonic() + 15
            while not sock.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f'FC did not start: {log}')
                time.sleep(.05)
            api('/machine-config', {'vcpu_count': 1, 'mem_size_mib': args.ram_mib,
                                     'track_dirty_pages': True, 'huge_pages': 'None'})
            api('/boot-source', {'kernel_image_path': str(args.kernel),
                                'initrd_path': str(args.out / 'probe.cpio.gz'),
                                'boot_args': 'console=ttyS0 reboot=k panic=1 pci=off rdinit=/init'})
            if size:
                api('/pmem/lower', {'id': 'lower', 'path_on_host': str(directory / 'pmem.raw'),
                                   'read_only': True, 'root_device': False})
            api('/actions', {'action_type': 'InstanceStart'})
            deadline = time.monotonic() + 45
            while True:
                text = log.read_text(errors='replace')
                if 'E2B_METADATA_DONE' in text:
                    break
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f'Guest probe incomplete: {log}')
                time.sleep(.1)
            section = text.split('E2B_METADATA_MEMINFO_BEGIN\n', 1)[1].split('E2B_METADATA_MEMINFO_END', 1)[0]
            meminfo = {line.split(':')[0]: int(line.split()[1]) for line in section.splitlines() if ':' in line}
            sectors = int(text.split('E2B_METADATA_PMEM_SIZE_BEGIN\n', 1)[1].split('E2B_METADATA_PMEM_SIZE_END', 1)[0].strip())
            if bool(sectors) != bool(size):
                raise RuntimeError('Guest pmem enumeration differs from configured arm')
            # Namespace metadata may reserve a prefix; retain actual exposed size.
            result = {'name': name, 'configured_pmem_bytes': size, 'guest_pmem_bytes': sectors * 512,
                      'ram_mib': args.ram_mib, 'meminfo_kib': meminfo, 'seconds': time.monotonic()-started}
            (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            return result
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firecracker', type=Path, required=True)
    p.add_argument('--kernel', type=Path, required=True)
    p.add_argument('--busybox', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--pmem-bytes', type=int, nargs='+', required=True)
    p.add_argument('--ram-mib', type=int, default=2048)
    p.add_argument('--repeats', type=int, default=3)
    args = p.parse_args()
    for key in ('firecracker', 'kernel', 'busybox', 'out'):
        setattr(args, key, getattr(args, key).absolute())
    if args.repeats < 1 or args.ram_mib < 128 or any(n <= 0 or n % (2 << 20) for n in args.pmem_bytes):
        p.error('positive repeats, RAM >=128 MiB and positive 2 MiB-aligned pmem sizes required')
    args.out.mkdir(parents=True, exist_ok=False)
    entries = [(name, stat.S_IFDIR | 0o755, b'') for name in ('bin', 'proc', 'sys', 'dev')]
    entries += [('bin/busybox', stat.S_IFREG | 0o755, args.busybox.read_bytes()),
                ('init', stat.S_IFREG | 0o755, INIT)]
    (args.out / 'probe.cpio.gz').write_bytes(gzip.compress(archive(entries), mtime=0))
    results = []
    for repeat in range(args.repeats):
        for size in [0, *args.pmem_bytes]:
            results.append(run(args, f'r{repeat}-{size}', size))
            (args.out / 'report.json').write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps({'case': results[-1]['name'], 'status': 'completed'}), flush=True)


if __name__ == '__main__':
    os.umask(0o077)
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    main()
