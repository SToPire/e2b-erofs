#!/usr/bin/env python3
"""Build a reproducible newc initramfs containing a static BusyBox and /init."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile


def check_static_elf(data: bytes) -> None:
    if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
        raise ValueError('BusyBox must be a little-endian ELF64 binary')
    if struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('BusyBox must target x86_64')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    if phentsize < 56 or phnum == 0 or phoff + phentsize * phnum > len(data):
        raise ValueError('invalid ELF program headers')
    for index in range(phnum):
        if struct.unpack_from('<I', data, phoff + index * phentsize)[0] == 3:
            raise ValueError('BusyBox has an ELF interpreter; a static binary is required')


def archive(busybox: bytes, init: bytes, dax_check: bytes, rootfs_copy: bytes = b'') -> bytes:
    out = io.BytesIO()
    inode = 0

    def entry(name: str, mode: int, data: bytes = b'') -> None:
        nonlocal inode
        inode += 1
        encoded = name.encode() + b'\0'
        values = (inode, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0,
                  len(data), 0, 0, 0, 0, len(encoded), 0)
        out.write(b'070701' + b''.join(f'{v:08x}'.encode() for v in values))
        out.write(encoded)
        out.write(b'\0' * (-out.tell() % 4))
        out.write(data)
        out.write(b'\0' * (-out.tell() % 4))

    for name in ('bin', 'dev', 'proc', 'sys', 'state', 'newroot', 'export'):
        entry(name, stat.S_IFDIR | 0o755)
    entry('bin/busybox', stat.S_IFREG | 0o755, busybox)
    entry('bin/dax-check', stat.S_IFREG | 0o755, dax_check)
    if rootfs_copy:
        entry('bin/rootfs-copy', stat.S_IFREG | 0o755, rootfs_copy)
        entry('export-init', stat.S_IFREG | 0o755,
              b'#!/bin/busybox sh\nexport E2B_EXPORT_ONLY=1\nexec /init\n')
    entry('bin/sh', stat.S_IFLNK | 0o777, b'busybox')
    entry('init', stat.S_IFREG | 0o755, init)
    if rootfs_copy:
        entry('e2b-rootfs.json', stat.S_IFREG | 0o644,
              b'{"layout":"pmem-overlay-raw-v1","export_version":2,"root_metadata_version":2}\n')
    entry('TRAILER!!!', 0)
    return gzip.compress(out.getvalue(), mtime=0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--busybox', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default='gcc', help='C compiler with static x86_64 libc')
    args = parser.parse_args()
    busybox = args.busybox.read_bytes()
    check_static_elf(busybox)
    init = Path(__file__).with_name('init').read_bytes()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='e2b-init-build-') as directory:
        executable = Path(directory) / 'dax-check'
        subprocess.run([args.cc, '-static', '-Os', '-Wall', '-Wextra', '-Werror',
                        '-Wl,--build-id=none', '-o', str(executable),
                        str(Path(__file__).with_name('dax-check.c'))], check=True)
        dax_check = executable.read_bytes()
        check_static_elf(dax_check)
        subprocess.run([args.cc, '-static', '-Os', '-Wall', '-Wextra', '-Werror',
                        '-Wl,--build-id=none', '-o', str(executable),
                        str(Path(__file__).with_name('rootfs-copy.c'))], check=True)
        rootfs_copy = executable.read_bytes()
        check_static_elf(rootfs_copy)
    data = archive(busybox, init, dax_check, rootfs_copy)
    with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as f:
        temporary = Path(f.name)
        try:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            os.replace(temporary, args.output)
        finally:
            temporary.unlink(missing_ok=True)
    print(json.dumps({
        'layout': 'pmem-overlay-raw-v1',
        'initramfs_sha256': hashlib.sha256(data).hexdigest(),
        'busybox_sha256': hashlib.sha256(busybox).hexdigest(),
        'init_sha256': hashlib.sha256(init).hexdigest(),
        'dax_check_sha256': hashlib.sha256(dax_check).hexdigest(),
        'rootfs_copy_sha256': hashlib.sha256(rootfs_copy).hexdigest(),
        'bytes': len(data),
    }, indent=2))


if __name__ == '__main__':
    main()
