#!/usr/bin/env python3
"""Opt-in root/KVM test of the actual initramfs, DAX sharing and FC snapshots.

Creates only files, private mount namespaces and a file-backed EROFS mount.
Requires mkfs.ext4, gcc/static libc, the file-backend Host EROFS feature, and the
pinned Firecracker, new Guest kernel, initramfs and static BusyBox artifacts.
"""
import argparse
import ctypes
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import struct
import subprocess
import time

PAGE = 4096
RAM = 256 << 20
LOWER_SIZE = 64 << 20
UPPER_SIZE = 64 << 20


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


def sha(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def mount_erofs(source, target):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(os.fsencode(source), os.fsencode(target), b'erofs',
                  ctypes.c_ulong(1 | 2 | 4 | 8), b'') != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def copy_raw(source, target):
    subprocess.run(['cp', '--reflink=auto', '--sparse=always', source, target], check=True)


def sparse_extents(path):
    with path.open('rb') as source:
        size = os.fstat(source.fileno()).st_size
        position = 0
        while position < size:
            try:
                start = os.lseek(source.fileno(), position, os.SEEK_DATA)
            except OSError as error:
                if error.errno == errno.ENXIO:
                    break
                raise
            end = os.lseek(source.fileno(), start, os.SEEK_HOLE)
            if start % PAGE or end % PAGE or not start < end <= size:
                raise ValueError('invalid native memory delta extent')
            yield start, end
            position = end


class VM:
    def __init__(self, args, name, lower, upper):
        self.root = args.output / name
        self.root.mkdir()
        self.socket = self.root / 'api'
        if len(os.fsencode(self.socket)) >= 104:
            raise ValueError('output path is too long for an API Unix socket')
        self.log = self.root / 'console.log'
        self.position = 0
        self.lower = lower
        self.upper = upper
        aliases = args.output / 'devices'
        aliases.mkdir(exist_ok=True)
        self.lower_alias = aliases / 'lower.ext4'
        self.upper_alias = aliases / 'upper.ext4'
        commands = [f'mount -t tmpfs tmpfs {shlex.quote(str(aliases))}']
        for source, target, readonly in ((lower, self.lower_alias, True), (upper, self.upper_alias, False)):
            commands += [f'touch {shlex.quote(str(target))}',
                         f'mount --bind {shlex.quote(str(source))} {shlex.quote(str(target))}']
            if readonly:
                commands += [f'mount -o remount,bind,ro {shlex.quote(str(target))}']
        commands += [f'exec {shlex.quote(str(args.firecracker))} --api-sock {shlex.quote(str(self.socket))}']
        self.output = self.log.open('wb')
        self.process = subprocess.Popen(
            ['unshare', '--mount', '--propagation', 'private', '--', '/bin/sh', '-ec', '\n'.join(commands)],
            stdin=subprocess.PIPE, stdout=self.output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while not self.socket.exists():
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f'VMM startup failed: {self.log}')
                time.sleep(0.05)
        except BaseException:
            self.close()
            raise

    def api(self, method, path, data):
        connection = UnixHTTP(str(self.socket), timeout=60)
        try:
            connection.request(method, path, json.dumps(data), {'Content-Type': 'application/json'})
            response = connection.getresponse()
            content = response.read()
            if response.status != 204:
                raise RuntimeError(f'{path}: {response.status}: {content!r}')
        finally:
            connection.close()

    def boot(self, args):
        self.api('PUT', '/machine-config', {'vcpu_count': 1, 'mem_size_mib': RAM >> 20,
                                           'track_dirty_pages': True, 'huge_pages': 'None'})
        self.api('PUT', '/boot-source', {
            'kernel_image_path': str(args.kernel), 'initrd_path': str(args.initramfs),
            'boot_args': 'console=ttyS0 reboot=k panic=1 pci=off rdinit=/init '
                         f'e2b.rootfs_layout=pmem-overlay-raw-v1 e2b.lower_bytes={LOWER_SIZE} '
                         f'e2b.upper_bytes={UPPER_SIZE} e2b.init=/sbin/init'})
        self.api('PUT', '/pmem/lower', {'id': 'lower', 'path_on_host': str(self.lower_alias),
                                      'read_only': True, 'root_device': False})
        self.api('PUT', '/drives/upper', {'drive_id': 'upper', 'path_on_host': str(self.upper_alias),
                                        'is_read_only': False, 'is_root_device': False,
                                        'io_engine': 'Sync', 'cache_type': 'Writeback'})
        self.api('PUT', '/actions', {'action_type': 'InstanceStart'})
        return self.state()

    def state(self, command=None):
        if command:
            self.process.stdin.write(command.encode() + b'\n')
            self.process.stdin.flush()
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            text = self.log.read_text(errors='replace')
            recent = text[self.position:]
            if 'P0_FAIL:' in recent or 'E2B_ROOTFS_ERROR:' in recent or self.process.poll() is not None:
                raise RuntimeError(f'Guest failed: {self.log}\n{recent[-3000:]}')
            marker = recent.find('P0_STATE: ')
            if marker >= 0:
                end = recent.find('\n', marker)
                if end >= 0:
                    result = json.loads(recent[marker + len('P0_STATE: '):end].strip())
                    self.position += end + 1
                    return result
            time.sleep(0.05)
        raise TimeoutError(f'Guest response timed out: {self.log}')

    def snapshot(self, name, kind):
        memory, state = self.root / f'{name}.mem', self.root / f'{name}.state'
        self.api('PUT', '/snapshot/create', {'snapshot_type': kind,
                                           'snapshot_path': str(state), 'mem_file_path': str(memory)})
        if memory.stat().st_size != RAM:
            raise AssertionError('snapshot unexpectedly includes pmem or omits RAM')
        return state, memory

    def restore(self, state, memory):
        self.api('PUT', '/snapshot/load', {'snapshot_path': str(state), 'track_dirty_pages': True,
                                         'mem_backend': {'backend_type': 'File', 'backend_path': str(memory)}})
        self.api('PATCH', '/vm', {'state': 'Resumed'})
        return self.state('state')

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.process.stdin.close()
        self.output.close()


def host_pfns(vm, guest):
    pid = vm.process.pid
    identity = vm.lower.stat()
    mappings = []
    for line in Path(f'/proc/{pid}/maps').read_text().splitlines():
        fields = line.split(maxsplit=5)
        major, minor = (int(x, 16) for x in fields[3].split(':'))
        if (int(fields[4]) == identity.st_ino and
                (major, minor) == (os.major(identity.st_dev), os.minor(identity.st_dev))):
            start, end = (int(x, 16) for x in fields[0].split('-'))
            mappings.append((start, end, int(fields[2], 16)))
    if not mappings:
        raise AssertionError('pmem file mapping missing')
    result = {}
    with open(f'/proc/{pid}/pagemap', 'rb') as file:
        for gfn in guest['gfns']:
            offset = gfn * PAGE - guest['region_start']
            if not 0 <= offset < LOWER_SIZE:
                raise AssertionError('Guest binary mapping is ordinary RAM, not pmem')
            for start, end, file_offset in mappings:
                if file_offset <= offset < file_offset + end - start:
                    address = start + offset - file_offset
                    entry, = struct.unpack('<Q', os.pread(file.fileno(), 8, address // PAGE * 8))
                    if not entry >> 63 or not entry & ((1 << 55) - 1):
                        raise AssertionError('Host PFN not observable/resident')
                    result[offset] = entry & ((1 << 55) - 1)
                    break
            else:
                raise AssertionError('pmem offset outside VMM mappings')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('firecracker', 'kernel', 'initramfs', 'busybox', 'mkfs-erofs', 'output'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root for private mounts and PFN verification')
    if Path('/sys/module/nbd').exists():
        parser.error('P0 requires the Host NBD module to be absent; do not unload another workload\'s module')
    for key, value in vars(args).items():
        setattr(args, key, value.resolve())
    results = {'artifacts': {key: sha(getattr(args, key)) for key in ('firecracker', 'kernel', 'initramfs', 'busybox')},
               'generations': [], 'ram_bytes': RAM, 'lower_bytes': LOWER_SIZE, 'upper_bytes': UPPER_SIZE}
    args.output.mkdir(parents=True, exist_ok=False)
    tree = args.output / 'lower-tree'
    for directory in ('bin', 'sbin', 'usr/lib', 'dev', 'proc', 'sys', 'directory', 'opaque'):
        (tree / directory).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.busybox, tree / 'bin/busybox')
    (tree / 'bin/busybox').chmod(0o755)
    subprocess.run(['gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-o', tree / 'usr/lib/p0-init',
                    Path(__file__).with_name('probe.c')], check=True)
    (tree / 'sbin/init').symlink_to('/usr/lib/p0-init')
    (tree / 'sample').write_text('original\n')
    os.link(tree / 'sample', tree / 'sample-link')
    (tree / 'sample-symlink').symlink_to('/sample')
    (tree / 'append').write_text('base')
    (tree / 'mmap-private').write_bytes(b'P' + bytes(PAGE-1))
    (tree / 'mmap-shared').write_bytes(b'0' + bytes(PAGE-1))
    (tree / 'opaque/old').write_text('hidden after replacement\n')
    (tree / 'deleted').write_text('delete-me\n')
    (tree / 'directory/child').write_text('child\n')
    erofs_tree = args.output / 'erofs-tree'
    erofs_tree.mkdir()
    raw = erofs_tree / 'rootfs.ext4'
    raw.touch()
    with raw.open('r+b') as file:
        file.truncate(LOWER_SIZE)
    subprocess.run(['mkfs.ext4', '-q', '-F', '-b', str(PAGE), '-E', 'lazy_itable_init=0,lazy_journal_init=0',
                    '-d', tree, raw], check=True)
    image = args.output / 'lower.erofs'
    subprocess.run([args.mkfs_erofs, '-b4096', image, erofs_tree], check=True)
    lower = args.output / 'lower-mount'
    lower.mkdir()
    mount_erofs(image, lower)
    vms = []
    try:
        seed_tree = args.output / 'upper-tree'
        (seed_tree / 'upper').mkdir(parents=True)
        (seed_tree / 'work').mkdir()
        seed = args.output / 'upper-seed.raw'
        seed.touch()
        with seed.open('r+b') as file:
            file.truncate(UPPER_SIZE)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-b', str(PAGE), '-E', 'lazy_itable_init=0,lazy_journal_init=0',
                        '-d', seed_tree, seed], check=True)
        guests = []
        for index in range(2):
            upper = args.output / f'upper-{index}.raw'
            copy_raw(seed, upper)
            vm = VM(args, f'cold-{index}', lower / 'rootfs.ext4', upper)
            vms.append(vm)
            guests.append(vm.boot(args))
        a, b = (host_pfns(vm, guest) for vm, guest in zip(vms, guests))
        if a != b or not a:
            raise AssertionError('same lower offsets do not share Host PFNs')
        results['shared_program_pages'] = len(a)
        vm = vms[0]
        state = vm.state('mutate')
        if state['generation'] != 1 or vms[1].state('state')['generation'] != 0:
            raise AssertionError('upper isolation failed')
        vm.api('PATCH', '/vm', {'state': 'Paused'})
        snapshot, memory = vm.snapshot('full', 'Full')
        vm.close()
        for generation in range(1, 4):
            upper = args.output / f'restored-upper-{generation}.raw'
            copy_raw(vm.upper, upper)
            restored = VM(args, f'restore-{generation}', lower / 'rootfs.ext4', upper)
            vms.append(restored)
            observed = restored.restore(snapshot, memory)
            if observed['generation'] != generation:
                raise AssertionError('RAM/disk cutoff differs after restore')
            results['generations'].append(observed['generation'])
            state = restored.state('mutate')
            if state['generation'] != generation + 1:
                raise AssertionError('restored Guest cannot continue modifying upper')
            restored.api('PATCH', '/vm', {'state': 'Paused'})
            snapshot, delta = restored.snapshot('diff', 'Diff')
            _, full = restored.snapshot('full-reference', 'Full')
            merged = restored.root / 'merged.mem'
            copy_raw(memory, merged)
            with delta.open('rb') as source, merged.open('r+b') as target:
                for start, end in sparse_extents(delta):
                    for position in range(start, end, 1 << 20):
                        data = os.pread(source.fileno(), min(end-position, 1 << 20), position)
                        if os.pwrite(target.fileno(), data, position) != len(data):
                            raise IOError('short rebase write')
                os.fsync(target.fileno())
            if sha(merged) != sha(full):
                raise AssertionError('Diff + parent does not equal same-cutoff Full')
            restored.close()
            memory, vm = merged, restored
        results['lower_unchanged'] = sha(raw) == sha(lower / 'rootfs.ext4')
        if not results['lower_unchanged']:
            raise AssertionError('shared lower changed')
        if Path('/sys/module/nbd').exists():
            raise AssertionError('NBD module appeared during the test')
        results['nbd_module_present'] = False
        results['filesystem_semantics'] = ['overwrite', 'truncate', 'append', 'whiteout', 'opaque',
                                          'rename', 'hardlink', 'symlink', 'MAP_PRIVATE write isolation',
                                          'MAP_SHARED persistence', 'open descriptor across copy-up']
        results['passed'] = True
    except BaseException as error:
        results['passed'] = False
        results['error'] = str(error)
        raise
    finally:
        for vm in reversed(vms):
            vm.close()
        subprocess.run(['umount', lower], check=True)
        (args.output / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
