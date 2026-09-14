#!/usr/bin/env python3
"""Exercise a supplied Firecracker binary on a local 4 GiB x86 KVM guest.

Requires gcc (static libc), cpio, /dev/kvm and a Firecracker-compatible vmlinux
with initramfs, devtmpfs, /dev/mem, serial console and virtio-rng built in. Supply
the exact E2B binary to be deployed; passing on upstream is not fork validation.
The output directory must be new, live on the production staging filesystem,
and have approximately 32 GiB free. It retains artifacts and logs on failure.
"""

import argparse
from dataclasses import dataclass
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import time

PAGE = 4096
RAM = 4 << 30
BOUNDARY = 3 << 30


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


class VM:
    def __init__(self, binary, work, index):
        self.socket = work / f"fc-{index}.sock"
        self.log = work / f"fc-{index}.log"
        self.metrics = work / f"fc-{index}.metrics"
        self.metrics.touch()
        self.output = self.log.open("wb")
        self.process = subprocess.Popen(
            [binary, "--api-sock", self.socket],
            stdin=subprocess.PIPE, stdout=self.output, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 10
        while not self.socket.exists():
            if self.process.poll() is not None or time.monotonic() > deadline:
                self.close()
                raise RuntimeError(f"Firecracker failed to start: {self.log}")
            time.sleep(0.05)
        try:
            self.api("PUT", "/metrics", {"metrics_path": str(self.metrics)})
        except BaseException:
            self.close()
            raise

    def api(self, method, path, body):
        connection = UnixHTTP(str(self.socket), timeout=120)
        try:
            connection.request(method, path, json.dumps(body) if body is not None else None,
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            content = response.read()
            if method == "GET" and response.status == 200:
                return json.loads(content)
            if response.status != 204:
                raise RuntimeError(f"{method} {path}: {response.status} {content!r}")
        finally:
            connection.close()

    def wait(self, marker):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            output = self.log.read_text(errors="replace")
            if "NATIVE-FAIL" in output or self.process.poll() is not None:
                raise RuntimeError(f"guest failed, see {self.log}")
            if marker in output:
                return
            time.sleep(0.05)
        raise RuntimeError(f"timed out waiting for {marker}, see {self.log}")

    def command(self, marker, command=b"x"):
        self.process.stdin.write(command)
        self.process.stdin.flush()
        self.wait(marker)

    def snapshot(self, work, name, kind):
        state, memory = work / f"{name}.state", work / f"{name}.mem"
        # This matches the Go wrapper: reserve new, empty files, never reuse a
        # prior memfile (the native API can otherwise merge Diff in place).
        state.touch(exist_ok=False)
        memory.touch(exist_ok=False)
        self.api("PUT", "/snapshot/create", {
            "snapshot_type": kind, "snapshot_path": str(state),
            "mem_file_path": str(memory),
        })
        for path in (state, memory):
            with path.open("rb") as file:
                os.fsync(file.fileno())
        assert memory.stat().st_size == RAM
        return state, memory

    def restore(self, state, memory):
        self.api("PUT", "/snapshot/load", {
            "snapshot_path": str(state), "track_dirty_pages": True,
            "mem_backend": {"backend_type": "File", "backend_path": str(memory)},
        })
        machine = self.api("GET", "/machine-config", None)
        assert machine["huge_pages"] == "None" and machine["track_dirty_pages"]
        self.api("PATCH", "/vm", {"state": "Resumed"})

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.output.close()
        self.process.stdin.close()


@dataclass
class ErofsGeneration:
    image: Path
    dependencies: list[Path]
    memory: Path


class ErofsChain:
    """Own actual kernel mounts and every loop in their ordered device tables."""

    def __init__(self, work, mkfs, fsck):
        self.work, self.mkfs, self.fsck = work, mkfs, fsck
        self.resources = []

    def build(self, memory, name, parent=None):
        image = self.work / f"{name}.erofs"
        args = [self.mkfs, "-b4096", "-Eforce-chunk-indexes", "--chunksize=4096"]
        if parent is None:
            tree = self.work / "erofs-base-tree"
            (tree / "memory").mkdir(parents=True)
            os.link(memory, tree / "memory" / "memfile")
            args += [image, tree]
            dependencies = []
        else:
            args += [f"--file-delta=sparse:/memory/memfile:{memory}", image, parent.image]
            dependencies = [parent.image, *parent.dependencies]
        subprocess.run(args, check=True)
        subprocess.run([self.fsck, *(f"--device={p}" for p in dependencies), image], check=True)
        mount = self.work / f"{name}.mount"
        mount.mkdir()
        record = {"mount": mount, "mounted": False, "loops": []}
        self.resources.append(record)
        for file in [image, *dependencies]:
            loop = subprocess.check_output(
                ["sudo", "-n", "losetup", "--find", "--show", "--read-only", file], text=True,
            ).strip()
            record["loops"].append(loop)
        options = ",".join(["ro", "nosuid", "nodev", "noexec",
                            *(f"device={loop}" for loop in record["loops"][1:])])
        subprocess.run(["sudo", "-n", "mount", "-t", "erofs", "-o", options,
                        record["loops"][0], mount], check=True)
        record["mounted"] = True
        memfile = mount / "memory" / "memfile"
        assert memfile.stat().st_size == RAM
        return ErofsGeneration(image, dependencies, memfile)

    def close(self):
        for record in reversed(self.resources):
            if record["mounted"]:
                subprocess.run(["sudo", "-n", "umount", record["mount"]], check=True)
                record["mounted"] = False
            while record["loops"]:
                subprocess.run(["sudo", "-n", "losetup", "--detach", record["loops"][-1]], check=True)
                record["loops"].pop()


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def extents(path):
    with path.open("rb") as file:
        size, position = path.stat().st_size, 0
        while position < size:
            try:
                start = os.lseek(file.fileno(), position, os.SEEK_DATA)
            except OSError as error:
                if error.errno == errno.ENXIO:
                    return
                raise
            end = os.lseek(file.fileno(), start, os.SEEK_HOLE)
            assert start % PAGE == end % PAGE == 0 and start < end <= size
            yield start, end
            position = end


def page_at(path, offset):
    with path.open("rb") as file:
        return os.pread(file.fileno(), PAGE, offset)


def compare_rebase(base, diff, full, merged):
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", base, merged], check=True)
    regions = list(extents(diff))
    with diff.open("rb") as source, merged.open("r+b") as target:
        for start, end in regions:
            for position in range(start, end, 1 << 20):
                data = os.pread(source.fileno(), min(end - position, 1 << 20), position)
                assert os.pwrite(target.fileno(), data, position) == len(data)
        os.fsync(target.fileno())
    assert digest(merged) == digest(full), "Diff merged with parent must equal same-cutoff Full"
    return regions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firecracker", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mkfs-erofs", type=Path,
                        help="optionally build and File-restore a kernel-mounted EROFS memory chain")
    parser.add_argument("--fsck-erofs", type=Path)
    args = parser.parse_args()
    if bool(args.mkfs_erofs) != bool(args.fsck_erofs):
        parser.error("--mkfs-erofs and --fsck-erofs must be provided together")
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    binary, kernel = str(args.firecracker.resolve()), str(args.kernel.resolve())
    initroot = work / "initroot"
    (initroot / "dev").mkdir(parents=True)
    subprocess.run(["gcc", "-static", "-O2", "-Wall", "-Wextra", "-o", initroot / "init",
                    Path(__file__).with_name("native_memory_guest.c")], check=True)
    initrd = work / "initrd.cpio"
    with initrd.open("wb") as file:
        subprocess.run(["cpio", "-o", "-H", "newc"], cwd=initroot,
                       input=b".\ndev\ninit\n", stdout=file, check=True)
    chain = ErofsChain(work, args.mkfs_erofs.resolve(), args.fsck_erofs.resolve()) if args.mkfs_erofs else None
    vm = VM(binary, work, 0)
    try:
        vm.api("PUT", "/machine-config", {"vcpu_count": 1, "mem_size_mib": 4096,
                                           "track_dirty_pages": True, "huge_pages": "None"})
        vm.api("PUT", "/boot-source", {
            "kernel_image_path": kernel, "initrd_path": str(initrd),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off nokaslr "
                         "memmap=4K$0x40000000 memmap=4K$0xbffff000 "
                         "memmap=12K$0x100000000 iomem=relaxed rdinit=/init",
        })
        vm.api("PUT", "/entropy", {})
        vm.api("PUT", "/actions", {"action_type": "InstanceStart"})
        vm.wait("NATIVE-READY-0")
        vm.api("PATCH", "/vm", {"state": "Paused"})
        state0, base = vm.snapshot(work, "base", "Full")
        base_hash = digest(base)
        vm.close()
        print("ordinary-page Full baseline captured", flush=True)

        generation0 = chain.build(base, "memory0") if chain else None
        restore0 = generation0.memory if chain else base
        assert digest(restore0) == base_hash

        vm = VM(binary, work, 1)
        vm.restore(state0, restore0)
        vm.command("NATIVE-READY-1")
        vm.api("PATCH", "/vm", {"state": "Paused"})
        state1, diff1 = vm.snapshot(work, "diff1", "Diff")
        _, full1 = vm.snapshot(work, "full1", "Full")
        vm.api("PUT", "/actions", {"action_type": "FlushMetrics"})
        vm.close()
        metrics = [json.loads(line) for line in vm.metrics.read_text().splitlines()]
        assert sum(m.get("entropy", {}).get("entropy_bytes", 0) for m in metrics) > 0, "virtio-rng must write guest RAM"
        assert digest(base) == base_hash, "File MAP_PRIVATE restore must not modify the baseline"
        assert digest(restore0) == base_hash, "EROFS baseline must remain unchanged"
        assert page_at(base, BOUNDARY - PAGE) == bytes([0x42]) * PAGE
        assert page_at(diff1, BOUNDARY) == bytes([0xa6]) * PAGE
        assert page_at(diff1, BOUNDARY + PAGE) == bytes(PAGE)
        regions = list(extents(diff1))
        assert any(start <= BOUNDARY < end for start, end in regions), "second region mutation must be DATA"
        assert any(start <= BOUNDARY + PAGE < end for start, end in regions), "explicit zero mutation must be DATA"
        assert not any(start <= BOUNDARY - PAGE < end for start, end in regions), "first region's last page must be HOLE"
        assert not any(start <= (1 << 30) < end for start, end in regions), "unaccessed nonzero baseline must be HOLE"
        merged1 = work / "merged1.mem"
        compare_rebase(base, diff1, full1, merged1)
        generation1 = chain.build(diff1, "memory1", generation0) if chain else None
        restore1 = generation1.memory if chain else merged1
        parent1_hash = digest(merged1)
        assert digest(restore1) == parent1_hash
        print("first File generation: sparse zeros, region offsets, VMM writes and rebase verified", flush=True)

        vm = VM(binary, work, 2)
        vm.restore(state1, restore1)
        vm.command("NATIVE-READY-2")
        vm.api("PATCH", "/vm", {"state": "Paused"})
        state2, diff2 = vm.snapshot(work, "diff2", "Diff")
        _, full2 = vm.snapshot(work, "full2", "Full")
        vm.close()
        merged2 = work / "merged2.mem"
        regions2 = compare_rebase(merged1, diff2, full2, merged2)
        assert not any(start <= BOUNDARY < end for start, end in regions2), "second generation must inherit the first update"
        assert page_at(diff2, BOUNDARY + 2 * PAGE) == bytes([0xb7]) * PAGE
        generation2 = chain.build(diff2, "memory2", generation1) if chain else None
        restore2 = generation2.memory if chain else merged2
        assert digest(restore2) == digest(full2)

        # Fork from the first generation and change the same page to another
        # value. It must not alter the first branch or their common EROFS parent.
        vm = VM(binary, work, 3)
        vm.restore(state1, restore1)
        vm.command("NATIVE-BRANCH-READY-2", b"b")
        vm.api("PATCH", "/vm", {"state": "Paused"})
        branch_state, branch_diff = vm.snapshot(work, "branch-diff", "Diff")
        _, branch_full = vm.snapshot(work, "branch-full", "Full")
        vm.close()
        branch_merged = work / "branch-merged.mem"
        compare_rebase(merged1, branch_diff, branch_full, branch_merged)
        branch_generation = chain.build(branch_diff, "memory-branch", generation1) if chain else None
        branch_restore = branch_generation.memory if chain else branch_merged
        assert digest(branch_restore) == digest(branch_full)
        assert digest(restore1) == parent1_hash
        assert page_at(branch_restore, BOUNDARY + 2 * PAGE) == bytes([0xc8]) * PAGE
        assert page_at(restore2, BOUNDARY + 2 * PAGE) == bytes([0xb7]) * PAGE
        vm = VM(binary, work, 4)
        vm.restore(branch_state, branch_restore)
        vm.command("NATIVE-PASS")
        vm.close()
        vm = VM(binary, work, 5)
        vm.restore(state2, restore2)
        vm.command("NATIVE-PASS")
        vm.close()
        report = {"firecracker": binary, "binary_sha256": digest(Path(binary)),
                  "kernel": kernel, "ram_bytes": RAM, "status": "passed",
                  "kernel_erofs_chain": chain is not None, "branch_isolation": True,
                  "diff1_data_bytes": sum(end - start for start, end in regions),
                  "diff2_data_bytes": sum(end - start for start, end in regions2)}
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    finally:
        vm.close()
        if chain:
            chain.close()


if __name__ == "__main__":
    main()
