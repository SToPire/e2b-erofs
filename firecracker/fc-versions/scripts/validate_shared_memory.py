#!/usr/bin/env python3
"""Prove physical sharing and guest-write COW in two real File-restored FC VMs.

Run explicitly with sudo (CAP_SYS_ADMIN for visible PFNs, ptrace access, KVM,
loop and EROFS mounts). Requires x86_64, 4 KiB host pages, gcc with static libc,
cpio, and approximately 16 GiB free output space. --output must not exist.
Retains artifacts, API/guest/tool logs, raw smaps, PFNs and report.json even on
failure. No KSM configuration changes, global cache drops, or host mmap stand-ins.
An owned anonymous mmap calibrates host KSM flag reporting only; it is not the
sharing workload. A detected reporting anomaly still requires exclusive COW PFNs.
This tests RAM sharing only, not the orchestrator shared-mount lifecycle.
The controlled 64 MiB region is warmed before restore. Cold KVM async faults
may request FOLL_WRITE and privatize pages even when the guest only reads them;
this strict warm-scenario proof does not establish cold-cache sharing behavior.
"""

import argparse
from collections import Counter
import ctypes
import hashlib
import json
import mmap
import os
from pathlib import Path
import platform
import re
import signal
import struct
import subprocess
import sys
import traceback

sys.dont_write_bytecode = True
from validate_native_memory import VM, PAGE, RAM, digest, extents, page_at

# x86 4 GiB FC layout: [0, 3 GiB), [4 GiB, 5 GiB), serialized contiguously.
# The fixture sits entirely in the first region, so GPA == memfile offset.
START = 1 << 30
SIZE = 64 << 20
COUNT = SIZE // PAGE
STRIDE = 16
KPF_ANON = 1 << 12
KPF_KSM = 1 << 21
PM_FILE = 1 << 61
PM_EXCLUSIVE = 1 << 56
FORBIDDEN = sum(1 << bit for bit in (7, 10, 17, 19, 20, 23, 24, 26))
COMPOUND = sum(1 << bit for bit in (15, 16, 22))
CONTROL_PAGES = 256
ANON_KSM_ANOMALY = "anonymous-pages-misreported-as-KSM"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


class LoggedVM(VM):
    def __init__(self, binary, work, index):
        self.api_log = work / f"fc-{index}.api.jsonl"
        super().__init__(binary, work, index)

    def api(self, method, path, body):
        with self.api_log.open("a") as log:
            log.write(json.dumps({"method": method, "path": path, "body": body}) + "\n")
            result = super().api(method, path, body)
            log.write(json.dumps({"result": result}) + "\n")
        return result


def maps_for(text, identity):
    mappings = []
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            continue
        major, minor = (int(x, 16) for x in fields[3].split(":"))
        if (os.makedev(major, minor), int(fields[4])) != identity:
            continue
        start, end = (int(x, 16) for x in fields[0].split("-"))
        require(fields[1] == "rw-p", f"expected private writable FC mapping: {line}")
        mappings.append({"start": start, "end": end, "offset": int(fields[2], 16)})
    require(mappings, "FC has no mapping of the shared EROFS inode")
    return mappings


def address_for(mappings, offset):
    matches = [m["start"] + offset - m["offset"] for m in mappings
               if m["offset"] <= offset and offset + PAGE <= m["offset"] + m["end"] - m["start"]]
    require(len(matches) == 1, f"ambiguous/missing FC mapping at memfile offset {offset:#x}")
    return matches[0]


def pagemap(pid, addresses):
    with open(f"/proc/{pid}/pagemap", "rb", buffering=0) as file:
        return [struct.unpack("<Q", os.pread(file.fileno(), 8, va // PAGE * 8))[0]
                for va in addresses]


def decode(entry):
    require(entry & (1 << 63) and not entry & (1 << 62), "page not resident or swapped")
    pfn = entry & ((1 << 55) - 1)
    require(pfn != 0, "zero/hidden PFN: CAP_SYS_ADMIN in the initial user namespace is required")
    return pfn


def kpage_values(name, pfns):
    with open(f"/proc/{name}", "rb", buffering=0) as file:
        return [struct.unpack("<Q", os.pread(file.fileno(), 8, pfn * 8))[0]
                for pfn in pfns]


def ordinary_vmas(smaps, addresses):
    """Require complete smaps evidence for every sampled VMA, failing closed."""
    blocks = []
    for line in smaps.splitlines():
        if re.match(r"^[0-9a-f]+-[0-9a-f]+ ", line):
            fields = line.split()
            start, end = (int(x, 16) for x in fields[0].split("-"))
            blocks.append((start, end, fields[1], {}))
        elif blocks and ":" in line:
            key, value = line.split(":", 1)
            blocks[-1][3][key] = value.split()
    selected = set()
    for address in addresses:
        matches = [i for i, (start, end, _, _) in enumerate(blocks)
                   if start <= address and address + PAGE <= end]
        require(len(matches) == 1, "missing/ambiguous smaps VMA")
        selected.add(matches[0])
    for i in selected:
        _, _, permissions, fields = blocks[i]
        require(permissions == "rw-p", "expected private writable VMA")
        require("VmFlags" in fields and not {"mg", "ht"} & set(fields["VmFlags"]),
                "missing VmFlags or mergeable/hugetlb VMA")
        for key in ("KernelPageSize", "MMUPageSize"):
            require(fields.get(key) == ["4", "kB"], "non-ordinary/missing VMA page size")
        for key in ("AnonHugePages", "FilePmdMapped", "ShmemPmdMapped",
                    "Shared_Hugetlb", "Private_Hugetlb"):
            require(fields.get(key) == ["0", "kB"], "huge/missing VMA accounting")


def private_page(entry, flags, mapcount):
    decode(entry)
    require(flags & KPF_ANON and not entry & PM_FILE, "private page is not anonymous")
    require(entry & PM_EXCLUSIVE and mapcount == 1,
            "private page lacks exclusive single-mapping ownership")
    # Compound anonymous folios can have averaged mapcounts: exclude them.
    require(not flags & (FORBIDDEN | COMPOUND), "private page has unsupported flags")


def classify_control(control):
    require(control["madv_unmergeable"] is True, "control was not explicitly unmergeable")
    addresses = control["addresses"]
    require(len(addresses) == CONTROL_PAGES and len(set(addresses)) == CONTROL_PAGES,
            "incomplete control addresses")
    modes = []
    previous = None
    require(len(control["samples"]) == 2, "control needs two stable observations")
    for observation in control["samples"]:
        ordinary_vmas(observation["smaps"], addresses)
        entries, flags, counts = (observation[key] for key in
                                  ("pagemap", "kpageflags", "kpagecount"))
        require(len(entries) == len(flags) == len(counts) == CONTROL_PAGES,
                "incomplete control observations")
        pfns = [decode(e) for e in entries]
        require(len(set(pfns)) == CONTROL_PAGES, "aliased control PFNs")
        require(previous is None or previous == entries, "unstable control pagemap")
        previous = entries
        for entry, flag, count in zip(entries, flags, counts):
            private_page(entry, flag, count)
        bits = {bool(flag & KPF_KSM) for flag in flags}
        require(len(bits) == 1, "inconsistent control KSM flags")
        modes.append(ANON_KSM_ANOMALY if True in bits else "standard")
    require(modes[0] == modes[1], "unstable control KSM classification")
    return modes[0]


def calibrate_kpageflags(work):
    """Own random unmergeable pages; no sysctls or changes to VM workloads."""
    control = {"host": platform.uname()._asdict(), "madv_unmergeable": False,
               "samples": [], "status": "failed",
               "scope": "KSM flag reporting only; all ownership checks remain mandatory",
               "known_anomaly": (
                   "Linux v7.0 stable_page_flags tests mapping & FOLIO_MAPPING_KSM, "
                   "whose combined ANON|ANON_KSM mask also matches ordinary anonymous pages"),
               "sources": ["https://raw.githubusercontent.com/torvalds/linux/v7.0/fs/proc/page.c",
                           "https://raw.githubusercontent.com/torvalds/linux/v7.0/include/linux/page-flags.h"]}
    try:
        ksm_run = Path("/sys/kernel/mm/ksm/run")
        control["ksm_run"] = ksm_run.read_text().strip() if ksm_run.exists() else None
        with mmap.mmap(-1, CONTROL_PAGES * PAGE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE) as region:
            region.madvise(mmap.MADV_UNMERGEABLE)
            control["madv_unmergeable"] = True
            region.madvise(mmap.MADV_NOHUGEPAGE)
            data = os.urandom(CONTROL_PAGES * PAGE)
            (work / "kpageflags-control.bin").write_bytes(data)
            region[:] = data
            control["content_sha256"] = hashlib.sha256(data).hexdigest()
            start = ctypes.addressof(ctypes.c_char.from_buffer(region))
            addresses = [start + i * PAGE for i in range(CONTROL_PAGES)]
            control["addresses"] = addresses
            for _ in range(2):
                observation = {"smaps": Path("/proc/self/smaps").read_text(),
                               "pagemap": pagemap(os.getpid(), addresses)}
                control["samples"].append(observation)
                pfns = [decode(e) for e in observation["pagemap"]]
                observation.update(pfns=pfns, kpageflags=kpage_values("kpageflags", pfns),
                                   kpagecount=kpage_values("kpagecount", pfns))
            control["pagemap_after"] = pagemap(os.getpid(), addresses)
            require(control["pagemap_after"] == control["samples"][-1]["pagemap"],
                    "control pagemap changed during final flags observation")
            require(region[:] == data, "control contents changed")
            control["mode"] = classify_control(control)
            control["status"] = "validated"
        return control
    except BaseException:
        control["error"] = traceback.format_exc()
        raise
    finally:
        save(work / "kpageflags-control.json", control)


def classify_pages(entries, flags, counts, cow_indices, mode):
    require(mode in ("standard", ANON_KSM_ANOMALY), "unvalidated host flags mode")
    require(len(entries) == len(flags) == len(counts), "incomplete page evidence")
    require(all(0 <= i < len(entries) for i in cow_indices), "invalid COW indices")
    occurrences = Counter(decode(e) for e in entries)
    for i, (entry, flag, count) in enumerate(zip(entries, flags, counts)):
        require(not flag & FORBIDDEN, f"unsupported page flags at {i}")
        if i in cow_indices:
            private_page(entry, flag, count)
            require(occurrences[decode(entry)] == 1, f"aliased private PFN at {i}")
            require(bool(flag & KPF_KSM) == (mode == ANON_KSM_ANOMALY),
                    f"private KSM flag inconsistent with host control at {i}")
        else:
            require(entry & PM_FILE and not flag & (KPF_ANON | KPF_KSM),
                    f"expected nonanonymous file page without KSM at {i}")


def sample(vm, memory, work, label, control, cow_indices=frozenset()):
    """Called only with both guests paused; sample before reading /proc/PID/mem."""
    pid = vm.process.pid
    require(vm.process.poll() is None, "FC exited before sampling")
    prefix = work / f"{label}-{pid}"
    text = Path(f"/proc/{pid}/maps").read_text()
    prefix.with_suffix(".maps").write_text(text)
    smaps = Path(f"/proc/{pid}/smaps").read_text()
    prefix.with_suffix(".smaps").write_text(smaps)
    prefix.with_suffix(".smaps_rollup").write_text(Path(f"/proc/{pid}/smaps_rollup").read_text())
    stat = memory.stat()
    mappings = maps_for(text, (stat.st_dev, stat.st_ino))
    starts = {m["start"] for m in mappings}
    totals = {}
    active = False
    for line in smaps.splitlines():
        if re.match(r"^[0-9a-f]+-[0-9a-f]+ ", line):
            active = int(line.split("-", 1)[0], 16) in starts
        elif active:
            key, _, value = line.partition(":")
            if key == "VmFlags":
                require("mg" not in value.split(), "KSM-mergeable mapping cannot prove this path")
                require("ht" not in value.split(), "hugetlb mapping is not allowed")
            elif key in ("KernelPageSize", "MMUPageSize"):
                require(value.split() == ["4", "kB"], "non-ordinary mapping page size")
            elif key in ("AnonHugePages", "FilePmdMapped", "ShmemPmdMapped",
                         "Shared_Hugetlb", "Private_Hugetlb"):
                require(int(value.split()[0]) == 0, "huge mapped pages are not allowed")
            if key in ("Rss", "Pss", "Shared_Clean", "Shared_Dirty", "Private_Clean", "Private_Dirty"):
                totals[key + "_kB"] = totals.get(key + "_kB", 0) + int(value.split()[0])
    addresses = [address_for(mappings, START + i * PAGE) for i in range(COUNT)]
    ordinary_vmas(smaps, addresses)
    entries = pagemap(pid, addresses)
    # Save raw entries before validating: masked PFNs must be a reported failure.
    result = {"pid": pid, "device": stat.st_dev, "inode": stat.st_ino,
              "mappings": mappings, "smaps_totals": totals, "pagemap": entries}
    save(prefix.with_suffix(".json"), result)
    pfns = [decode(e) for e in entries]
    page_flags = kpage_values("kpageflags", pfns)
    counts = kpage_values("kpagecount", pfns)
    result.update(pfns=pfns, kpageflags=page_flags, kpagecount=counts,
                  cow_indices=sorted(cow_indices), kpageflags_mode=classify_control(control),
                  kpf_thp_pages=sum(bool(f & (1 << 22)) for f in page_flags))
    save(prefix.with_suffix(".json"), result)
    # KPF_THP also marks large file folios mapped with ordinary 4 KiB PTEs.
    # Record flagged base pages (not distinct folios); smaps above rejects huge
    # mappings. Only independently owned expected COW pages may use the calibrated
    # anonymous KSM-reporting anomaly; file pages always reject ANON and KSM.
    classify_pages(entries, page_flags, counts, cow_indices, result["kpageflags_mode"])
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as file:
        pages = [os.pread(file.fileno(), PAGE, va) for va in addresses]
    require(all(len(p) == PAGE and any(p) for p in pages), "short read or zero-content test page")
    require(pagemap(pid, addresses) == entries, "pagemap changed during paused sampling")
    result["page_sha256"] = [hashlib.sha256(p).hexdigest() for p in pages]
    save(prefix.with_suffix(".json"), result)
    return result, b"".join(pages)


def stable(vm, result):
    addresses = [address_for(result["mappings"], START + i * PAGE) for i in range(COUNT)]
    require(pagemap(vm.process.pid, addresses) == result["pagemap"],
            "pagemap changed across the two-VM paused sampling window")
    ordinary_vmas(Path(f"/proc/{vm.process.pid}/smaps").read_text(), addresses)
    classify_pages(result["pagemap"], kpage_values("kpageflags", result["pfns"]),
                   kpage_values("kpagecount", result["pfns"]), set(result["cow_indices"]),
                   result["kpageflags_mode"])


def guest_command(vm, sequence, command, expected):
    marker = f"SHARED-DONE-{sequence}"
    vm.command(marker + " ", command)
    match = re.search(rf"{marker} ([0-9a-f]{{16}})", vm.log.read_text(errors="replace"))
    require(match is not None, "missing guest checksum")
    checksum = sum(word[0] for word in struct.iter_unpack("<Q", expected)) & ((1 << 64) - 1)
    require(int(match[1], 16) == checksum, "guest checksum differs from expected baseline/COW data")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("firecracker", "kernel", "mkfs-erofs", "fsck-erofs", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    report = {"status": "failed", "host": platform.uname()._asdict(),
              "ram_bytes": RAM, "test_gpa": START, "memfile_offset": START,
              "test_bytes": SIZE, "write_stride_pages": STRIDE, "inputs": {}, "cleanup": []}
    vms, loop = [], None
    mount = work / "memory.mount"
    tool_log = (work / "tools.log").open("w")

    def run(argv, **kwargs):
        tool_log.write(json.dumps([str(x) for x in argv]) + "\n")
        tool_log.flush()
        return subprocess.run(argv, check=True, stderr=tool_log,
                              stdout=kwargs.pop("stdout", tool_log), **kwargs)

    def new_vm(index):
        # Own even a partially initialized object if startup is interrupted.
        vm = LoggedVM.__new__(LoggedVM)
        vms.append(vm)
        vm.__init__(str(args.firecracker.resolve()), work, index)
        return vm

    def interrupt(signum, _frame):
        raise RuntimeError(f"interrupted by signal {signum}")

    previous = {s: signal.signal(s, interrupt) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        for name in ("firecracker", "kernel", "mkfs_erofs", "fsck_erofs"):
            path = getattr(args, name).resolve()
            report["inputs"][name] = {"path": str(path), "sha256": digest(path)}
        report["inputs"]["guest_source"] = digest(Path(__file__).with_name("shared_memory_guest.c"))
        report["inputs"]["validator"] = digest(Path(__file__))
        report["inputs"]["native_helpers"] = digest(Path(__file__).with_name("validate_native_memory.py"))
        require(os.geteuid() == 0, "run explicitly with sudo for pagemap/ptrace/mount permissions")
        require(platform.machine() == "x86_64" and os.sysconf("SC_PAGE_SIZE") == PAGE,
                "requires x86_64 and 4096-byte host pages")
        report["host_status"] = Path("/proc/self/status").read_text()
        # Fail before VM creation if pagemap access is masked even for our own resident page.
        probe = ctypes.create_string_buffer(PAGE * 2)
        probe[0] = b"x"
        decode(pagemap(os.getpid(), [ctypes.addressof(probe)])[0])
        with open("/dev/kvm", "r+b"), open("/proc/kpageflags", "rb"):
            pass
        control = calibrate_kpageflags(work)
        report["kpageflags_control"] = {"artifact": "kpageflags-control.json",
                                      "mode": control["mode"], "scope": control["scope"]}
        if control["mode"] == ANON_KSM_ANOMALY:
            report["kpageflags_anomaly"] = control["known_anomaly"]
            print(f"Detected {control['mode']}: {control['scope']}", flush=True)
        initroot = work / "initroot"
        (initroot / "dev").mkdir(parents=True)
        run(["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", initroot / "init",
             Path(__file__).with_name("shared_memory_guest.c")])
        initrd = work / "initrd.cpio"
        with initrd.open("wb") as output:
            run(["cpio", "-o", "-H", "newc"], cwd=initroot, input=b".\ndev\ninit\n", stdout=output)
        report["inputs"]["guest_binary"] = digest(initroot / "init")
        report["inputs"]["initrd"] = digest(initrd)
        base_vm = new_vm("base")
        base_vm.api("PUT", "/machine-config", {"vcpu_count": 1, "mem_size_mib": 4096,
                    "track_dirty_pages": True, "huge_pages": "None"})
        base_vm.api("PUT", "/boot-source", {
            "kernel_image_path": str(args.kernel.resolve()), "initrd_path": str(initrd),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off nokaslr "
                         "memmap=64M$0x40000000 iomem=relaxed rdinit=/init"})
        base_vm.api("PUT", "/actions", {"action_type": "InstanceStart"})
        base_vm.wait("SHARED-READY")
        base_vm.api("PATCH", "/vm", {"state": "Paused"})
        state, base = base_vm.snapshot(work, "base", "Full")
        base_vm.close()
        report["baseline_sha256"] = digest(base)
        tree = work / "tree" / "memory"
        tree.mkdir(parents=True)
        os.link(base, tree / "memfile")
        image = work / "memory.erofs"
        run([args.mkfs_erofs.resolve(), "-b4096", "-Eforce-chunk-indexes", "--chunksize=4096",
             image, tree.parent])
        run([args.fsck_erofs.resolve(), image])
        report["image_sha256"] = digest(image)
        mount.mkdir()
        # Save losetup output in a file so a signal cannot lose an allocated loop ID.
        loop_file = work / "loop.txt"
        with loop_file.open("w") as output:
            run(["losetup", "--find", "--show", "--read-only", image], stdout=output)
        loop = loop_file.read_text().strip()
        run(["mount", "-t", "erofs", "-o", "ro,nosuid,nodev,noexec", loop, mount])
        memory = mount / "memory" / "memfile"
        require(digest(memory) == report["baseline_sha256"], "EROFS baseline differs")
        require(os.statvfs(memory).f_flag & os.ST_RDONLY, "EROFS mount is not read-only")
        report["mountinfo"] = Path("/proc/self/mountinfo").read_text()
        with memory.open("rb") as file:
            baseline = os.pread(file.fileno(), SIZE, START)
        require(len(baseline) == SIZE, "short baseline")
        # Full-file verification faults in even the EROFS memfile's logical zeros.
        # Release only this fixture's hash-primed cache, with the producer stopped
        # and neither restored VM created yet. DONTNEED is advisory; residency
        # and PFN assertions below remain mandatory after actual guest reads.
        report["cache_hygiene"] = {"advice": "POSIX_FADV_DONTNEED", "files": []}
        (work / "meminfo-before-fadvise.txt").write_text(Path("/proc/meminfo").read_text())
        try:
            for path in (base, memory):
                with path.open("rb") as file:
                    os.posix_fadvise(file.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                report["cache_hygiene"]["files"].append(str(path))
        finally:
            (work / "meminfo-after-fadvise.txt").write_text(Path("/proc/meminfo").read_text())
        report["test_cache_mode"] = "warm-controlled-region"
        report["test_cache_note"] = (
            "Only the controlled 64 MiB region is explicitly warmed after fixture cache cleanup. "
            "Cold KVM async faults may request FOLL_WRITE and privatize guest-read-only pages; "
            "this result establishes the intentional warm scenario only.")
        with memory.open("rb") as file:
            require(os.pread(file.fileno(), SIZE, START) == baseline,
                    "controlled-region warm read differs from baseline")
        expected_a = bytearray(baseline)
        for i in range(0, COUNT, STRIDE):
            expected_a[i * PAGE] ^= 0xff
        expected_a = bytes(expected_a)
        a, b = new_vm("A"), new_vm("B")
        for vm in (a, b):
            vm.restore(state, memory)
            machine = vm.api("GET", "/machine-config", None)
            require(machine["track_dirty_pages"] and machine["huge_pages"] == "None",
                    "restore must enable native dirty tracking and ordinary pages")
            guest_command(vm, 1, b"r", baseline)
            vm.api("PATCH", "/vm", {"state": "Paused"})
        before_a, data_a = sample(a, memory, work, "before-A", control)
        before_b, data_b = sample(b, memory, work, "before-B", control)
        stable(a, before_a)
        stable(b, before_b)
        require(data_a == data_b == baseline, "initial guest memory differs from baseline")
        require(before_a["pfns"] == before_b["pfns"], "resident clean PFNs are not shared")
        require(all(e & (1 << 61) for e in before_a["pagemap"] + before_b["pagemap"]),
                "initial shared pages are not file-backed")
        report["shared_pages_before"] = COUNT
        a.api("PATCH", "/vm", {"state": "Resumed"})
        guest_command(a, 2, b"w", expected_a)
        a.api("PATCH", "/vm", {"state": "Paused"})
        b.api("PATCH", "/vm", {"state": "Resumed"})
        guest_command(b, 2, b"r", baseline)
        b.api("PATCH", "/vm", {"state": "Paused"})
        after_a, data_a = sample(a, memory, work, "after-A", control,
                                 frozenset(range(0, COUNT, STRIDE)))
        after_b, data_b = sample(b, memory, work, "after-B", control)
        stable(a, after_a)
        stable(b, after_b)
        require(data_a == expected_a and data_b == baseline, "COW content isolation failed")
        original_pfns = set(before_a["pfns"] + before_b["pfns"] + after_b["pfns"])
        for i in range(COUNT):
            pa, pb = after_a["pfns"][i], after_b["pfns"][i]
            require(pb == before_b["pfns"][i], f"B PFN changed at page {i}; unstable proof window")
            require(bool(after_b["pagemap"][i] & (1 << 61)), f"B page {i} is no longer file-backed")
            written = i % STRIDE == 0
            if written:
                require(pa not in original_pfns, f"COW page {i} aliases an original/shared PFN")
            require((pa != pb) == written, f"unexpected COW PFN at page {i}")
            require(bool(after_a["pagemap"][i] & (1 << 61)) != written,
                    f"unexpected A file/anonymous page at {i}")
        report["cow_pages"] = COUNT // STRIDE
        report["smaps"] = {name: sample_["smaps_totals"] for name, sample_ in
                           (("before_A", before_a), ("before_B", before_b),
                            ("after_A", after_a), ("after_B", after_b))}
        # Native Diff must contain precisely the guest-written reserved pages.
        for name, vm, expected in (("A", a, expected_a), ("B", b, baseline)):
            _, diff = vm.snapshot(work, f"{name}-diff", "Diff")
            regions = list(extents(diff))
            save(work / f"{name}-diff-extents.json", regions)
            for i in range(COUNT):
                offset = START + i * PAGE
                dirty = any(start <= offset < end for start, end in regions)
                require(dirty == (name == "A" and i % STRIDE == 0),
                        f"native dirty tracking mismatch: {name} page {i}")
                if dirty:
                    require(page_at(diff, offset) == expected[i * PAGE:(i + 1) * PAGE],
                            f"native Diff content mismatch: {name} page {i}")
        require(digest(memory) == digest(base) == report["baseline_sha256"], "baseline changed")
        # Hash the actual running executables too, not just the input filenames.
        for name, vm in (("A", a), ("B", b)):
            actual = digest(Path(f"/proc/{vm.process.pid}/exe"))
            report[f"{name}_executable_sha256"] = actual
            require(actual == report["inputs"]["firecracker"]["sha256"], "FC binary identity changed")
        report["status"] = "passed"
    except BaseException:
        report["error"] = traceback.format_exc()
        (work / "failure.log").write_text(report["error"])
    finally:
        # Do not allow a second interrupt to skip owned-resource cleanup.
        for s in previous:
            signal.signal(s, signal.SIG_IGN)
        for vm in reversed(vms):
            try:
                if hasattr(vm, "process"):
                    vm.close()
                elif hasattr(vm, "output"):
                    vm.output.close()
            except BaseException as error:
                report["cleanup"].append(f"FC cleanup: {error!r}")
        alive = any(hasattr(v, "process") and v.process.poll() is None for v in vms)
        try:
            if alive:
                raise RuntimeError("FC still alive; retaining mount and loop")
            if os.path.ismount(mount):
                run(["umount", mount])
            loop_file = work / "loop.txt"
            loop = loop or (loop_file.read_text().strip() if loop_file.exists() else "")
            if loop:
                run(["losetup", "--detach", loop])
                loop = None
        except BaseException as error:
            report["cleanup"].append(f"mount/loop cleanup: {error!r}")
        report["remaining_resources"] = {"live_pids": [v.process.pid for v in vms
            if hasattr(v, "process") and v.process.poll() is None],
            "mounted": os.path.ismount(mount), "loop": loop}
        if report["cleanup"]:
            report["status"] = "failed"
        tool_log.close()
        save(work / "report.json", report)
        for s, handler in previous.items():
            signal.signal(s, handler)
    print(f"{report['status']}: {work / 'report.json'}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
