#!/bin/bash
# Build the pmem-overlay profile from an existing, clean, pinned source tree.
# No package installation, checkout, or modification of the source tree.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <linux-6.1.177-source> <new-output-directory> [jobs]" >&2
  exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
kernel_src=$(realpath -- "$1")
kernel_out=$(realpath -m -- "$2")
jobs=${3:-8}
kernel_cc=${KERNEL_CC:-gcc-13}
kernel_hostcc=${KERNEL_HOSTCC:-$kernel_cc}
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo 'jobs must be positive' >&2; exit 2; }
[[ $(uname -m) == x86_64 ]] || { echo 'pmem-overlay currently requires x86_64' >&2; exit 2; }
[[ ! -e "$kernel_out" ]] || { echo "Output already exists: $kernel_out" >&2; exit 2; }
command -v "$kernel_cc" >/dev/null
command -v "$kernel_hostcc" >/dev/null
git -C "$kernel_src" diff --quiet
git -C "$kernel_src" diff --cached --quiet
source_commit=$(git -C "$kernel_src" rev-parse HEAD)
source_version=$(make --no-print-directory -s -C "$kernel_src" kernelversion)
[[ "$source_version" == 6.1.177 ]] || { echo "Expected 6.1.177, got $source_version" >&2; exit 2; }

mkdir -p -- "$kernel_out/build" "$kernel_out/source"
# Apply the host-tool compatibility patch to a private source export, never the
# caller's checkout. Record both the original commit and patch in the artifact.
git -C "$kernel_src" archive "$source_commit" | tar -xf - -C "$kernel_out/source"
host_patch="$script_dir/patches/pmem-overlay/0001-libbpf-preserve-const-next-path.patch"
patch --directory="$kernel_out/source" --strip=1 --fuzz=0 --forward < "$host_patch"
kernel_src="$kernel_out/source"
base="$script_dir/configs/x86_64/6.1.177.config"
fragment="$script_dir/configs/profiles/pmem-overlay.config"
(
  cd -- "$kernel_out/build"
  KCONFIG_CONFIG="$kernel_out/build/.config" "$kernel_src/scripts/kconfig/merge_config.sh" \
    -m -O "$kernel_out/build" "$base" "$fragment"
)
# Pin GCC 13 by default: the 6.1 host tools fail on newer toolchain/header
# combinations even when the C dialect alone is overridden.
# Keep compiler variables executable-only: some 6.1 recursive tools makefiles
# forward them without quotes. Kbuild sets the target kernel's C dialect itself.
make_args=("-C" "$kernel_src" "O=$kernel_out/build" "ARCH=x86_64" "CC=$kernel_cc" "HOSTCC=$kernel_hostcc")
make "${make_args[@]}" olddefconfig
for symbol in VIRTIO_PMEM BLK_DEV_PMEM LIBNVDIMM ZONE_DEVICE FS_DAX EXT4_FS OVERLAY_FS BLK_DEV_INITRD DEVTMPFS; do
  if ! grep -qx "CONFIG_${symbol}=y" "$kernel_out/build/.config"; then
    echo "Required built-in CONFIG_${symbol} missing after olddefconfig" >&2
    exit 1
  fi
done
make "${make_args[@]}" -j "$jobs" vmlinux
objcopy --strip-debug "$kernel_out/build/vmlinux" "$kernel_out/vmlinux.bin"
cp -- "$kernel_out/build/.config" "$kernel_out/kernel.config"
python3 - "$kernel_out" "$source_commit" "$base" "$fragment" "$kernel_cc" "$kernel_hostcc" "$host_patch" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

out, commit, base, fragment, cc, hostcc, host_patch = sys.argv[1:]
root = pathlib.Path(out)
def sha(path):
    return hashlib.file_digest(open(path, 'rb'), 'sha256').hexdigest()
result = {
    'version': 'vmlinux-6.1.177-pmem-overlay-v1',
    'architecture': 'amd64',
    'source_commit': commit,
    'host_tool_patch_sha256': sha(host_patch),
    'compiler': subprocess.check_output([cc, '--version'], text=True).splitlines()[0],
    'host_compiler': subprocess.check_output([hostcc, '--version'], text=True).splitlines()[0],
    'kernel_c_standard': 'gnu11',
    'base_config_sha256': sha(base),
    'profile_sha256': sha(fragment),
    'resolved_config_sha256': sha(root / 'kernel.config'),
    'kernel_sha256': sha(root / 'vmlinux.bin'),
}
(root / 'artifact.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
PY
