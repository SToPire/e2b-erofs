#!/usr/bin/env python3
"""Behavioral tests for the static Guest merged-root exporter."""
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest


class RootfsCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.build.name) / 'rootfs-copy'
        subprocess.run(['gcc', '-static', '-Os', '-Wall', '-Wextra', '-Werror',
                        '-o', str(cls.binary), str(Path(__file__).with_name('rootfs-copy.c'))], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def test_bytes_links_sparse_xattrs_acl_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            src, dst = Path(directory) / 'src', Path(directory) / 'dst'
            src.mkdir(); dst.mkdir()
            item = src / 'file'
            item.write_bytes(b'preserved contents')
            os.link(item, src / 'hard')
            os.symlink('/outside/unresolved', src / 'link')
            os.link(src / 'link', src / 'link-hard', follow_symlinks=False)
            os.mkfifo(src / 'fifo', 0o640)
            os.setxattr(item, 'user.test', b'attribute')
            acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, perms, ident) for tag, perms, ident in [
                (1, 7, 0xffffffff), (2, 4, os.getuid() + 1), (4, 5, 0xffffffff), (16, 5, 0xffffffff), (32, 0, 0xffffffff)])
            os.setxattr(item, 'system.posix_acl_access', acl)
            stamp = 1_500_000_000_123_456_789
            os.utime(item, ns=(stamp, stamp))
            sparse = src / 'sparse'
            with sparse.open('wb') as f:
                f.write(b'head'); f.seek(64 << 20); f.write(b'tail')
            for name in ('dev', 'proc', 'sys', 'run', '.e2b-rootfs'):
                (src / name).mkdir(); (src / name / 'temporary').write_text('exclude')
            (src / '.e2b').write_text('BUILD_ID=parent\n')
            before = item.stat()
            subprocess.run([str(self.binary), str(src), str(dst)], check=True, capture_output=True)
            self.assertEqual((dst / 'file').read_bytes(), b'preserved contents')
            self.assertEqual((dst / 'file').stat().st_ino, (dst / 'hard').stat().st_ino)
            self.assertEqual((dst / 'link').lstat().st_ino, (dst / 'link-hard').lstat().st_ino)
            self.assertEqual(os.readlink(dst / 'link'), '/outside/unresolved')
            self.assertTrue(stat.S_ISFIFO((dst / 'fifo').stat().st_mode))
            self.assertEqual(os.getxattr(dst / 'file', 'user.test'), b'attribute')
            self.assertEqual(os.getxattr(dst / 'file', 'system.posix_acl_access'), acl)
            after = (dst / 'file').stat()
            self.assertEqual((after.st_uid, after.st_gid, after.st_mode, after.st_mtime_ns),
                             (before.st_uid, before.st_gid, before.st_mode, before.st_mtime_ns))
            self.assertEqual((dst / 'sparse').stat().st_size, (64 << 20) + 4)
            self.assertLess((dst / 'sparse').stat().st_blocks * 512, 1 << 20)
            with (dst / 'sparse').open('rb') as f:
                self.assertEqual(f.read(4), b'head'); f.seek(64 << 20); self.assertEqual(f.read(), b'tail')
            self.assertEqual((dst / '.e2b').read_text(), 'BUILD_ID=parent\n')
            self.assertFalse((dst / '.e2b-rootfs').exists())
            for name in ('dev', 'proc', 'sys', 'run'):
                self.assertEqual(list((dst / name).iterdir()), [])

    def test_root_metadata_initializes_only_the_root(self):
        with tempfile.TemporaryDirectory() as directory:
            src, dst = Path(directory) / 'src', Path(directory) / 'dst'
            src.mkdir(); dst.mkdir(); (src / 'file').write_text('not copied')
            os.chmod(src, 0o711); os.setxattr(src, 'user.root', b'root metadata')
            subprocess.run([str(self.binary), '--root-metadata', str(src), str(dst)], check=True, capture_output=True)
            self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o711)
            self.assertEqual(os.getxattr(dst, 'user.root'), b'root metadata')
            self.assertEqual(list(dst.iterdir()), [])

    def test_nonempty_destination_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            src, dst = Path(directory) / 'src', Path(directory) / 'dst'
            src.mkdir(); dst.mkdir(); (src / 'file').write_text('new'); (dst / 'file').write_text('keep')
            result = subprocess.run([str(self.binary), str(src), str(dst)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((dst / 'file').read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
