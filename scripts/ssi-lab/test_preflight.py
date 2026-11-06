"""只读准入探针在失败时必须回收已创建的 KVM 对象，不能伪造完整结果。"""
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'ssi_probe', Path(__file__).resolve().parents[2] / 'src/ssi_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def read_text(path):
    if str(path) == '/etc/machine-id':
        return '1' * 32
    return 'MemTotal: 4096 kB'


def ioctl(fd, operation, arg):
    if operation == 0xae00:
        return 12
    if operation == 0xae03:
        return {60: 0, 61: 1, 39: 14}[arg]
    if operation == 0xc008ae05:
        struct.pack_into('<I', arg, 0, 0)
        return 0
    if operation == 0xae01:
        return 11
    if operation == 0xae41:
        if arg == 1:
            raise OSError(12, 'second vcpu allocation failed')
        return 12
    if operation == 0xaea3:
        return 2400000
    if operation in (0x4018aee3, 0x8030ae7c):
        return 0
    raise AssertionError(f'unexpected ioctl {operation:#x}')


class PreflightTests(unittest.TestCase):
    def test_partial_allocation_closes_children_before_parent(self):
        with patch.object(probe.platform, 'system', return_value='Linux'), \
                patch.object(probe.platform, 'machine', return_value='x86_64'), \
                patch.object(probe.Path, 'read_text', read_text), \
                patch.object(probe.os, 'open', return_value=10), \
                patch.object(probe.os, 'close') as close, \
                patch.object(probe.fcntl, 'ioctl', side_effect=ioctl):
            report = probe.collect()
        self.assertEqual([call.args[0] for call in close.call_args_list], [12, 11, 10])
        self.assertEqual(report['closed_fds'], 3)
        self.assertEqual(len(report['vcpus']), 1)
        self.assertIn('second vcpu allocation failed', report['errors'][0])

    def test_close_error_is_reported_and_other_descriptors_still_close(self):
        with patch.object(probe.platform, 'system', return_value='Linux'), \
                patch.object(probe.platform, 'machine', return_value='x86_64'), \
                patch.object(probe.Path, 'read_text', read_text), \
                patch.object(probe.os, 'open', return_value=10), \
                patch.object(probe.os, 'close', side_effect=[OSError(5, 'close error'), None, None]) as close, \
                patch.object(probe.fcntl, 'ioctl', side_effect=ioctl):
            report = probe.collect()
        self.assertEqual(close.call_count, 3)
        self.assertEqual(report['closed_fds'], 2)
        self.assertEqual(len(report['errors']), 2)

    def test_non_x86_host_does_not_open_kvm(self):
        with patch.object(probe.platform, 'system', return_value='Darwin'), \
                patch.object(probe.os, 'open') as opened:
            report = probe.collect()
        opened.assert_not_called()
        self.assertTrue(report['errors'])
        self.assertEqual(report['closed_fds'], 0)


if __name__ == '__main__':
    unittest.main()
