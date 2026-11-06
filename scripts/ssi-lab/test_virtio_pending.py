"""重放真实设备故障并拒绝伪成功、错误释放计数、路径覆盖和缺失原生证据。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load('check-virtio-pending')
probe = load('probe-virtio-pending')


class VirtioPendingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-virtio-pending-20261106.json').read_text())
        cls.row = next(r for r in cls.evidence['runs'] if r['run']['variant'] == 'candidate' and
                       r['run']['error'] == 5 and r['run']['action'] == 'quit')

    def reject(self, mutate, source=None):
        row = deepcopy(self.row if source is None else source)
        mutate(row['record'])
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
            checker.check(row)

    def test_full_twenty_case_matrix(self):
        observed = set()
        for row in self.evidence['runs']:
            self.assertEqual(checker.check(row), row['checked'])
            r = row['run']
            observed.add((r['variant'], r['node'], r['error'], r['action']))
        expected = {(variant, node, error, action)
                    for variant in ('baseline', 'candidate') for node in (0, 1)
                    for error, action in [(0, 'quit')] + [(5 if node == 0 else 28, a)
                        for a in ('quit', 'reset', 'resume', 'unrealize')]}
        self.assertEqual(observed, expected)
        self.assertEqual(len(self.evidence['runs']), 20)

    def test_rejected_captures_remain_rejected(self):
        self.assertEqual(len(self.evidence['rejected_runs']), 3)
        for row in self.evidence['rejected_runs']:
            with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
                checker.check(row)

    def test_exit_zero_and_final_flush_do_not_erase_prior_failure(self):
        self.reject(lambda r: r.update(qemu_exit=0))
        self.reject(lambda r: r.update(stderr=r['stderr'].replace("retains I/O status 'failed'", 'unknown')))
        self.reject(lambda r: r.update(stderr=r['stderr'].replace('vm_stop_flush_all ret 0', 'vm_stop_flush_all ret -5')))

    def test_native_guest_and_device_path_required(self):
        self.reject(lambda r: r.update(serial=r['serial'].replace('SSI_BLOCK_WRITE_BEGIN', '')))
        self.reject(lambda r: r.update(stderr=r['stderr'].replace('virtio_blk_handle_write', 'hmp_write')))
        self.reject(lambda r: r.update(stderr=r['stderr'].replace('ret -5', 'ret 0')))
        self.reject(lambda r: r.update(stderr=r['stderr'] + '\nvirtio_blk_req_complete fabricated\n'))
        self.reject(lambda r: r['command'].append('-S'))
        self.reject(lambda r: r['command'].extend(['-drive', 'file=business.img']))
        self.reject(lambda r: r['command'].extend(['-blockdev', 'driver=file,filename=business.img']))

    def test_snapshots_cannot_disagree_with_qmp(self):
        self.reject(lambda r: r['snapshots'][1]['queue'].update(inuse=0))
        self.reject(lambda r: r['snapshots'][1]['blocks'][0].update(**{'io-status': 'ok'}))
        self.reject(lambda r: r['snapshots'].pop(2))
        self.reject(lambda r: r['qmp'].pop(1))

    def test_consistent_fake_completion_is_rejected(self):
        def fabricate(record):
            for snapshot in record['snapshots'][1:]:
                snapshot['queue']['inuse'] = 0
            for entry in record['qmp']:
                if entry['request']['execute'] == 'x-query-virtio-queue-status':
                    for reply in entry['responses']:
                        if 'return' in reply:
                            reply['return']['inuse'] = 0
        self.reject(fabricate)

    def test_original_error_event_required(self):
        def remove(record):
            for entry in record['qmp']:
                entry['responses'] = [r for r in entry['responses'] if r.get('event') != 'BLOCK_IO_ERROR']
        self.reject(remove)

    def test_reset_and_unrealize_are_not_successful_retries(self):
        for action in ('reset', 'unrealize'):
            row = next(r for r in self.evidence['runs'] if r['run']['variant'] == 'candidate' and
                       r['run']['error'] == 5 and r['run']['action'] == action)
            self.reject(lambda r: r.update(payload_matches=True, payload_zero=False), row)
        row = next(r for r in self.evidence['runs'] if r['run']['variant'] == 'candidate' and
                   r['run']['error'] == 5 and r['run']['action'] == 'resume')
        self.reject(lambda r: r.update(serial=r['serial'].replace('SSI_BLOCK_WRITE_OK', '')), row)
        self.reject(lambda r: r.update(payload_sha256=hashlib.sha256(b'\0' * 4096).hexdigest()), row)

    def test_timeout_cleanup_and_dsm_claims_are_rejected(self):
        self.reject(lambda r: r.update(forced_cleanup=True))
        self.reject(lambda r: r.update(errors=['timeout']))
        self.reject(lambda r: r.update(dsm_observed=True))
        self.reject(lambda r: r.update(kernel='7.1.0-rc3-sshpool-gvm-pf24'))

    def test_refuses_existing_experiment_or_parameter_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            sentinel = parent / 'company-data'
            sentinel.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError):
                probe.prepare(SimpleNamespace(directory=parent, error=5))
            self.assertEqual(sentinel.read_bytes(), b'preserve')
            self.assertEqual(list(parent.iterdir()), [sentinel])
            for name in ('a,b', 'a:b', 'a\nb', 'a\rb'):
                target = parent / name
                with self.assertRaises(ValueError):
                    probe.prepare(SimpleNamespace(directory=target, error=5))
                self.assertFalse(target.exists())

    def test_current_sources_match_exported_build(self):
        e = self.evidence
        self.assertEqual(hashlib.sha256(Path(__file__).with_name('probe-virtio-pending.py').read_bytes()).hexdigest(),
                         e['capture_versions']['v2'])
        self.assertEqual(hashlib.sha256(Path(__file__).with_name('guest-block-init.sh').read_bytes()).hexdigest(),
                         e['initramfs']['files']['init']['sha256'])
        self.assertEqual(hashlib.sha256((ROOT / 'scripts/ssi-lab/experiments/qemu-shutdown-iostatus.patch').read_bytes()).hexdigest(),
                         e['patch_replay']['patch_sha256'])
        self.assertTrue(e['patch_replay']['zero_fuzz'])
        self.assertEqual(e['candidate_build']['source_sha256'], e['patch_replay']['after_sha256'])
        self.assertNotIn('warning:', e['build_log'])
        self.assertNotIn('error:', e['build_log'])
        for key in ('full_ssi_accepted', 'dsm_pins_observed', 'cross_physical_verified', 'ceph_deployed'):
            self.assertFalse(e[key])


if __name__ == '__main__':
    unittest.main()
