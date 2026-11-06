"""重放真实块层故障，拒绝把退出零、QMP 应答或缓存读回误称为成功持久化。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

root = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load('check-shutdown-flush')


class ShutdownFlushTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((root / 'docs/evidence/ssi-shutdown-flush-20261106.json').read_text())
        cls.single = next(r for r in cls.evidence['single_runs'] if r['run']['variant'] == 'candidate' and r['run']['error'] == 5)
        cls.pair = next(r for r in cls.evidence['pair_runs'] if r['run']['variant'] == 'candidate' and r['run']['fault_node'] == 1)

    def reject(self, mutate, paired=False):
        row = deepcopy(self.pair if paired else self.single)
        mutate(row)
        with self.assertRaises(ValueError):
            checker.inspect(row)

    def test_complete_real_matrix(self):
        expected = {(v, n, e) for v in ('baseline', 'candidate') for n in (0, 1) for e in (0, 5 if n == 0 else 28)}
        actual = {(r['run']['variant'], r['run']['node'], r['run']['error']) for r in self.evidence['single_runs']}
        self.assertEqual(actual, expected)
        self.assertEqual(len(self.evidence['single_runs']), 8)
        expected = {('baseline', 0), ('baseline', 1), ('candidate', -1), ('candidate', 0), ('candidate', 1)}
        actual = {(r['run']['variant'], r['run']['fault_node']) for r in self.evidence['pair_runs']}
        self.assertEqual(actual, expected)
        self.assertEqual(len(self.evidence['pair_runs']), 5)
        for row in self.evidence['single_runs'] + self.evidence['pair_runs']:
            self.assertEqual(checker.inspect(row), row['analysis'])
            self.assertFalse(row['analysis']['whole_vm_shutdown_verified'])
            self.assertFalse(row['analysis']['persistent_io_verified'])

    def test_source_runtime_and_capture_hashes_match(self):
        for path, sha in self.evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), sha)
        captures = set()
        for source in self.evidence['capture_sources']:
            self.assertEqual(hashlib.sha256(source['text'].encode()).hexdigest(), source['sha256'])
            captures.add(source['sha256'])
        self.assertTrue(self.evidence['patch_replay']['patch_replays_to_compiled_source'])
        self.assertNotRegex(self.evidence['build_log'], r'warning:|error:')
        for row in self.evidence['single_runs'] + self.evidence['pair_runs']:
            run = row['run']
            expected = self.evidence['candidate_build']['sha256'] if run['variant'] == 'candidate' else self.evidence['baseline_sha256']
            self.assertEqual(run['runtime_sha256'], expected)
            self.assertIn(run['capture_sha256'], captures)
        original = self.evidence['original_source_sha256']
        candidate = self.evidence['candidate_build']['sources']
        self.assertNotEqual(original['system/runstate.c'], candidate['system/runstate.c'])
        for name in ('system/physmem.c', 'monitor/hmp-cmds.c', 'include/monitor/hmp.h', 'hmp-commands.hx'):
            self.assertEqual(original[name], candidate[name])
        guards = self.evidence['path_guards']
        self.assertEqual({g['mode'] for g in guards}, {'delimiter', 'existing'})
        for guard in guards:
            self.assertEqual(guard['exit'], 2)
            self.assertEqual(guard['source_sha256'], self.evidence['source_sha256']['scripts/ssi-lab/probe-shutdown-flush.py'])
            self.assertTrue(guard['no_qemu_started'])
            self.assertTrue(guard['files_preserved'])

    def test_initial_bug_and_rejected_capture_are_retained(self):
        original = self.evidence['exploratory_baseline']
        self.assertEqual(original['exit'], 0)
        self.assertEqual(original['stderr'], 'vm_stop_flush_all ret -5\n')
        self.assertTrue(original['data_matches'])
        self.assertEqual(len(self.evidence['rejected_runs']), 1)
        row = self.evidence['rejected_runs'][0]
        self.assertEqual(row['record']['qemu_exit'], 1)
        self.assertFalse(row['record']['forced_cleanup'])
        self.assertTrue(row['record']['errors'])
        with self.assertRaises(ValueError):
            checker.inspect(row)
        forged = deepcopy(row)
        forged['record']['errors'] = []
        forged['run']['capture_exit'] = 0
        with self.assertRaises(ValueError):
            checker.inspect(forged)

    def test_local_and_peer_exit_codes_are_real(self):
        self.reject(lambda r: r['record'].update(qemu_exit=0))
        self.reject(lambda r: r['records'][0].update(qemu_exit=0), paired=True)
        self.reject(lambda r: r['records'][1].update(qemu_exit=0), paired=True)
        self.reject(lambda r: r['records'][0].update(qemu_exit=-9), paired=True)
        self.reject(lambda r: r['record'].update(qemu_exit=124))

    def test_actual_flush_failure_and_message_are_required(self):
        self.reject(lambda r: r['record'].update(stderr=r['record']['stderr'].replace('ret -5', 'ret 0')))
        self.reject(lambda r: r['record'].update(stderr=r['record']['stderr'].replace('QEMU device shutdown/flush failed', 'lost message')))
        self.reject(lambda r: r['records'][1].update(stderr=r['records'][1]['stderr'].replace('ret -28', 'ret -5')), paired=True)
        self.reject(lambda r: r['records'][0].update(stderr=r['records'][0]['stderr'] + '\nSSI_DRAIN_COMPLETE node=0 peers=1\n'), paired=True)
        self.reject(lambda r: r['records'][0].update(stderr=r['records'][0]['stderr'].replace(
            'SSI missing or invalid drain acknowledgement', 'unrelated').replace(
            'SSI router EOF before acknowledged drain', 'unrelated')), paired=True)

    def test_flush_cannot_be_skipped_or_injected_as_a_write_error(self):
        self.reject(lambda r: r['record']['qmp'][2]['responses'][0]['return'][0]['inserted']['cache'].update(**{'no-flush': True}))
        self.reject(lambda r: r['record'].update(blkdebug_config=r['record']['blkdebug_config'].replace('iotype = "flush"', 'iotype = "write"')))
        self.reject(lambda r: r['record'].update(stderr=r['record']['stderr'].replace('flags 0x0', 'flags 0x1')))
        self.reject(lambda r: r['record'].update(injected_errno=0))

    def test_data_and_device_identity_cannot_be_forged(self):
        self.reject(lambda r: r['record'].update(data_sha256='0' * 64))
        self.reject(lambda r: r['record'].update(stdout=r['record']['stdout'].replace('wrote 65536/65536', 'wrote 0/65536')))
        self.reject(lambda r: r['record']['qmp'][5]['responses'][0]['return'][0]['stats'].update(wr_highest_offset=0))
        self.reject(lambda r: r['record']['qmp'][2]['responses'][0]['return'][0].update(qdev='/machine/other'))

    def test_qmp_success_is_not_enough_and_missing_setup_is_rejected(self):
        self.reject(lambda r: r['record']['qmp'][1]['responses'][0]['return'].update(running=True))
        self.reject(lambda r: r['record']['qmp'][3]['request']['arguments'].update(**{'command-line': 'info block'}))
        self.reject(lambda r: r['record']['qmp'][4]['responses'][0].update(error={'class': 'GenericError'}))
        self.reject(lambda r: r['record'].update(quit_transport={'kind': 'reset', 'errno': 110}))

    def test_pair_uses_one_initiator_and_both_ready_processes(self):
        self.reject(lambda r: r['records'][1].update(action='quit'), paired=True)
        self.reject(lambda r: r['run']['ready']['0'].update(pid=1), paired=True)
        self.reject(lambda r: r['run'].update(node1_remaining='qemu-system-x86'), paired=True)
        self.reject(lambda r: r['run'].update(capture_exits=[0, 1]), paired=True)

    def test_capture_identity_and_cleanup_are_checked(self):
        self.reject(lambda r: r['record'].update(forced_cleanup=True))
        self.reject(lambda r: r['record'].update(qemu_sha256='0' * 64))
        self.reject(lambda r: r['record'].update(capture_sha256='0' * 64))
        self.reject(lambda r: r['record'].update(kernel='other'))
        self.reject(lambda r: r['record'].update(stderr=r['record']['stderr'] + '\nsegmentation fault\n'))

    def test_probe_never_reuses_existing_directory(self):
        probe = load('probe-shutdown-flush')
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            sentinel = target / 'disk.raw'
            sentinel.write_bytes(b'existing company data')
            with self.assertRaises(FileExistsError):
                probe.prepare(SimpleNamespace(directory=target), 'unused')
            self.assertEqual(sentinel.read_bytes(), b'existing company data')
            self.assertEqual(list(target.iterdir()), [sentinel])

    def test_directory_cannot_inject_qemu_drive_parameters(self):
        probe = load('probe-shutdown-flush')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name in ('a,file=other', 'a:other', 'a\nb', 'a\rb'):
                target = root / name
                with self.assertRaises(ValueError):
                    probe.prepare(SimpleNamespace(directory=target), 'unused')
                self.assertFalse(target.exists())

    def test_probe_refuses_disk_boundary_changes(self):
        self.reject(lambda r: r['record'].update(directory_created_exclusively=False))
        self.reject(lambda r: r['record'].update(image_regular=False))
        self.reject(lambda r: r['record'].update(image_size_after=1024))
        self.reject(lambda r: r['record']['command'].extend(['-drive', 'file=other.img']))
        self.reject(lambda r: r['record']['command'].extend(['-kernel', 'guest']))

    def test_full_guest_regressions_keep_unresolved_shutdown_errors(self):
        boot, clock = load('check-ssh-boot'), load('check-clock')
        for row in self.evidence['workspace_runs']:
            self.assertFalse(row['full_ssi_accepted'])
            for hashes in row['runtime_hashes']:
                self.assertEqual(hashes['qemu'], self.evidence['candidate_build']['sha256'])
                self.assertEqual(hashes['kernel'], self.evidence['kernel_sha256'])
            trials = ['CLOCK_START' + t for t in row['clock_log'].split('CLOCK_START')[1:]]
            actual = []
            for trial in trials:
                try:
                    clock.validate(trial, 250000000)
                    actual.append(None)
                except ValueError as error:
                    actual.append(str(error))
            self.assertEqual(actual, row['validation']['clock'])
            for log, error in zip(row['host_logs'], row['validation']['hosts']):
                if error:
                    with self.assertRaises(ValueError):
                        boot.check_errors(log)
                else:
                    boot.check_errors(log)

    def test_stock_restoration_and_boot_files_are_verified(self):
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual({n['node'] for n in nodes}, {0, 1})
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            for key in ('identity_matches', 'old_boot_files_unchanged', 'firewall_matches_original'):
                self.assertTrue(node[key])
            for key in ('remaining_processes', 'trace_events', 'trace_instances', 'grub_environment'):
                self.assertFalse(node[key])


if __name__ == '__main__':
    unittest.main()
