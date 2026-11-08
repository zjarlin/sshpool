"""重放真实 steal-time 失败与修复，核验补丁来源并拒绝损坏的交接和关闭证据。"""
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('steal', HERE / 'check-steal-time.py')
steal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(steal)
clock = steal.close.load('check-clock')
stress = steal.close.load('check-stress')


def transform_raw(raw, change):
    rows = []
    for line in raw.splitlines():
        prefix = next((p for p in ('PVCLOCK_CHECK ', 'PVCLOCK_RESULT ') if line.startswith(p)), '')
        rows.append((prefix, json.loads(line[len(prefix):])))
    change(rows)
    return '\n'.join(prefix + json.dumps(row) for prefix, row in rows) + '\n'


class StealTimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-steal-time-20261108.json').read_text())
        cls.runs = cls.evidence['runs']
        cls.raw = cls.runs[-1]['raw']

    def reject(self, change):
        with self.assertRaises(ValueError):
            steal.inspect(transform_raw(self.raw, change), 2)

    def test_all_public_raw_runs_recompute_and_close(self):
        for run, failures in zip(self.runs, (0, 8, 0, 0)):
            with self.subTest(label=run['label']):
                analysis = steal.inspect(run['raw'], run['nodes'])
                self.assertEqual(analysis, run['analysis'])
                self.assertEqual(analysis['failures'], failures)
                self.assertFalse(analysis['preemption_hint_verified'])
                self.assertFalse(analysis['full_ssi_accepted'])
                for node, log in enumerate(run['host_logs']):
                    steal.inspect_host(log, node, analysis['generation'], run['nodes'])
                self.assertTrue(run['firewall']['restored_exactly'])
                self.assertEqual(run['firewall']['before'], run['firewall']['after'])

    def test_probe_source_matches_the_same_tested_binary(self):
        build = self.evidence['probe_build']
        self.assertEqual(hashlib.sha256((HERE / 'probe-pvclock.c').read_bytes()).hexdigest(), build['source_sha256'])
        self.assertEqual(build['binary_sha256'], '57787bfe3eb57eebdea49a5d7d49a0d05cde4ecf9e82a4da3cf17d1e66beda2c')

    def test_claim_owner_order_and_completeness_are_required(self):
        self.reject(lambda rows: rows.pop(2))
        self.reject(lambda rows: rows[2][1].update(node=1))
        self.reject(lambda rows: rows[2][1].update(node=False))
        self.reject(lambda rows: rows[2][1].update(op='read'))
        self.reject(lambda rows: rows[3][1].update(records=rows[3][1]['records'][:1]))
        self.reject(lambda rows: rows.append(rows[-1]))

    def test_invalid_record_types_ranges_and_reserved_bytes_are_rejected(self):
        for field, value in [('version', -1), ('version', 1 << 32), ('version', True),
                             ('steal', 1 << 64), ('steal', -1), ('steal', '123'),
                             ('flags', 1), ('preempted', 256), ('padding', 'ff' * 47)]:
            with self.subTest(field=field, value=value):
                self.reject(lambda rows: rows[3][1]['records'][0].update({field: value}))

    def test_reported_success_cannot_override_raw_failure(self):
        baseline = self.runs[1]['raw']
        def falsify(rows):
            for prefix, row in rows:
                if prefix == 'PVCLOCK_CHECK ':
                    row['pass'] = True
                if prefix == 'PVCLOCK_RESULT ':
                    row['failures'] = 0
        with self.assertRaisesRegex(ValueError, '重算'):
            steal.inspect(transform_raw(baseline, falsify), 2)

    def test_stale_torn_regressing_and_damaged_records_fail(self):
        original = self.runs[-1]['analysis']['exchanges'][0]
        for kind in ('stale', 'torn', 'regress', 'neighbor', 'marker', 'preempted'):
            row = deepcopy(original)
            if kind == 'stale':
                row['observed'] = row['previous']
            else:
                for side in ('latest', 'observed'):
                    record = row[side]['records'][row['cpu']]
                    if kind == 'torn':
                        record['version'] |= 1
                    if kind == 'regress':
                        record['steal'] = 0
                    if kind == 'neighbor':
                        row[side]['records'][1 - row['cpu']]['steal'] += 1
                    if kind == 'marker':
                        row[side]['marker'] = 99
                    if kind == 'preempted':
                        record['preempted'] = 1
            with self.subTest(kind=kind):
                result = steal.probe.check_exchange(row['before'], row['previous'], row['latest'],
                                                     row['observed'], row['cpu'], row['reader'], 'steal')
                self.assertFalse(result['pass'])

    def test_close_requires_both_nodes_same_generation_before_fd_release(self):
        def change_seal(rows, field, value):
            next(row for _, row in rows if row.get('op') == 'sealed')[field] = value
        for field, value in [('generation', 0), ('generation', True), ('generation', 1 << 64),
                             ('generation', 123), ('node', 9), ('op', 'closed')]:
            with self.subTest(field=field, value=value):
                self.reject(lambda rows: change_seal(rows, field, value))
        def reorder(rows):
            index = next(i for i, (_, row) in enumerate(rows) if row.get('op') == 'sealed')
            rows[index], rows[index + 2] = rows[index + 2], rows[index]
        self.reject(reorder)

    def test_host_counters_errors_and_generation_are_required(self):
        run = self.runs[-1]
        log, gen = run['host_logs'][0], run['analysis']['generation']
        for bad in [log.replace('accepted=2', 'accepted=1'), log.replace('eof=2', 'eof=1'),
                    log.replace(f'generation={gen}', 'generation=1'), log + '\nBUG: injected\n',
                    log + '\nkvm-dsm: request failed\n', log + log]:
            with self.assertRaises(ValueError):
                steal.inspect_host(bad, 0, gen, 2)

    def test_cli_retains_baseline_failure_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'probe.jsonl'
            for run, code in [(self.runs[1], 1), (self.runs[-1], 0)]:
                path.write_text(run['raw'])
                result = subprocess.run([sys.executable, str(HERE / 'check-steal-time.py'), str(path),
                                         '--nodes', '2'], capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(json.loads(result.stdout)['failures'], run['analysis']['failures'])

    def test_kernel_patch_zero_fuzz_replays_compiled_source(self):
        base = self.evidence['kernel_base_source']
        data = (ROOT / 'docs/evidence' / base['file']).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), base['sha256'])
        source = gzip.decompress(data)
        self.assertEqual(hashlib.sha256(source).hexdigest(), base['uncompressed_sha256'])
        previous = json.loads((ROOT / 'docs/evidence/ssi-kernel-close-20261108.json').read_text())['build']['compiled_sources']
        current = self.evidence['kernel_build']['compiled_sources']
        self.assertEqual(previous['arch/x86/kvm/x86.c'], base['uncompressed_sha256'])
        self.assertEqual({key: value for key, value in current.items() if key != 'arch/x86/kvm/x86.c'},
                         {key: value for key, value in previous.items() if key != 'arch/x86/kvm/x86.c'})
        self.assertIn(b'SPDX-License-Identifier: GPL-2.0-only', source)
        patch = HERE / 'experiments/kernel-dsm-steal-time.patch'
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), self.evidence['kernel_build']['patch_sha256'])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'arch/x86/kvm/x86.c'
            path.parent.mkdir(parents=True)
            path.write_bytes(source)
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                    cwd=tmp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('offset', result.stdout)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                             self.evidence['kernel_build']['compiled_sources']['arch/x86/kvm/x86.c'])
        before = self.evidence['kernel_config']['before']
        self.assertEqual(before.replace('CONFIG_LOCALVERSION="-sshpool-gvm-pf28"',
                                        'CONFIG_LOCALVERSION="-sshpool-gvm-pf29"'), self.evidence['kernel_config']['pf29'])

    def test_qemu_profile_patch_changes_only_the_exact_kernel(self):
        before = self.evidence['qemu_base_source']
        patch = HERE / 'experiments/qemu-pf29-lab-profile.patch'
        build = self.evidence['qemu_build']
        previous = json.loads((ROOT / 'docs/evidence/ssi-qemu-close-20261108.json').read_text())['build']['compiled_source_sha256']
        current = build['compiled_source_sha256']
        self.assertEqual(hashlib.sha256(before.encode()).hexdigest(), previous['system/ssi-close.inc'])
        self.assertEqual({key: value for key, value in current.items() if key != 'system/ssi-close.inc'},
                         {key: value for key, value in previous.items() if key != 'system/ssi-close.inc'})
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), build['patch_sha256'])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'system/ssi-close.inc'
            path.parent.mkdir()
            path.write_text(before)
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                    cwd=tmp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(path.read_text(), before.replace('PF28', 'PF29').replace('gvm-pf28', 'gvm-pf29'))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), build['compiled_source_sha256']['system/ssi-close.inc'])

    def test_workspace_close_preserves_guard_failure_and_trace_boundary(self):
        failed = next(row for row in self.evidence['workspaces'] if row['label'] == 'pf29-steal-workspace-pair-a')
        runtime = self.evidence['qemu_build']['sha256']
        with self.assertRaises(ValueError):
            steal.inspect_workspace_close(failed, runtime)
        row = next(row for row in self.evidence['workspaces'] if row['label'] == 'pf29-steal-workspace-pair-b')
        analysis = steal.inspect_workspace_close(row, runtime)
        self.assertEqual(analysis, row['close_analysis'])
        self.assertFalse(analysis['native_function_trace_verified'])
        for field, value in [('qemu_ssh_exits', [0, 1]), ('samples_errors', ['injected']),
                             ('qemu_sha256', 'wrong'), ('management_timeout', True)]:
            bad = deepcopy(row)
            bad['result'][field] = value
            with self.assertRaises(ValueError):
                steal.inspect_workspace_close(bad, runtime)

        for old, new in [('read=0', 'read=1'), ('SSI_DEVICE_CLOSE_COMPLETE', ''),
                         ('SSI_DRAIN_ACK_SENT', 'SSI_DRAIN_ACK_RECEIVED')]:
            bad = deepcopy(row)
            bad['qemu_stderr'][0] = bad['qemu_stderr'][0].replace(old, new)
            with self.assertRaises(ValueError):
                steal.inspect_workspace_close(bad, runtime)

    def test_workspace_timer_failure_survives_zero_probe_and_qemu_exits(self):
        for row in self.evidence['workspaces']:
            for node in range(len(row['result']['qemu_ssh_exits'])):
                hashes = [line.split()[0] for line in row['files'][f'node{node}-hashes.txt'].splitlines()]
                self.assertEqual(hashes[:2], [self.evidence['kernel_build']['kernel'], row['result']['qemu_sha256']])
            self.assertEqual(row['firewall']['before'], row['firewall']['after'])
            for phase in ('identity', 'clock-upload', 'clock', 'stress', 'pause-user', 'sftp'):
                self.assertEqual(row['result']['phases'][phase]['exit'], 0)
            self.assertTrue(row['result']['sftp_matches'])
            self.assertEqual(row['result']['sftp_sha256'],
                             'fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83')
            stress.validate(row['files']['stress.log'])
            self.assertEqual(row['files']['pause-user.log'].splitlines(),
                             [f'PAUSE_CPU cpu={cpu} cpl=3 iterations=64 checksum=2080' for cpu in range(4)])
            trials = row['files']['clock.log'].split('CLOCK_START')[1:]
            self.assertEqual(len(trials), 3)
            for trial in trials:
                clock.validate('CLOCK_START' + trial)
            timers = [int(value) for value in re.findall(r'elapsed_ns=(\d+)', row['files']['clock.log'])]
            self.assertEqual(len(timers), 12)
            self.assertEqual(row['timers'], {'count': 12, 'max_elapsed_ns': max(timers),
                                             'gate_ns': 250_000_000, 'passed': max(timers) <= 250_000_000})
        row = self.evidence['workspaces'][-1]
        self.assertEqual(row['label'], 'pf29-steal-workspace-pair-b')
        self.assertEqual(row['result']['phases']['clock']['exit'], 0)
        self.assertEqual(row['result']['qemu_ssh_exits'], [0, 0])
        self.assertEqual(row['timers']['max_elapsed_ns'], 359_971_240)
        self.assertFalse(row['timers']['passed'])
        with self.assertRaisesRegex(ValueError, '超过'):
            for trial in row['files']['clock.log'].split('CLOCK_START')[1:]:
                clock.validate('CLOCK_START' + trial, 250_000_000)

    def test_stock_restoration_covers_both_lab_nodes(self):
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual([node['node'] for node in nodes], [0, 1])
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            for field in ('identity_matches', 'old_boot_files_unchanged', 'grub_config_unchanged',
                          'firewall_matches_original', 'stock_grub_default', 'pf29_grub_entry_removed'):
                self.assertTrue(node[field])
            for field in ('grub_environment', 'remaining_processes', 'remaining_trace_instances', 'remaining_experiment_tcp'):
                self.assertFalse(node[field])



if __name__ == '__main__':
    unittest.main()
