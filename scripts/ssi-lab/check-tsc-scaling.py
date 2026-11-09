#!/usr/bin/env python3
"""重放软件 TSC 实验；三条读取路径和 pvclock 必须同时满足包络。"""
import argparse
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('frequency', HERE / 'check-tsc-frequency.py')
frequency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(frequency)
require = frequency.require
integer = frequency.integer
sha = frequency.sha
read_artifact = frequency.read_artifact
MODES = ('native', 'faster', 'slower', 'target')
CLOCKS = ('guest_tsc', 'guest_tscp', 'guest_msr')


def inspect_run(run, build, enabled, native, target):
    selection, mode = run['selection'], run['mode']
    require(selection in ('control', 'software') and mode in MODES, '未知运行模式')
    require(run['stderr'] == '' and 0 < run['elapsed_ns'] < 15000000000, '探针错误或运行超期')
    rows = [json.loads(line) for line in run['stdout'].splitlines()]
    selected = selection == 'software'
    if selected and not enabled:
        require(run['exit'] == 2 and rows == [{'op': 'unavailable', 'fds_closed': 3, 'run_calls': 0}],
                '默认关闭时仍允许软件执行')
        return {'selection': selection, 'mode': mode, 'unavailable': True}
    require(run['exit'] == 0 and len(rows) >= 3, '探针没有正常退出')
    code, config = rows[:2]
    guest_hex = build['guest_hex']
    require(code == {'op': 'guest_code', 'gpa': 4096, 'bytes': len(bytes.fromhex(guest_hex)), 'hex': guest_hex},
            '客体指令与构建不符')
    requested = {'native': native, 'faster': native * 6 // 5, 'slower': native * 4 // 5, 'target': target}[mode]
    rejected = not selected and requested < native
    expected = {'op': 'configuration', 'kernel': build['kernel_version'], 'mode': mode,
                'native_khz': native, 'requested_khz': requested, 'reported_khz': requested,
                'control': 0, 'set_result': -1 if rejected else 0, 'set_errno': 22 if rejected else 0,
                'vcpu_host_cpu': 0, 'observer_host_cpu': 1, 'selected': selected,
                'attribute_supported': enabled, 'invalid_value_errno': 22 if selected else 0,
                'invalid_flags_errno': 6 if selected else 0}
    require(config == expected, '频率配置、硬件能力或软件选择不符')
    require(rows[-1] == {'op': 'closed', 'run_calls': 0 if rejected else 1,
                         'fds_closed': 3, 'rejected': rejected}, '关闭或执行次数不符')
    result = {'selection': selection, 'mode': mode, 'requested_khz': requested}
    if rejected:
        require(len(rows) == 3, '拒绝设置后仍执行客体')
        return {**result, 'rejected_before_run': True}
    tail = ['late_change'] if selected else ['late_selection'] if enabled else []
    require([row['op'] for row in rows] == ['guest_code', 'configuration'] + ['sample'] * 12 +
            ['run_done'] + tail + ['closed'], '采样或生命周期顺序不符')
    done = rows[14]
    require(done['result'] == done['errno'] == 0 and done['exit_reason'] == 5 and
            done['rip'] == 4096 + code['bytes'], '没有正常 HLT')
    require(done['reported_khz_after_run'] == requested, '执行后频率元数据变化')
    if selected:
        require(rows[15] == {'op': 'late_change', 'rate_result': -1, 'rate_errno': 22,
                            'attribute_result': -1, 'attribute_errno': 16, 'reported_khz': requested},
                '运行后改频或选择未拒绝')
    elif enabled:
        require(rows[15] == {'op': 'late_selection', 'result': -1, 'errno': 16, 'selected': False},
                '普通实例执行后仍允许选择')
    samples, pv = rows[2:14], []
    rate = requested if selected else native
    for index, sample in enumerate(samples):
        require(sample['index'] == index, '样本重复或错序')
        for key in ('host_before_ns', 'host_after_ns', *CLOCKS):
            integer(sample[key], 1, 2**64 - 1, key)
        width = sample['host_after_ns'] - sample['host_before_ns']
        require(0 <= width <= (100000000 if index == 0 else 10000000), '宿主包络过宽或倒退')
        require(sample['tsc_aux'] == 0x53534901, 'RDTSCP AUX 不符')
        # 三次读发生在同一包络内，既比较速率，也限制零点差异。
        require(sample['guest_tsc'] <= sample['guest_tscp'] <= sample['guest_msr'] and
                (sample['guest_msr'] - sample['guest_tsc']) * 1000000 <= width * rate * Fraction(1001, 1000),
                'RDTSC/RDTSCP/MSR 零点或顺序不一致')
        pv.append(frequency.pvclock(sample))
        if index:
            previous = samples[index - 1]
            require(90000000 <= sample['host_before_ns'] - previous['host_after_ns'] <= 500000000,
                    '采样间隔异常')
            require(all(sample[key] > previous[key] for key in CLOCKS) and pv[-1] > pv[-2], '客体时钟倒退')
    # 固定使用 1→11 和每个相邻区间；不根据实际结果挑选样本。
    for left, right in [(i - 1, i) for i in range(2, 12)] + [(1, 11)]:
        intervals = {}
        for key in CLOCKS:
            interval = frequency.bounds(samples[left], samples[right], samples[right][key] - samples[left][key], 1000000)
            require(rate * Fraction(999, 1000) <= interval[0] <= interval[1] <= rate * Fraction(1001, 1000),
                    key + ' 实测速率不在千分之一容差内')
            if requested != native:
                excluded = native if selected else requested
                require(not frequency.overlaps(interval, excluded, Fraction(excluded, 1000)), '未排除另一频率')
            intervals[key] = [float(value) for value in interval]
        interval = frequency.bounds(samples[left], samples[right], pv[right] - pv[left])
        require(Fraction(999, 1000) <= interval[0] <= interval[1] <= Fraction(1001, 1000), 'pvclock 速率不符')
        intervals['pvclock'] = [float(value) for value in interval]
    require(done['clock'] >= pv[-1], '结束时钟早于末次 pvclock')
    return {**result, 'sample_pair': [1, 11], 'bounds': intervals,
            'requested_rate_observed': selected or requested == native}


def inspect_capture(data, build, identity, native, target, enabled, expected_msr_failure=False):
    require(data['schema'] == 1 and data['software_enabled'] is enabled and data['target_khz'] == target,
            '采集模式不符')
    for name in ('source_sha256', 'capture_sha256', 'binary_sha256'):
        require(data[name] == build[name], '源码或二进制哈希不符')
    require(data['before'] == data['after'], '前后身份配置或清理状态变化')
    host = data['before']
    require(host['kernel'] == build['kernel_version'] and host['architecture'] == 'x86_64' and
            host['clocksource'] == 'tsc', '宿主计时前提不符')
    require(host['processes'] == host['kvm_fds'] == [] and host['allowed_cpus'] == [0, 1], '进程、fd 或 CPU 不符')
    require(set(host['identity_sha256']) == {'machine', 'dmi', 'boot'} and
            all(host['identity_sha256'][key] == identity[key] for key in ('machine', 'dmi')), '采集混入其他节点')
    require(host['identity_sha256']['boot'] != identity['boot'], '实验未离开原版启动身份')
    digests = list(host['identity_sha256'].values()) + list(host['files_sha256'].values()) + [host['firewall_sha256']]
    require(all(re.fullmatch('[0-9a-f]{64}', value) for value in digests), '宿主摘要无效')
    version = build['kernel_version']
    directory = '/var/lib/sshpool/boot-' + version.rsplit('-', 1)[1]
    files = host['files_sha256']
    require({'/etc/fstab', '/etc/default/grub', '/boot/grub/grub.cfg', '/boot/grub/grubenv',
             '/proc/cmdline', '/etc/netplan/90-ssi-unique.yaml'} <= set(files), '缺少启动配置')
    require(files[directory + '/vmlinuz-' + version] == build['kernel_sha256'] and
            files[directory + '/config-' + version] == build['config_sha256'], '运行内核或配置与构建不符')
    require(host['modules'] == {key: {'builtin': True, 'kernel_sha256': build['kernel_sha256']}
                                for key in ('kvm', 'kvm_intel')}, '内置 KVM 来源不符')
    parameters = {'kvm_intel/parameters/lab_tsc_scaling': 'Y' if enabled else 'N',
                  'kvm_intel/parameters/nested': 'N', 'kvm_intel/parameters/enable_apicv': 'N',
                  'kvm/parameters/dsm_write_grace_us': '0'}
    require(host['parameters'] == parameters and
            all(files['/sys/module/' + name] == sha((value + '\n').encode()) for name, value in parameters.items()),
            '宿主开关或参数摘要不符')
    require(data['finished_unix_ns'] > data['started_unix_ns'], '采集生命周期倒退')
    plans = [(s, m) for s in ('control', 'software') for m in MODES if s == 'control' or enabled or m == 'native']
    require([(run['selection'], run['mode']) for run in data['runs']] == plans, '模式矩阵不完整')
    results = []
    for run in data['runs']:
        failed = expected_msr_failure and run['selection'] == 'software' and run['mode'] != 'native'
        try:
            result = inspect_run(run, build, enabled, native, target)
        except ValueError as error:
            require(failed and str(error) == 'RDTSC/RDTSCP/MSR 零点或顺序不一致', '非预期失败: ' + str(error))
            result = {'selection': run['selection'], 'mode': run['mode'], 'rejected': str(error)}
        require(('rejected' in result) == failed, 'PF31 MSR 失败被掩盖')
        results.append(result)
    return results


def check(path):
    manifest = json.loads(path.read_text())
    require(manifest['schema'] == 1, '未知清单协议')
    baseline = manifest['baseline']
    baseline_path = path.parent / baseline['file']
    require(sha(baseline_path.read_bytes()) == baseline['sha256'], '基线哈希不符')
    frequency.check(baseline_path)
    prior = json.loads(baseline_path.read_text())
    capture = json.loads(read_artifact(path.parent, prior['candidate']['capture']))
    identity = capture['before']['identity_sha256']
    native = json.loads(capture['runs'][0]['stdout'].splitlines()[1])['native_khz']
    target = prior['preflight']['report']['peers'][0]['probe']['vcpus'][0]['tsc_khz']
    require(manifest['native_khz'] == native and manifest['target_khz'] == target, '实测基线频率不符')
    sources = json.loads(read_artifact(path.parent, manifest['sources']))
    require(set(manifest['patches']) == {'kernel-software-tsc.patch', 'kernel-software-tsc-msr.patch',
                                        'probe-tsc-scaling.patch', 'capture-tsc-scaling.patch'}, '补丁清单不完整')
    for filename, digest in manifest['patches'].items():
        require(sha((HERE / 'experiments' / filename).read_bytes()) == digest and
                sha(sources['patches'][filename].encode()) == digest, '实验补丁与归档不符')
    require(set(manifest['builds']) == {'pf31', 'pf32'}, '构建或失败候选缺失')
    for label, build in manifest['builds'].items():
        require(build['kernel_version'] == '7.1.0-rc3-sshpool-gvm-' + label, '构建版本不符')
        for name, key in [('probe-tsc-scaling.c', 'source_sha256'), ('capture-tsc-scaling.py', 'capture_sha256')]:
            require(sha(sources[name].encode()) == build[key], '构建源码摘要不符')
        require(sha(sources['config-' + label].encode()) == build['config_sha256'], '构建配置摘要不符')
        for name, digest in build['compiled_sources'].items():
            require(sha(sources[label][name].encode()) == digest, '实际内核源码摘要不符')
        instructions = re.findall(r'^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2} )+)', sources['guest-disassembly.txt'], re.M)
        require(''.join(instructions).replace(' ', '') == build['guest_hex'], '反汇编与客体指令不符')
    require([row['label'] for row in manifest['captures']] == ['pf31-off', 'pf31-on', 'pf32-off', 'pf32-on'],
            '正式矩阵或历史失败缺失')
    boots, results = set(), {}
    for row in manifest['captures']:
        label, enabled = row['label'].split('-')
        enabled = enabled == 'on'
        data = json.loads(read_artifact(path.parent, row['capture']))
        boot = data['before']['identity_sha256']['boot']
        require(boot not in boots, '启动身份重复或使用陈旧采集')
        boots.add(boot)
        require(row['runner_exit'] == 0 and re.fullmatch(
            r'\[\s*\d+\.\d+\] kvm: user requested TSC rate below hardware speed\n', row['kernel_log_delta']),
            '采集失败或内核日志异常')
        result = inspect_capture(data, manifest['builds'][label], identity, native, target, enabled,
                                 expected_msr_failure=row['label'] == 'pf31-on')
        require(result == row['analysis'], '保存分析与重算不符')
        results[row['label']] = result
    cleanup = manifest['cleanup']
    host = cleanup['snapshot']
    require(host['kernel'] == '6.8.0-147-generic' and host['processes'] == host['kvm_fds'] == [], '未恢复原版或遗留 fd')
    require(all(host['identity_sha256'][key] == identity[key] for key in ('machine', 'dmi')) and
            host['identity_sha256']['boot'] not in boots | {identity['boot']}, '恢复启动身份不符')
    require(cleanup['experiment_paths_removed'] is True and
            cleanup['restored'] == {'restored_files': 90, 'restored_bytes': 90865762}, '实验文件或下载缓存未恢复')
    checks = cleanup['configuration_checks']
    require(set(checks) == {'grub.cfg', 'boot.sha256', 'firewall', 'netplan'} and all(
        re.fullmatch('[0-9a-f]{64}', row['before_sha256']) and row['before_sha256'] == row['after_sha256']
        for row in checks.values()), '恢复配置不符')
    require(host['files_sha256']['/boot/grub/grub.cfg'] == checks['grub.cfg']['after_sha256'] and
            host['firewall_sha256'] == checks['firewall']['after_sha256'], '恢复快照与配置摘要不符')
    require(manifest['full_ssi_accepted'] is False and manifest['cross_physical_verified'] is False and
            manifest['default_runtime_enabled'] is False, '限定实验被提升为 SSI 准入')
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    print(json.dumps(check(parser.parse_args().manifest), ensure_ascii=False, indent=2))
