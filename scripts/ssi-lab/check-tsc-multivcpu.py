#!/usr/bin/env python3
"""重放同一 KVM 实例双 vCPU 的比例、偏移与 CPU 轮换；保留真实错位对照。"""
import argparse
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scaling', HERE / 'check-tsc-scaling.py')
scaling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scaling)
freq = scaling.frequency
require, integer, sha, read_artifact = freq.require, freq.integer, freq.sha, freq.read_artifact
CLOCKS = (*scaling.CLOCKS, 'pvclock_ns')
SKEW_LIMIT_NS = 100000


def interval_status(interval, lower, upper):
    if lower <= interval[0] <= interval[1] <= upper:
        return 'within'
    if interval[1] < lower or interval[0] > upper:
        return 'outside'
    return 'inconclusive'


def guest_code(binary):
    """从归档 ELF 的符号和节表定位客体字节，不能只相信探针打印内容。"""
    require(binary[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', binary, 18)[0] == 62,
            '探针不是 x86_64 ELF')
    start = struct.unpack_from('<Q', binary, 40)[0]
    size, count = struct.unpack_from('<HH', binary, 58)
    require(size == 64 and 0 < count < 256 and start + count * size <= len(binary), 'ELF 节表无效')
    sections = [struct.unpack_from('<IIQQQQIIQQ', binary, start + i * size) for i in range(count)]
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        require(section[9] == 24 and section[6] < count, 'ELF 符号表无效')
        strings = sections[section[6]]
        names = binary[strings[4]:strings[4] + strings[5]]
        for position in range(section[4], section[4] + section[5], 24):
            name, _, _, index, value, _ = struct.unpack_from('<IBBHQQ', binary, position)
            label = names[name:].split(b'\0', 1)[0]
            if label in (b'sshpool_tsc_guest_begin', b'sshpool_tsc_guest_end'):
                require(label not in symbols and 0 < index < count, 'ELF 客体符号无效')
                symbols[label] = (index, value)
    require(len(symbols) == 2, 'ELF 缺少客体符号')
    index, begin = symbols[b'sshpool_tsc_guest_begin']
    end_index, end = symbols[b'sshpool_tsc_guest_end']
    section = sections[index]
    require(index == end_index and section[3] <= begin < end <= section[3] + section[5] and
            end - begin <= 4096, 'ELF 客体范围无效')
    offset = section[4] + begin - section[3]
    require(offset + end - begin <= len(binary), 'ELF 客体内容缺失')
    return binary[offset:offset + end - begin].hex()


def inspect_run(run, build, native, target):
    require(run['exit'] == 0 and run['stderr'] == '' and 0 < run['elapsed_ns'] < 15000000000,
            '探针失败或超期')
    mode, alignment = run['mode'], run['alignment']
    require(mode in scaling.MODES and alignment in ('aligned', 'skew'), '运行模式错误')
    rows = [json.loads(line) for line in run['stdout'].splitlines()]
    require([r['op'] for r in rows] == ['configuration', 'offset', 'offset'] + ['sample'] * 24 +
            ['vcpu_done', 'vcpu_done', 'closed'], '记录缺失或顺序错误')
    rate = {'native': native, 'faster': native * 6 // 5, 'slower': native * 4 // 5, 'target': target}[mode]
    require(rows[0] == {'op': 'configuration', 'kernel': build['kernel_version'], 'mode': mode,
                       'alignment': alignment, 'native_khz': native, 'requested_khz': rate,
                       'control': 0, 'vcpus': 2, 'vms': 1, 'host_cpus': [0, 1], 'guest_hex': build['guest_hex']},
            '内核、能力、拓扑或指令不符')
    offsets = []
    for cpu in range(2):
        offset = rows[1 + cpu]
        integer(offset['written'], 0, 2**64 - 1, 'offset')
        require(offset == {'op': 'offset', 'vcpu': cpu, 'written': offset['written'], 'reported': offset['written']},
                '偏移未读回')
        offsets.append(offset['written'])
        require(rows[27 + cpu] == {'op': 'vcpu_done', 'vcpu': cpu, 'exit_reason': 5,
                                   'rip': 4096 + len(bytes.fromhex(build['guest_hex'])), 'run_calls': 13,
                                   'late_result': -1, 'late_errno': 22, 'reported_khz': rate,
                                   'offset_after': offset['written']}, '执行后比例偏移变化或未正常停止')
    require((offsets[1] - offsets[0]) % 2**64 == (rate * 50 if alignment == 'skew' else 0), '共同偏移或注入值不符')
    require(rows[-1] == {'op': 'closed', 'run_calls': 26, 'fds_closed': 4}, '未关闭或执行次数错误')
    samples = rows[3:27]
    for index, sample in enumerate(samples):
        round_index, order = divmod(index, 2)
        cpu = order ^ (round_index & 1)
        require(sample['index'] == index and sample['vcpu'] == cpu and
                sample['host_cpu'] == cpu ^ ((round_index // 3) & 1), '采样身份、顺序或 CPU 轮换错误')
        for key in ('host_before_ns', 'host_after_ns', *scaling.CLOCKS):
            integer(sample[key], 1, 2**64 - 1, key)
        width = sample['host_after_ns'] - sample['host_before_ns']
        require(0 <= width <= (100000000 if round_index == 0 else 1000000), '宿主包络倒退或过宽')
        require(sample['tsc_aux'] == 0x53534900 + cpu, 'AUX 不属于该 vCPU')
        require(sample['guest_tsc'] <= sample['guest_tscp'] <= sample['guest_msr'] and
                (sample['guest_msr'] - sample['guest_tsc']) * 1000000 <= width * rate * Fraction(1001, 1000),
                '三条 TSC 路径顺序或零点错误')
        sample['pvclock_ns'] = freq.pvclock(sample)
        if index:
            gap = sample['host_before_ns'] - samples[index - 1]['host_after_ns']
            require((1000000 if order else build['interval_ns']) <= gap < 750000000, '采样间隔不符')
    rates = []
    for cpu in range(2):
        points = [s for s in samples if s['vcpu'] == cpu]
        for key in CLOCKS:
            require(all(b[key] > a[key] for a, b in zip(points, points[1:])), '同 vCPU 时钟倒退')
        # 首轮仅用来预热；对全部后续相邻区间及 1→11 总区间执行相同门槛。
        for left, right in [(i - 1, i) for i in range(2, 12)] + [(1, 11)]:
            bounds, statuses = {}, {}
            for key in CLOCKS:
                expected = 1 if key == 'pvclock_ns' else rate
                scale = 1 if key == 'pvclock_ns' else 1000000
                interval = freq.bounds(points[left], points[right], points[right][key] - points[left][key], scale)
                statuses[key] = interval_status(interval, expected * Fraction(999, 1000),
                                                expected * Fraction(1001, 1000))
                if key != 'pvclock_ns' and native != rate:
                    require(not freq.overlaps(interval, native, Fraction(native, 1000)), '未排除原生频率')
                bounds[key] = list(map(float, interval))
            rates.append({'vcpu': cpu, 'sample_pair': [left, right], 'bounds': bounds, 'status': statuses})
    cross = []
    for round_index in range(1, 12):
        a, b = samples[round_index * 2:round_index * 2 + 2]
        intervals, statuses = {}, {}
        for key in CLOCKS:
            delta = Fraction(b[key] - a[key])
            if key != 'pvclock_ns':
                delta *= Fraction(1000000, rate)
            interval = (delta - (b['host_after_ns'] - a['host_before_ns']),
                        delta - (b['host_before_ns'] - a['host_after_ns']))
            intervals[key] = list(map(float, interval))
            statuses[key] = interval_status(interval, -SKEW_LIMIT_NS, SKEW_LIMIT_NS)
        if alignment == 'skew':
            # 宽包络只代表未知；负对照必须与容许区间完全分离，并包含有符号的 50 ms 注入值。
            injected = 50000000 if a['vcpu'] == 0 else -50000000
            require(all(statuses[key] == 'outside' and intervals[key][0] <= injected <= intervals[key][1]
                        for key in scaling.CLOCKS), '偏移错误对照没有被实测拒绝')
        cross.append({'round': round_index, 'from_vcpu': a['vcpu'], 'bounds_ns': intervals, 'status': statuses})
    if alignment == 'aligned':
        require(all(b[key] > a[key] for a, b in zip(samples, samples[1:]) for key in CLOCKS), '跨 vCPU 时钟倒退')
    rate_passed = all(status == 'within' for row in rates for status in row['status'].values())
    offset_passed = all(status == 'within' for row in cross for status in row['status'].values())
    return {'mode': mode, 'alignment': alignment, 'accepted': rate_passed and offset_passed and alignment == 'aligned',
            'rate_passed': rate_passed, 'offset_passed': offset_passed,
            'injected_skew_detected': alignment == 'skew',
            'rates': rates, 'cross': cross}


def inspect_capture(data, build, previous):
    require(data['schema'] == 2 and data['target_khz'] == previous['target_khz'] and
            data['finished_unix_ns'] > data['started_unix_ns'], '采集配置或时间错误')
    for key in ('source_sha256', 'capture_sha256', 'binary_sha256'):
        require(data[key] == build[key], '运行与构建身份不同')
    require(data['before'] == data['after'], '采集后状态变化')
    host = data['before']
    require(host['kernel'] == build['kernel_version'] and host['architecture'] == 'x86_64' and
            host['clocksource'] == 'tsc' and host['allowed_cpus'] == [0, 1], '运行前提不符')
    require(host['processes'] == host['kvm_fds'] == [], '遗留实验进程或 KVM fd')
    require(all(host['identity_sha256'][k] == previous['cleanup']['snapshot']['identity_sha256'][k]
                for k in ('machine', 'dmi')), '节点身份不符')
    digests = list(host['identity_sha256'].values()) + list(host['files_sha256'].values()) + [host['firewall_sha256']]
    require(all(re.fullmatch('[0-9a-f]{64}', value) for value in digests), '宿主摘要无效')
    require(host['parameters'] == {'kvm_intel/parameters/lab_tsc_scaling': 'Y', 'kvm_intel/parameters/nested': 'N',
                                   'kvm_intel/parameters/enable_apicv': 'N', 'kvm/parameters/dsm_write_grace_us': '0'},
            '实验开关不符')
    require(all(host['files_sha256']['/sys/module/' + key] == sha((value + '\n').encode())
                for key, value in host['parameters'].items()), '实验参数摘要不符')
    require(host['modules'] == {k: {'builtin': True, 'kernel_sha256': build['kernel_sha256']} for k in ('kvm', 'kvm_intel')},
            'KVM 模块来源不符')
    for prefix, key in [('vmlinuz-', 'kernel_sha256'), ('config-', 'config_sha256')]:
        require(host['files_sha256']['/var/lib/sshpool/boot-pf32/' + prefix + build['kernel_version']] ==
                previous['builds']['pf32'][key], '实际启动镜像或配置不符')
    require([(r['mode'], r['alignment']) for r in data['runs']] ==
            [(mode, 'aligned') for mode in scaling.MODES] + [('target', 'skew')], '实验矩阵不完整')
    return [inspect_run(r, build, previous['native_khz'], previous['target_khz']) for r in data['runs']]


def check_manifest(manifest, directory):
    require(manifest['schema'] == 1, '未知清单')
    baseline = directory / manifest['baseline']['file']
    require(sha(baseline.read_bytes()) == manifest['baseline']['sha256'], '基线哈希不符')
    previous = json.loads(baseline.read_text())
    scaling.check(baseline)
    sources = json.loads(read_artifact(directory, manifest['sources']))
    require(sources['probe-tsc-multivcpu.c'] == (HERE / 'probe-tsc-multivcpu.c').read_text() and
            sources['capture-tsc-multivcpu.patch'] == (HERE / 'experiments/capture-tsc-multivcpu.patch').read_text(),
            '归档与复现源码不符')
    labels = ['io-envelope-a', 'handshake-b', 'handshake-c']
    require(set(manifest['builds']) == set(labels) and [row['label'] for row in manifest['captures']] == labels,
            '正式矩阵或历史失败缺失')
    results, hosts, finished = {}, [], 0
    for row in manifest['captures']:
        label = row['label']
        build = manifest['builds'][label]
        require(build['kernel_version'] == previous['builds']['pf32']['kernel_version'] and
                build['kernel_sha256'] == previous['builds']['pf32']['kernel_sha256'], '没有复用已核对的 PF32')
        require(build['interval_ns'] == (500000000 if label == 'handshake-c' else 100000000), '采样间隔被改写')
        source = sources['probe-tsc-multivcpu.c'] if label == 'handshake-c' else sources['probe-' + label + '.c']
        require(sha(source.encode()) == build['source_sha256'] and
                sha(sources['capture-tsc-multivcpu.py'].encode()) == build['capture_sha256'], '采集源码摘要不符')
        binary = read_artifact(directory, build['binary'])
        require(sha(binary) == build['binary_sha256'] and guest_code(binary) == build['guest_hex'],
                '二进制或客体指令身份不符')
        data = json.loads(read_artifact(directory, row['capture']))
        require(data['started_unix_ns'] > finished, '矩阵执行时间重复或倒序')
        finished = data['finished_unix_ns']
        require(row['runner'] == {'exit': 0, 'stdout': '', 'stderr': ''} and row['kernel_log_delta'] == '' and
                re.fullmatch('[0-9a-f]{64}', row['kernel_log_before_sha256']) and
                row['kernel_log_before_sha256'] == row['kernel_log_after_sha256'], '采集错误或新增内核告警')
        result = inspect_capture(data, build, previous)
        require(result == row['analysis'], '保存分析与重算不同')
        results[label] = result
        hosts.append(data['before'])
    require(hosts[0] == hosts[1] == hosts[2], '矩阵来自不同启动或状态')
    expected_rates = {'io-envelope-a': [False] * 5, 'handshake-b': [True, False, True, False, True],
                      'handshake-c': [True] * 5}
    expected_offsets = {'io-envelope-a': [False] * 5, 'handshake-b': [True, False, True, False, False],
                        'handshake-c': [False] * 5}
    for label in labels:
        require([r['rate_passed'] for r in results[label]] == expected_rates[label] and
                [r['offset_passed'] for r in results[label]] == expected_offsets[label], '保留失败的结论被改变')
    setup = manifest['setup_failure']
    require(sha(sources['capture-setup-a.py'].encode()) == setup['source_sha256'] and
            setup['runner']['exit'] == 2 and setup['runner']['stdout'] == '' and
            setup['runner']['stderr'].endswith('error: the following arguments are required: --software\n'),
            '采集器参数失败记录缺失')
    before, after = manifest['before'], manifest['cleanup']['snapshot']
    host = hosts[0]
    for state in (before, after):
        require(state['processes'] == state['kvm_fds'] == [], '遗留实验进程或 KVM fd')
        require(all(state['identity_sha256'][k] == host['identity_sha256'][k] for k in ('machine', 'dmi')),
                '恢复节点身份不符')
    require(before['kernel'] == after['kernel'] == '6.8.0-147-generic' and
            len({s['identity_sha256']['boot'] for s in (before, host, after)}) == 3, '没有完整启动恢复')
    cleanup = manifest['cleanup']
    require(cleanup['experiment_paths_removed'] is True and
            re.fullmatch('[0-9a-f]{64}', cleanup['experiment_archive_sha256']), '实验路径未归档清理')
    checks = cleanup['configuration_checks']
    require(set(checks) == {'grub.cfg', 'boot.sha256', 'firewall', 'netplan', 'apt.sha256'} and
            all(re.fullmatch('[0-9a-f]{64}', row['before_sha256']) and row['before_sha256'] == row['after_sha256']
                for row in checks.values()), '启动配置、防火墙、网络或缓存没有恢复')
    require(before['files_sha256'] == after['files_sha256'] and before['modules'] == after['modules'] and
            before['firewall_sha256'] == after['firewall_sha256'], '原版配置摘要未恢复')
    require(after['files_sha256']['/boot/grub/grub.cfg'] == checks['grub.cfg']['after_sha256'] and
            after['firewall_sha256'] == checks['firewall']['after_sha256'], '恢复快照与配置检查不符')
    require(all(manifest[key] is False for key in ('full_ssi_accepted', 'concurrent_vcpus_verified',
                'cross_physical_verified', 'default_runtime_enabled', 'multivcpu_alignment_verified')),
            '交替执行实验被提升为完整准入')
    return results


def check(path):
    return check_manifest(json.loads(path.read_text()), path.parent)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    results = check(parser.parse_args().manifest)
    summary = {label: [{key: run[key] for key in ('mode', 'alignment', 'rate_passed', 'offset_passed', 'accepted')}
                       for run in runs] for label, runs in results.items()}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
