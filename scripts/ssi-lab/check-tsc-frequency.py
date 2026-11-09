#!/usr/bin/env python3
"""重算 RDTSC 与 pvclock 的宿主包络，设置成功不等于实际频率已缩放。"""
import argparse
from fractions import Fraction
import gzip
import hashlib
import json
from pathlib import Path
import re


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def integer(value, lower, upper, name):
    require(type(value) is int and lower <= value <= upper, '非法 ' + name)
    return value


def pvclock(sample):
    record = sample['pvclock']
    version = integer(record['version'], 2, 2**32 - 1, 'pvclock version')
    require(version % 2 == 0, 'pvclock 奇数版本')
    base = integer(record['tsc'], 0, 2**64 - 1, 'pvclock tsc')
    system = integer(record['system_time'], 1, 2**64 - 1, 'pvclock system_time')
    multiplier = integer(record['multiplier'], 1, 2**32 - 1, 'pvclock multiplier')
    shift = integer(record['shift'], -31, 31, 'pvclock shift')
    integer(record['flags'], 0, 255, 'pvclock flags')
    delta = sample['guest_tsc'] - base
    require(delta >= 0, '采样 TSC 早于 pvclock 基准')
    delta = delta << shift if shift >= 0 else delta >> -shift
    return system + ((delta * multiplier) >> 32)


def bounds(first, last, delta, scale=1):
    low = last['host_before_ns'] - first['host_after_ns']
    high = last['host_after_ns'] - first['host_before_ns']
    require(0 < low <= high and delta > 0, '区间倒退或重叠')
    return Fraction(delta * scale, high), Fraction(delta * scale, low)


def overlaps(interval, center, tolerance):
    return interval[0] <= center + tolerance and interval[1] >= center - tolerance


def inspect_run(run, guest_hex):
    require(run['exit'] == 0 and run['stderr'] == '', '探针没有正常退出')
    rows = [json.loads(line) for line in run['stdout'].splitlines()]
    require(len(rows) >= 3, '缺少输出')
    code, config = rows[:2]
    require(code == {'op': 'guest_code', 'gpa': 4096, 'bytes': len(bytes.fromhex(guest_hex)),
                     'hex': guest_hex}, '客体指令与构建产物不一致')
    require(config['op'] == 'configuration' and config['kernel'] == '6.8.0-147-generic', '配置内核不符')
    mode = run['mode']
    require(config['mode'] == mode and mode in ('native', 'faster', 'slower'), '模式不符')
    native = integer(config['native_khz'], 1, 2**31 - 1, 'native_khz')
    requested = {'native': native, 'faster': native * 6 // 5, 'slower': native * 4 // 5}[mode]
    require(config['requested_khz'] == config['reported_khz'] == requested, '频率元数据不符')
    require(config['control'] == 0, '本证据只覆盖不支持硬件缩放的节点')
    require(config['vcpu_host_cpu'] >= 0 and config['observer_host_cpu'] >= 0 and
            config['vcpu_host_cpu'] != config['observer_host_cpu'], '观测线程与 vCPU 未分开')
    rejected = mode == 'slower'
    require(config['set_result'] == (-1 if rejected else 0) and
            config['set_errno'] == (22 if rejected else 0), 'SET 返回与本实验结果不符')
    close = {'op': 'closed', 'run_calls': 0 if rejected else 1, 'fds_closed': 3, 'rejected': rejected}
    require(rows[-1] == close, '关闭记录缺失或执行次数不符')
    if rejected:
        require(len(rows) == 3, '设置失败后仍执行或产生采样')
        return {'mode': mode, 'requested_khz': requested, 'rejected_before_run': True}
    require([row['op'] for row in rows] == ['guest_code', 'configuration'] +
            ['sample'] * 12 + ['run_done', 'closed'], '采样或生命周期顺序不符')
    done = rows[-2]
    require(done['result'] == done['errno'] == 0 and done['exit_reason'] == 5 and
            done['rip'] == 4096 + code['bytes'], '未在预期 HLT 正常退出')
    require(done['reported_khz_after_run'] == requested, '运行后报告频率变化')
    samples = rows[2:-2]
    times = []
    for index, sample in enumerate(samples):
        require(sample['index'] == index, '样本重复或错序')
        for key in ('host_before_ns', 'host_after_ns', 'guest_tsc'):
            integer(sample[key], 1, 2**64 - 1, key)
        width = sample['host_after_ns'] - sample['host_before_ns']
        # 首次进入允许较大的初始化窗口；其余上限预先固定，不用结果反推。
        require(0 <= width <= (100000000 if index == 0 else 10000000), '宿主包络过宽或倒退')
        times.append(pvclock(sample))
        if index:
            previous = samples[index - 1]
            require(90000000 <= sample['host_before_ns'] - previous['host_after_ns'] <= 500000000,
                    '采样间隔异常')
            require(sample['guest_tsc'] > previous['guest_tsc'] and times[-1] > times[-2], '客体时钟倒退')
    # 排除首次进入，固定使用 1→11；逐段也验收，避免平均值掩盖跳变。
    intervals = [(index - 1, index) for index in range(2, 12)] + [(1, 11)]
    for left, right in intervals:
        tsc = bounds(samples[left], samples[right], samples[right]['guest_tsc'] - samples[left]['guest_tsc'], 1000000)
        pv = bounds(samples[left], samples[right], times[right] - times[left])
        require(native * Fraction(999, 1000) <= tsc[0] <= tsc[1] <= native * Fraction(1001, 1000),
                '实测 TSC 包络不在原生频率千分之一容差内')
        require(Fraction(999, 1000) <= pv[0] <= pv[1] <= Fraction(1001, 1000),
                'pvclock 速率包络不在千分之一容差内')
        if mode == 'faster':
            require(not overlaps(tsc, requested, Fraction(requested, 1000)), '请求频率未被实际读数排除')
    require(done['clock'] >= times[-1], '结束 KVM 时钟早于末次 pvclock')
    return {'mode': mode, 'requested_khz': requested, 'reported_khz_after_run': done['reported_khz_after_run'],
            'sample_pair': [1, 11], 'tsc_khz_bounds': [float(x) for x in tsc],
            'pvclock_rate_bounds': [float(x) for x in pv], 'requested_rate_observed': mode == 'native',
            'max_bracket_ns': max(x['host_after_ns'] - x['host_before_ns'] for x in samples[1:])}


def inspect_capture(data, build, guest_hex):
    require(data['schema'] == 1, '未知采集协议')
    for name in ('source_sha256', 'capture_sha256', 'binary_sha256'):
        require(data[name] == build[name], '采集或构建源码哈希不符')
    require(data['before'] == data['after'], '节点身份配置或清理状态变化')
    host = data['before']
    require(host['kernel'] == '6.8.0-147-generic' and host['architecture'] == 'x86_64' and
            host['clocksource'] == 'tsc', '宿主计时前提不符')
    require(host['processes'] == host['kvm_fds'] == [], '实验进程或 KVM fd 没有清理')
    require(len(host['allowed_cpus']) >= 2, 'CPU 配额不足')
    require(set(host['identity_sha256']) == {'machine', 'dmi', 'boot'}, '身份不完整')
    digests = list(host['identity_sha256'].values()) + list(host['files_sha256'].values()) + [host['firewall_sha256']]
    require(all(re.fullmatch('[0-9a-f]{64}', value) for value in digests), '宿主哈希无效')
    require({'/etc/fstab', '/etc/default/grub', '/boot/grub/grub.cfg', '/boot/grub/grubenv',
             '/boot/vmlinuz-6.8.0-147-generic', '/boot/config-6.8.0-147-generic'} <= set(host['files_sha256']),
            '缺少启动配置或内核哈希')
    require(set(host['modules']) == {'kvm', 'kvm_intel'}, 'KVM 模块来源缺失')
    for module in host['modules'].values():
        require(re.fullmatch('[0-9a-f]{64}', module['sha256']) and module['srcversion'] and
                module['vermagic'].startswith(host['kernel'] + ' '), '模块哈希或版本不符')
    require(data['finished_unix_ns'] > data['started_unix_ns'], '采集生命周期倒退')
    require([run['mode'] for run in data['runs']] == ['native', 'faster', 'slower'], '模式矩阵不完整')
    results = []
    native_frequencies = set()
    for run in data['runs']:
        config = json.loads(run['stdout'].splitlines()[1])
        native_frequencies.add(config['native_khz'])
        require({config['vcpu_host_cpu'], config['observer_host_cpu']} <= set(host['allowed_cpus']), 'CPU 不在许可集内')
        require(0 < run['elapsed_ns'] < 15000000000, '运行期限不符')
        results.append(inspect_run(run, guest_hex))
    require(len(native_frequencies) == 1, '同一节点三次运行的原生频率不一致')
    return results


def read_artifact(directory, record):
    raw = (directory / record['file']).read_bytes()
    require(len(raw) == record['bytes'] and sha(raw) == record['sha256'], '归档哈希或大小不符')
    unpacked = gzip.decompress(raw)
    require(sha(unpacked) == record['raw_sha256'], '原始内容哈希不符')
    return unpacked


def inspect_node(directory, node, build, guest_hex):
    capture = json.loads(read_artifact(directory, node['capture']))
    analysis = inspect_capture(capture, build, guest_hex)
    require(analysis == node['analysis'], '保存的分析与重算结果不符')
    require(node['runner_exit'] == 0, '采集器失败')
    require(re.fullmatch(r'\[\s*\d+\.\d+\] kvm: user requested TSC rate below hardware speed\n',
                         node['kernel_log_delta']) is not None, '内核日志与本轮降频拒绝不符')
    return capture, analysis


def check_candidate(path, manifest):
    # 新候选引用已冻结的双节点基线，历史失败、源码和两端记录仍完整重放。
    reference = manifest['baseline']
    baseline_path = path.parent / reference['file']
    raw = baseline_path.read_bytes()
    require(sha(raw) == reference['sha256'], '基线清单哈希不符')
    baseline = json.loads(raw)
    require(baseline['schema'] == 1, '候选必须引用原始双节点基线')
    check(baseline_path)
    original = next(node for node in baseline['nodes'] if node['label'] == reference['node'])
    original_capture = json.loads(read_artifact(path.parent, original['capture']))
    capture, analysis = inspect_node(path.parent, manifest['candidate'], baseline['build'], baseline['guest_hex'])
    originals = {node['label'] for node in baseline['nodes']}
    require(manifest['candidate']['label'] not in originals, '候选标签与原节点混淆')

    audits = manifest['identity_audits']
    before, after = audits['before_reboot'], audits['after_reboot']
    stable = ('machine', 'dbus_machine', 'dmi', 'ssh_host_key', 'hostname')
    require(re.fullmatch('[0-9a-f]{64}', audits['old_machine_sha256']), '旧身份摘要无效')
    for row in (before, after):
        require(all(re.fullmatch('[0-9a-f]{64}', row[key]) for key in (*stable, 'boot', 'private_raw_sha256')),
                '身份审计摘要无效')
        require(row['machine'] == row['dbus_machine'] != audits['old_machine_sha256'], '克隆身份未更新')
    require(all(before[key] == after[key] for key in stable), '重启后身份未持久化')
    require(before['boot'] != after['boot'], '缺少独立重启观测')
    identity = capture['before']['identity_sha256']
    require(all(after[key] == identity[key] for key in ('machine', 'dmi', 'boot')), '身份审计与采集不对应')
    require(manifest['cleanup']['snapshot'] == capture['after'] and
            manifest['cleanup']['before_after_equal'] is True, '清理后的节点状态不一致')
    require(manifest['cleanup']['temporary_directory_removed'] is True, '临时目录未清理')

    run = manifest['preflight']
    report = run['report']
    require(run['exit'] == 2 and run['stderr'] == '', '预检没有按预期拒绝')
    require(report['schema'] == 1 and report['scope'] == 'native-tsc-preflight-only', '预检范围不符')
    require(len(report['peers']) == 2, '预检缺少节点')
    captures = (original_capture, capture)
    labels = (reference['node'], manifest['candidate']['label'])
    frequencies, identities = set(), set()
    for peer, measured, label in zip(report['peers'], captures, labels):
        probe = peer['probe']
        require(peer['ssh'] == label and peer['error'] is None, '预检节点或错误不符')
        machine = measured['before']['identity_sha256']['machine']
        require(probe['machine_id_sha256'] == machine and machine not in identities, '预检与实测身份不对应或重复')
        identities.add(machine)
        native = json.loads(measured['runs'][0]['stdout'].splitlines()[1])['native_khz']
        require([cpu['index'] for cpu in probe['vcpus']] == [0, 1] and
                all(cpu['tsc_khz'] == native and cpu['offset_supported'] is True for cpu in probe['vcpus']),
                '预检频率与实测原生频率不符')
        require(probe['api_version'] == 12 and probe['get_tsc_khz'] == 1 and probe['tsc_control'] == 0 and
                probe['tsc_adjust'] is True and probe['adjust_clock'] & 14 == 14 and
                probe['closed_fds'] == 4 and probe['errors'] == [], '预检接口或清理不符')
        frequencies.add(native)
    require(len(frequencies) == 2, '跨物理候选未保留不同原生频率')
    expected = f'原生 TSC 频率不一致或缺失: {sorted(frequencies)} kHz；当前运行时只支持偏移校准，不支持频率转换'
    require(report['blockers'] == [expected], '不同频率拒绝原因不符')
    for key in ('native_tsc_precheck_passed', 'physical_topology_verified', 'running_clock_verified', 'full_ssi_accepted'):
        require(report[key] is False, '空 VM 预检被提升为运行时验收')
    require(manifest['full_ssi_accepted'] is False and manifest['cross_physical_verified'] is False,
            '独立节点测量不证明跨物理执行或完整 SSI')
    return {manifest['candidate']['label']: analysis}


def check(path):
    manifest = json.loads(path.read_text())
    if manifest['schema'] == 2:
        return check_candidate(path, manifest)
    require(manifest['schema'] == 1, '未知清单协议')
    directory = path.parent
    sources = json.loads(read_artifact(directory, manifest['sources']))
    build = manifest['build']
    for filename, key in [('probe-tsc-frequency.c', 'source_sha256'), ('capture-tsc-frequency.py', 'capture_sha256')]:
        raw = sources[filename].encode()
        require(sha(raw) == build[key], '归档源码与构建不符')
        require(raw == Path(__file__).with_name(filename).read_bytes(), '当前探针与采集源码不符')
    require(sha(sources['ubuntu-6.8.0-147-x86.c'].encode()) == manifest['kernel_source']['sha256'], '内核源码哈希不符')
    instructions = re.findall(r'^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2} )+)', sources['guest-disassembly-v3.txt'], re.M)
    require(''.join(instructions).replace(' ', '') == manifest['guest_hex'], '反汇编与实际客体指令不符')
    require(len(manifest['nodes']) == 2, '双节点记录不完整')
    identities, results = set(), {}
    for node in manifest['nodes']:
        capture, analysis = inspect_node(directory, node, build, manifest['guest_hex'])
        identity = capture['before']['identity_sha256']['machine']
        require(identity not in identities, '节点身份重复')
        identities.add(identity)
        results[node['label']] = analysis
    for item in manifest['diagnostics']:
        # 早期诊断只有原始输出，没有完整前后状态，不能升级为正式验收。
        read_artifact(directory, item['capture'])
    require(len(manifest['failed_captures']) == 2, '首次采集失败记录缺失')
    for item in manifest['failed_captures']:
        failure = json.loads(read_artifact(directory, item['capture']))
        capture = failure['capture']
        require(failure['exit'] == 1 and 'PermissionError: [Errno 13]' in failure['stderr'] and
                capture['runs'] == [] and capture['before'] == capture['after'], '启动前失败被掩盖')
        require(capture['after']['processes'] == capture['after']['kvm_fds'] == [], '失败后未清理')
    require(manifest['full_ssi_accepted'] is False and manifest['cross_physical_verified'] is False,
            '本实验没有完整 SSI 或跨物理执行证据')
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    print(json.dumps(check(parser.parse_args().manifest), ensure_ascii=False, indent=2))
