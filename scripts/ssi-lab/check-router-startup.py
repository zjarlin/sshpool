#!/usr/bin/env python3
"""核对原生启动跟踪，区分新节点拒绝与整个混版本客体从未执行。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('boot', Path(__file__).with_name('check-ssh-boot.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
CAPTURE = '0d5b6aeb4cd29bb6f1f1e47c3bb0bb26e6756d0a800d0e7269c29574c675f9c8'
CANDIDATE = 'f0804eac45a00ccdd1c826298e205cfcc4530fcaa14674cf52688c8be408cb98'
PREVIOUS = '0ba2acb72d0c0fa57843adfda1a32bdbab01c5516d6da7d84059e3c0495c697e'
LEGACY = {3: '7ed4008cbe393138b82b7ec96a643347ea1a9e22ba05f927e943189b219d09fc',
          4: 'ea2e1852d1318fc9e92663be4bab6d1cf55978998ea16ade662cc8bc6639ad7d'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def native_trace(record):
    text = record['ioctl']
    require(text.strip(), '缺少原生 ioctl 跟踪，不能把空日志当成零次执行')
    entries = []
    for line in text.splitlines():
        match = re.fullmatch(r'(\d+)\s+(\d+\.\d+)\s+(.+)', line)
        require(match is not None, '原生跟踪截断或格式不符')
        entries.append((int(match[1]), float(match[2]), match[3]))
    root, begin, first = entries[0]
    execution = re.fullmatch(r'execve\(("(?:\\.|[^"])*"), (\[.*\]), .*\) = 0', first)
    require(execution is not None and json.loads(execution[1]) == record['qemu_binary'] and
            json.loads(execution[2]) == [record['qemu_binary']] + record['qemu_arguments'],
            '缺少与参数一致的原生 QEMU execve')
    require(sum('execve(' in body for _, _, body in entries) == 1, '跟踪包含其他运行实例')
    require(any(pid == root and re.fullmatch(r'ioctl\(\d+, KVM_GET_API_VERSION, 0\) = 12', body)
                for pid, _, body in entries), '缺少原生 KVM API 检查')
    require(any(pid == root and re.fullmatch(r'ioctl\(\d+, KVM_CREATE_VM, 0\) = [1-9]\d*', body)
                for pid, _, body in entries), '没有创建真实 KVM VM')
    created, seen, ended = {root}, set(), {}
    pending_clones = {}
    previous_time = {}
    runs = 0
    for pid, timestamp, body in entries:
        require(pid not in ended and timestamp >= previous_time.get(pid, begin), '退出后仍有记录或线程时间倒退')
        previous_time[pid] = timestamp
        seen.add(pid)
        if re.match(r'clone3?\(', body) and '<unfinished ...>' in body:
            require(pid not in pending_clones, '重复的未完成线程创建')
            pending_clones[pid] = body.split('<unfinished ...>')[0]
        resumed = re.match(r'<\.\.\. (clone3?) resumed>(.*)', body)
        if resumed:
            require(pid in pending_clones, '缺失线程创建入口')
            body = pending_clones.pop(pid) + resumed[2]
        clone = re.fullmatch(r'clone3?\(.*\)\s+= ([1-9]\d*)', body)
        if clone:
            child = int(clone[1])
            require(child not in created, '线程身份重复')
            created.add(child)
        # 未完成的 KVM_RUN 也算执行；只计入口，不能再计 resumed 行。
        if re.search(r'\bioctl\(\d+, (?:KVM_RUN\b|0xae80\b|'
                     r'_IOC\(_IOC_NONE, 0xae, 0x80, 0\))', body, re.IGNORECASE):
            runs += 1
        exit_match = re.fullmatch(r'\+\+\+ exited with ([01]) \+\+\+', body)
        if exit_match:
            ended[pid] = int(exit_match[1])
    require(not pending_clones and created == seen == set(ended), '线程创建或完整退出记录缺失')
    require(type(record['exit']) is int and ended[root] == record['exit'] == 1 and
            any('exit_group(1' in body for _, _, body in entries),
            '不是原生失败退出，不能用外部清理替代')
    require(entries[-1][1] - begin < 35 and type(record['kvm_run_calls']) is int and
            record['kvm_run_calls'] == runs, '执行计数或原生退出期限不符')
    return runs


def arguments(record):
    args = record['qemu_arguments']
    flags = ['-nodefaults', '-no-reboot']
    values = {'-name': f"sshpool-router-startup-{record['node']},debug-threads=on",
              '-machine': 'pc,accel=kvm,kernel-irqchip=split',
              '-cpu': 'qemu64,-x2apic,+tsc-adjust,enforce',
              '-smp': '4,sockets=2,cores=2,threads=1', '-m': '256',
              '-display': 'none', '-serial': 'stdio', '-monitor': 'none',
              '-append': 'console=ttyS0 rdinit=/init nokaslr panic=10 nox2apic'}
    paths = ['-L', '-kernel', '-initrd']
    options = {}
    index = 0
    while index < len(args):
        name = args[index]
        require(name not in options and name in flags + list(values) + paths + ['-local-cpu'],
                '启动参数重复或包含暂停/其他未验证选项')
        options[name] = True if name in flags else args[index + 1]
        index += 1 if name in flags else 2
    require(set(options) == set(flags + list(values) + paths + ['-local-cpu']), '启动参数缺失')
    require(all(options[key] == value for key, value in values.items()), '客体配置不符')
    require(all(isinstance(options[key], str) and options[key] for key in paths), '客体路径缺失')
    require(re.fullmatch(rf"cpus=2,start={record['node'] * 2},iplist=\S+ \S+", options['-local-cpu']),
            '节点拓扑参数不符')


def check_mixed(row, candidate=CANDIDATE):
    run, records = row['run'], row['records']
    versions = run['versions']
    require(versions in ([5, 3], [3, 5], [5, 4], [4, 5]), '混配矩阵不符')
    expected = [candidate if version == 5 else LEGACY[version] for version in versions]
    require(run['runtime_sha256'] == expected and run['capture_sha256'] == CAPTURE, '运行时或采集器哈希不符')
    require(run['capture_exits'] == [0, 0] and all(type(code) is int for code in run['capture_exits']) and
            run['errors'] == [] and len(records) == 2,
            '采集没有完整结束')
    require(len(row['host_logs']) == 2 and all(not run[f'node{n}_remaining'] for n in (0, 1)),
            '宿主日志缺失或实验进程残留')
    counts, elapsed = [], []
    for node, record in enumerate(records):
        require(record['schema'] == 1 and record['node'] == node and
                record['kernel'] == '7.1.0-rc3-sshpool-gvm-pf24' and
                record['qemu_sha256'] == expected[node] and record['capture_sha256'] == CAPTURE,
                '采集身份不符')
        require(record['guest_kernel_sha256'] == '41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f' and
                record['initramfs_sha256'] == 'd2c92382133792c5355e29a94862d7dc1b5fbc678dcc7e19227d04b45052e9bb',
                '客体镜像不符')
        require(record['errors'] == [] and record['forced_cleanup'] == [], '强制清理或采集错误不能算协议退出')
        times = [record[key] for key in ('started_ns', 'exit_observed_ns', 'finished_ns')]
        require(all(type(t) is int and t > 0 for t in times) and times == sorted(set(times)) and
                0 < times[1] - times[0] < 35_000_000_000, '退出观察缺失或超过期限')
        for name in ('stdout', 'stderr', 'ioctl'):
            require(hashlib.sha256(record[name].encode()).hexdigest() == record[name + '_sha256'],
                    '日志摘要不符')
        arguments(record)
        counts.append(native_trace(record))
        elapsed.append(times[1] - times[0])
        require('SSI_ROUTER_READY' not in record['stderr'], '版本拒绝后仍发布路由就绪')
        if versions[node] == 5:
            require(counts[-1] == 0 and 'SSI router startup protocol error:' in record['stderr'],
                    '新节点没有在执行客体前明确拒绝')
        require(row['host_logs'][node].strip(), '缺少本轮宿主日志')
        boot.check_errors(row['host_logs'][node])
    return {'kvm_run_calls': counts, 'exit_elapsed_ns': elapsed,
            'candidate_refused_before_guest': True, 'both_refused_before_guest': counts == [0, 0],
            'full_ssi_accepted': False}


def require_both_before_guest(row):
    result = check_mixed(row)
    require(result['both_refused_before_guest'], '旧节点已经执行客体，完整场景仍未通过')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--require-both-before-guest', action='store_true')
    args = parser.parse_args()
    try:
        check = require_both_before_guest if args.require_both_before_guest else check_mixed
        print(json.dumps(check(json.loads(args.record.read_text())), ensure_ascii=False))
    except (ValueError, KeyError, IndexError, TypeError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
