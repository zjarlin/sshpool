#!/usr/bin/env python3
"""从完整原生进程跟踪复核启动器混版本拒绝；不以汇总的零次执行替代证据。"""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re

VERSIONS = {
    3: '7ed4008cbe393138b82b7ec96a643347ea1a9e22ba05f927e943189b219d09fc',
    4: 'ea2e1852d1318fc9e92663be4bab6d1cf55978998ea16ade662cc8bc6639ad7d',
    5: 'f0804eac45a00ccdd1c826298e205cfcc4530fcaa14674cf52688c8be408cb98',
}
KERNEL = '7.1.0-rc3-sshpool-gvm-pf24'
GUEST = '41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f'
INITRAMFS = 'd2c92382133792c5355e29a94862d7dc1b5fbc678dcc7e19227d04b45052e9bb'
REASON = 'SSI runtime/image mismatch before commit; neither peer may execute'
SEALS = 'F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE'
spec = importlib.util.spec_from_file_location('boot', Path(__file__).with_name('check-ssh-boot.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def native_trace(raw, worker_sha256):
    rows = []
    for line in raw.splitlines():
        match = re.fullmatch(r'(\d+)\s+(\d+\.\d+)\s+(.+)', line)
        require(match, '原生跟踪缺失、截断或包含无法识别的行')
        rows.append((int(match[1]), float(match[2]), match[3]))
    require(rows, '缺少原生进程跟踪')
    root, began, _ = rows[0]
    created, seen, exited, pending, previous = {root}, set(), {}, {}, {}
    executions, descriptors, sealed, exit_calls = [], {}, set(), {}
    for pid, timestamp, body in rows:
        require(pid not in exited and timestamp >= previous.get(pid, began), '进程退出后仍有记录或时间倒退')
        previous[pid] = timestamp
        seen.add(pid)
        # 恢复未完成的原生系统调用，不能丢掉 exec 或 vfork 的前半行。
        if '<unfinished ...>' in body:
            require(pid not in pending, '重复的未完成系统调用')
            pending[pid] = body.split('<unfinished ...>')[0]
            continue
        resumed = re.fullmatch(r'<\.\.\. (\w+) resumed>(.*)', body)
        if resumed:
            require(pid in pending and pending[pid].startswith(resumed[1] + '('), '缺少系统调用入口')
            body = pending.pop(pid) + resumed[2]
        child = re.fullmatch(r'(?:vfork|fork|clone|clone3)\(.*\)\s+= ([1-9]\d*)', body)
        if child:
            require(int(child[1]) not in created, '重复创建进程')
            created.add(int(child[1]))
        if body.startswith(('execve(', 'execveat(')):
            execution = re.fullmatch(r'execve\(("(?:\\.|[^"\\])*"), (\[.*\]), .*\)\s+= (.+)', body)
            require(execution, '缺失完整 execve 参数或出现未知执行方式')
            path, arguments = ast.literal_eval(execution[1]), ast.literal_eval(execution[2])
            require(Path(path).name in ('python3', 'ps', 'ss'), '拒绝期间出现 QEMU 或其他程序执行')
            if execution[3] == '0':
                executions.append((pid, Path(path).name, arguments))
        require(not re.match(r'ioctl\(-?\d+,\s*(?:KVM_|0x[0-9a-f]*ae[0-9a-f]{2}\b|'
                             r'_IOC\([^,\n]+,\s*0xae\b)', body, re.IGNORECASE),
                '准入拒绝期间触达 KVM')
        memfd = re.fullmatch(r'memfd_create\("sshpool-ssi-(\w+)", MFD_CLOEXEC\|MFD_ALLOW_SEALING\) = (\d+)', body)
        if memfd:
            require(pid == root and memfd[1] not in descriptors, '镜像 memfd 身份重复或归属错误')
            descriptors[memfd[1]] = int(memfd[2])
        add = re.fullmatch(r'fcntl\((\d+), F_ADD_SEALS, ' + re.escape(SEALS) + r'\) = 0', body)
        if add:
            require(pid == root and int(add[1]) in descriptors.values(), '封存了未知输入')
            sealed.add(int(add[1]))
        get = re.fullmatch(r'fcntl\((\d+), F_GET_SEALS\) = 0xf \(seals ' + re.escape(SEALS) + r'\)', body)
        if get:
            require(pid == root and int(get[1]) in sealed, '缺少封条写入')
            sealed.add(('confirmed', int(get[1])))
        ended = re.fullmatch(r'\+\+\+ exited with (\d+) \+\+\+', body)
        if ended:
            exited[pid] = int(ended[1])
        exit_call = re.fullmatch(r'exit_group\((\d+)\)\s+= \?', body)
        if exit_call:
            exit_calls[pid] = int(exit_call[1])
    require(not pending and created == seen == set(exited), '原生进程创建或退出记录不完整')
    require(exit_calls == exited, '缺少原生进程退出调用')
    require(exited[root] == 1 and all(code == 0 for pid, code in exited.items() if pid != root),
            '不是 helper 自行拒绝退出')
    require(len(executions) == 3 and len({pid for pid, _, _ in executions}) == 3 and
            [name for _, name, _ in executions] == ['python3', 'ps', 'ss'],
            '执行链不完整或含额外程序')
    pid, _, args = executions[0]
    require(pid == root and len(args) == 4 and args[:3] == ['python3', '-u', '-c'], '没有执行实际 helper')
    require(hashlib.sha256(args[3].encode('latin1')).hexdigest() == worker_sha256,
            '原生执行的 helper 与报告不符')
    require(set(descriptors) == {'qemu', 'guest_kernel', 'initramfs'} and len(set(descriptors.values())) == 3 and
            all(('confirmed', fd) in sealed for fd in descriptors.values()), '三份实际输入没有全部封存')
    require(0 < rows[-1][1] - began < 35, '拒绝退出超过期限')
    return {'qemu_exec_calls': 0, 'kvm_calls': 0, 'sealed_inputs': 3, 'processes': len(created)}


def check_mixed(row):
    report, plan = row['report'], row['plan']
    source = Path(__file__).resolve().parents[2] / 'src/ssi_launch_worker.py'
    require(hashlib.sha256(source.read_bytes()).hexdigest() == report['worker_sha256'],
            '证据不是当前 helper 的运行结果')
    require(row['versions'] in ([3, 5], [5, 3], [4, 5], [5, 4]), '混版本矩阵无效')
    require(row['cli_exit'] == 2 and report['admission_passed'] is False and
            report['commit_sent'] == [False, False] and REASON in report['errors'], '启动器没有明确拒绝准入')
    require(report['full_ssi_accepted'] is False and len(report['nodes']) == len(row['records']) == 2,
            '节点数或验收范围无效')
    require(plan['require_kernel'] == KERNEL and len(plan['peers']) == 2, '计划边界不符')
    require(plan['peers'][0]['machine_id_sha256'] != plan['peers'][1]['machine_id_sha256'], '重复节点身份')
    require(report['nodes'][0]['prepared']['token'] != report['nodes'][1]['prepared']['token'], '重复准备 token')
    results = []
    for node, record in enumerate(row['records']):
        outcome, peer = report['nodes'][node], plan['peers'][node]
        prep, finish = outcome['prepared'], outcome['finished']
        require(prep['node'] == node and prep['run_id'] == report['run_id'] and
                prep['plan_sha256'] == report['plan_sha256'] and prep['kernel'] == KERNEL and
                prep['machine_id_sha256'] == peer['machine_id_sha256'], '准备报告身份或计划不符')
        for key, digest in [('qemu', VERSIONS[row['versions'][node]]), ('guest_kernel', GUEST), ('initramfs', INITRAMFS)]:
            image = prep['images'][key]
            require(peer[key]['sha256'] == image['sha256'] == digest and image['seals'] == 15 and
                    0 < image['bytes'] <= 256 * 1024 * 1024, '实际封存镜像不符')
        require(outcome['started'] is None and outcome['ssh_exit'] == 1 and outcome['transport_error'] is None,
                '节点执行过客体或未正常拒绝退出')
        require(finish['node'] == node and finish['run_id'] == report['run_id'] and
                finish['qemu_started'] is False and finish['qemu_exit'] is None and
                finish['forced_cleanup'] == [] and finish['errors'] == ['controller rejected preparation: ' + REASON],
                '拒绝结果不完整或需要强制清理')
        require(0 < finish['started_ns'] < finish['finished_ns'] < finish['started_ns'] + 35_000_000_000,
                '缺少有效拒绝时间边界')
        events = [json.loads(line) for line in record['control'].splitlines()]
        require([event['event'] for event in events] == ['prepared', 'finished'] and
                events[0]['data'] == prep and events[1]['data'] == finish and
                all(event['schema'] == 1 and event['node'] == node and event['run_id'] == report['run_id'] for event in events),
                '原始控制记录与汇总不符')
        remote = dict(record['remote'])
        remote_events = remote.pop('events')
        require(remote == finish and [event['event'] for event in remote_events] == ['prepared'] and
                remote_events[0]['data'] == prep,
                '远端记录缺失或不一致')
        require(record['remaining'] == [] and record['host_log'].strip(), '缺少清理或宿主日志')
        boot.check_errors(record['host_log'])
        for key in ('trace', 'control', 'host_log'):
            require(hashlib.sha256(record[key].encode()).hexdigest() == record[key + '_sha256'], '日志摘要不符')
        results.append(native_trace(record['trace'], report['worker_sha256']))
    return {'nodes': results, 'both_refused_before_guest': True, 'full_ssi_accepted': False}


def check_matrix(evidence):
    rows = evidence['mixed_runs']
    require(len(rows) == 4 and {tuple(row['versions']) for row in rows} ==
            {(3, 5), (5, 3), (4, 5), (5, 4)}, '混版本矩阵缺失或重复')
    require(evidence['full_ssi_accepted'] is False, '启动准入不能代表完整 SSI 验收')
    return [check_mixed(row) for row in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    try:
        evidence = json.loads(args.record.read_text())
        result = check_matrix(evidence) if 'mixed_runs' in evidence else check_mixed(evidence)
        print(json.dumps(result, ensure_ascii=False))
    except (ValueError, KeyError, TypeError, IndexError, SyntaxError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
