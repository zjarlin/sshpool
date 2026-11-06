#!/usr/bin/env python3
"""把双端 QMP、时钟屏障和同一客体进程的读数关联起来，检查有限恢复实验。"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct

spec = importlib.util.spec_from_file_location('clock', Path(__file__).with_name('check-clock.py'))
clock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clock)
spec = importlib.util.spec_from_file_location('boot', Path(__file__).with_name('check-ssh-boot.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
RUNTIME = 'ea2e1852d1318fc9e92663be4bab6d1cf55978998ea16ade662cc8bc6639ad7d'
CAPTURE = 'e14478bf6d35682e41f1a4fc0df90c8b4eef66fe389ac7ada0af93a10d5edf20'
PREPARED = re.compile(r'SSI_CLOCK_PREPARED epoch=(\d+) clock=(\d+) tsc=(\d+) clock_floor=(\d+) tsc_floor=(\d+)')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reply(entry):
    values = [value for value in entry['responses'] if 'id' in value]
    require(len(values) == 1 and values[0]['id'] == entry['request']['id'] and
            'return' in values[0] and 'error' not in values[0], '缺少对应的成功 QMP 回复')
    return values[0]['return']


def snapshots(record, cycles, failure=None):
    entries = record['qmp']
    require([item['request']['id'] for item in entries] == list(range(len(entries))), 'QMP 序号不连续')
    phases = [('ready', 'running')]
    if failure:
        phases.append(('paused_1', 'paused'))
        if failure == 'reset':
            phases.append(('after_reset', 'prelaunch'))
    else:
        for cycle in range(1, cycles + 1):
            phases.extend([(f'paused_{cycle}', 'paused'), (f'running_{cycle}', 'running')])
        phases.append(('before_quit', 'running'))
    require(len(record['snapshots']) == len(phases), '恢复快照数量不符')
    previous_end = 0
    previous_time = 0
    for snapshot, (phase, state) in zip(record['snapshots'], phases):
        require(snapshot['phase'] == phase and snapshot['time_ns'] > previous_time, '快照顺序不符')
        previous_time = snapshot['time_ns']
        start, end = snapshot['qmp_start'], snapshot['qmp_end']
        require(previous_end <= start < end <= len(entries) and end - start == 4, '快照没有完整原始回复')
        previous_end = end
        fields = ('status', 'blocks', 'realized', 'queue')
        names = ('query-status', 'query-block', 'qom-get', 'x-query-virtio-queue-status')
        for entry, field, name in zip(entries[start:end], fields, names):
            require(entry['request']['execute'] == name and reply(entry) == snapshot[field], '快照与 QMP 不符')
        require(snapshot['status'] == {'status': state, 'running': state == 'running'}, '两端未处于要求的状态')
        require(snapshot['pins'] == [], '该实验没有原生页引用查询')


def protocol(stderr):
    lines = [line for line in stderr.splitlines() if line.startswith('SSI_CLOCK_')]
    require(lines.count('SSI_CLOCK_COLD_START epoch=1') == 1, '冷启动标记缺失或重复')
    stages = [line for line in lines if line.startswith(('SSI_CLOCK_PREPARE ', 'SSI_CLOCK_RECEIVE ',
              'SSI_CLOCK_BARRIER ', 'SSI_CLOCK_PREPARED ', 'SSI_CLOCK_RELEASE '))]
    require(len(stages) == 7 * 7, '恢复协议阶段缺失或重复')
    for index, epoch in enumerate(range(2, 9)):
        prepare, receive1, barrier1, prepared, receive2, barrier2, release = stages[index * 7:(index + 1) * 7]
        require(prepare == f'SSI_CLOCK_PREPARE epoch={epoch} state=paused', '在暂停之外准备或代际不连续')
        for value, expected in ((receive1, f'SSI_CLOCK_RECEIVE epoch={epoch} phase=1'),
                                (barrier1, f'SSI_CLOCK_BARRIER epoch={epoch} phase=1'),
                                (receive2, f'SSI_CLOCK_RECEIVE epoch={epoch} phase=2'),
                                (barrier2, f'SSI_CLOCK_BARRIER epoch={epoch} phase=2'),
                                (release, f'SSI_CLOCK_RELEASE epoch={epoch}')):
            require(value == expected, '阶段错序、重复或使用旧代际')
        match = PREPARED.fullmatch(prepared)
        require(match is not None, '缺少时钟准备读回')
        generation, now, tsc, floor, tsc_floor = map(int, match.groups())
        require(generation == epoch and floor > 0 and tsc_floor > 0 and now >= floor and tsc >= tsc_floor,
                '准备时钟低于双端下界或代际错误')


def check(row):
    run, records = row['run'], row['records']
    require(run['variant'] == 'candidate' and run['fault'] == 'none', '只接受无故障的完整恢复实验')
    require(run['runtime_sha256'] == RUNTIME and run['capture_sha256'] == CAPTURE, '运行时或采集器不符')
    require(run['errors'] == [] and run['capture_exits'] == [0, 0] and run['clock_exit'] == 0,
            '协调器或客体进程失败')
    require(run['early_cont_reply'] == [False] * 7, '出现未等到对端的提前恢复回复')
    require(run['shutdown_method'] == 'guest-poweroff' and run['shutdown_ssh_exit'] in (0, 255),
            '不是指定的客体关机路径')
    require(run['physical_nodes'] in ([0, 1], [1, 0]), '实验节点映射不符')
    require(len(records) == 2 and all(not run[f'node{n}_remaining'] for n in (0, 1)), '有实验进程残留')
    clock.validate(row['clock_log'], max_timer_ns=250_000_000, pause_rounds=True)
    # watchdog 跳过检查已作为独立失败保留；这里只核对正常的唯一启动与 SSH 就绪记录。
    boot.check_errors(records[0]['serial'])
    kernels = re.findall(r'Linux version (\S+)', records[0]['serial'])
    ready = re.findall(r'SSH_GUEST_READY kernel=(\S+) cpus=(\d+)', records[0]['serial'])
    require(len(kernels) == 1 and ready == [(kernels[0], '4')], '缺少唯一可关联的客体启动记录')
    require(records[0]['serial'].count('Server listening on 0.0.0.0 port 22.') == 1,
            '缺少唯一的 SSH 监听记录')
    require('Power down' in records[0]['serial'], '没有实际客体关机标记')
    timer_max = max(map(int, re.findall(r'elapsed_ns=(\d+)', row['clock_log'])))
    for node, record in enumerate(records):
        require(record['node'] == node and record['qemu_sha256'] == RUNTIME and
                record['capture_sha256'] == CAPTURE and record['kernel'] == '7.1.0-rc3-sshpool-gvm-pf24',
                '节点身份或内核不符')
        require(record['qemu_exit'] == 0 and record['forced_cleanup'] is False and record['errors'] == [],
                '把强制清理或错误退出算作成功')
        require(record['pin_query'] == 'none' and record['injected_errno'] == 0, '混入引用查询或磁盘错误')
        snapshots(record, 7)
        names = [entry['request']['execute'] for entry in record['qmp']]
        queries = {'query-status', 'query-block', 'qom-get', 'x-query-virtio-queue-status'}
        require([name for name in names if name not in queries] ==
                ['qmp_capabilities'] + ['stop', 'cont'] * 7,
                '未按完整的七轮暂停恢复执行')
        for entry in record['qmp']:
            reply(entry)
        events = [value['event'] for entry in record['qmp'] for value in entry['responses'] if 'event' in value]
        require(events.count('STOP') == 7 and events.count('RESUME') == 7 and
                not any(name in events for name in ('RESET', 'BLOCK_IO_ERROR', 'GUEST_PANICKED')), '原生事件不完整')
        protocol(record['stderr'])
        boot.check_errors(record['stderr'])
        require('SSI router generated traffic after local drain' not in record['stderr'], '排空后仍产生设备流量')
    require([re.findall(r'SSI_CLOCK_SAMPLE samples=(\d+)', record['stderr']) for record in records] ==
            [[], ['16'] * 8], '未为每轮重新采样')
    sample_rows = re.findall(r'SSI_CLOCK_SAMPLE samples=16 khz=(\d+) rtt_ns=(\d+) uncertainty_ns=(\d+) source_flags=(\d+)',
                             records[1]['stderr'])
    require(len(sample_rows) == 8, '缺少往返延迟原始读数')
    for khz, rtt, uncertainty, flags in (map(int, values) for values in sample_rows):
        require(khz > 0 and 0 < rtt <= 5_000_000 and uncertainty == rtt // 2 and flags & 14 == 14,
                '采样质量不满足原协议门槛')
    floors = [[match.groups()[3:] for match in PREPARED.finditer(record['stderr'])] for record in records]
    require(floors[0] == floors[1], '两端未使用相同的暂停下界')
    return {'paired_pause_resume_verified': True, 'cycles': 7, 'samples': 32, 'max_timer_ns': timer_max,
            'global_stop_command_verified': False, 'reset_resume_verified': False, 'full_ssi_accepted': False}


def check_failure(row):
    run, records = row['run'], row['records']
    fault = run['fault']
    require(fault in ('one-sided', 'silent', 'reset', 'future'), '未知注入类型')
    require(run['runtime_sha256'] == RUNTIME and run['capture_sha256'] == CAPTURE and
            len(records) == 2 and run['errors'], '不是预定候选的拒绝实验')
    for node, record in enumerate(records):
        require(record['node'] == node and record['qemu_sha256'] == RUNTIME and
                record['capture_sha256'] == CAPTURE and record['qemu_exit'] == 1 and
                not record['forced_cleanup'] and not run[f'node{node}_remaining'], '未自行失败停止或有残留')
        snapshots(record, 0, failure=fault)
        require(record['stderr'].count('SSI_CLOCK_COLD_START epoch=1') == 1 and
                'SSI_CLOCK_RELEASE' not in record['stderr'], '错误场景仍释放了恢复许可')
        events = [value for entry in record['qmp'] for value in entry['responses'] if 'event' in value]
        require(sum(value['event'] == 'STOP' for value in events) == 1 and
                not any(value['event'] == 'RESUME' for value in events), '未真正暂停或故障后仍通知恢复')
        resets = [value['data'] for value in events if value['event'] == 'RESET']
        expected = [{'guest': node == 1, 'reason': 'guest-reset' if node else 'host-qmp-system-reset'}]
        require(resets == (expected if fault == 'reset' else []), '复位事件来源不符')
    stderr = '\n'.join(record['stderr'] for record in records)
    elapsed = None
    if fault in ('one-sided', 'silent'):
        elapsed = run['failure_observed_ns'] - run['last_resume_begin_ns']
        require(14_000_000_000 <= elapsed <= 25_000_000_000 and
                'SSI clock preparation deadline expired' in records[0]['stderr'], '未观察到有界准备超时')
        require('SSI_CLOCK_PREPARE epoch=2 state=paused' in records[0]['stderr'], '未进入恢复准备')
    if fault == 'silent':
        require(run['suspended_state'].startswith('T') and run['suspended_pid'] == records[1]['pid'] and
                run['silent_peer_released'] and run['silent_peer_exit_reply'].get('exit') == 1,
                '没有暂停并释放本次实验的对端进程')
        require('SSI invalid clock barrier' in records[1]['stderr'], '对端没有报告未完成的屏障')
    if fault == 'reset':
        require('SSI clock supports paired cold start or user-pause resume only' in stderr,
                '没有拒绝不支持的重置恢复')
    if fault == 'future':
        expected = struct.pack('>HiIIIQIQQ', 18, -1, 4, 1, 0, 99, 1, 0, 0).hex()
        require(run['injection']['frame_hex'] == expected and run['injection']['reply_hex'] == '' and
                'SSI invalid clock barrier' in records[0]['stderr'], '错误代际未被拒绝')
    require('CLOCK_PASS' not in row['clock_log'], '拒绝实验不应完成客体探针')
    return {'fault': fault, 'failed_without_resume': True, 'observed_ns': elapsed,
            'failover_verified': False, 'full_ssi_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    data = json.loads(args.evidence.read_text())
    require(sum(row['kind'] == 'paired-resume' for row in data['runs']) == 1, '缺少最终候选的完整恢复记录')
    failures = [row['run']['fault'] for row in data['runs'] if row['kind'] == 'rejected-resume']
    require(sorted(failures) == ['future', 'one-sided', 'reset', 'silent'], '拒绝实验缺失或重复')
    for row in data['runs']:
        if row['kind'] == 'paired-resume':
            print(row['run']['label'], json.dumps(check(row), ensure_ascii=False))
        elif row['kind'] == 'rejected-resume':
            print(row['run']['label'], json.dumps(check_failure(row), ensure_ascii=False))


if __name__ == '__main__':
    main()
