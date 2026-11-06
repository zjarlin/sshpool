#!/usr/bin/env python3
"""核对复位后的路由存活、真实 RESET 事件和退出，不把清理退出冒充协议完成。"""
import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('pins', Path(__file__).with_name('check-virtio-dsm-pins.py'))
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)
demand, response = pins.demand, pins.response
RUNTIMES = {'baseline': 'f2fd12e514efdeb7493dd482f4ab343dce72289b8a90b131aebe84e4dddd4540',
            'candidate': '7ed4008cbe393138b82b7ec96a643347ea1a9e22ba05f927e943189b219d09fc'}
CAPTURE = 'a2fba6dab8a868bf86472ec8f18232785165fce0d0dcd3baf07864c23ba88249'


def inspect_qmp(record, run, node):
    entries = record['qmp']
    names = [e['request']['execute'] for e in entries]
    demand([e['request']['id'] for e in entries] == list(range(len(entries))), 'QMP 序号不连续')
    demand(names[0] == 'qmp_capabilities', '缺少 QMP 协商')
    queries = {'query-status', 'query-block', 'qom-get', 'x-query-virtio-queue-status'}
    commands = ['stop']
    if node == 0:
        commands += ['system_reset'] * run['reset_count']
        if not run['crash']:
            commands.append('quit')
    demand([name for name in names[1:] if name not in queries] == commands, '复位发起方或次数不符')
    for entry in entries:
        name = entry['request']['execute']
        arguments = entry['request'].get('arguments', {})
        expected = {}
        if name == 'qom-get':
            expected = {'path': pins.DEVICE, 'property': 'realized'}
        elif name == 'x-query-virtio-queue-status':
            expected = {'path': pins.pending.DEVICE, 'queue': 0}
        demand(arguments == expected, '管理请求参数不符')
        if name == 'quit' and record.get('quit_transport') != 'reply':
            demand(run['error'] and record.get('quit_transport') in ('eof', 'reset') and
                   not any('id' in reply for reply in entry['responses']), '关闭传输不符')
        else:
            response(entry)
    reset_events = [(i, r['data']) for i, e in enumerate(entries) for r in e['responses'] if r.get('event') == 'RESET']
    demand(len(reset_events) == run['reset_count'], '没有实际执行全部复位')
    expected_reset = {'guest': node == 1, 'reason': 'guest-reset' if node else 'host-qmp-system-reset'}
    demand(all(event == expected_reset for _, event in reset_events), '复位不是由主节点传播')
    events = [r['data'] for e in entries for r in e['responses'] if r.get('event') == 'BLOCK_IO_ERROR']
    error = run['error'] if node == 0 else 0
    demand(len(events) == int(bool(error)), '块设备错误事件缺失')
    if events:
        event = events[0]
        demand(event['device'] == 'ssi-probe' and event['qom-path'] == pins.pending.DEVICE and
               event['operation'] == 'write' and event['action'] == 'stop' and
               event['nospace'] == (error == 28), '不是预定块设备错误')
    covered = set()
    previous_end = 0
    for snapshot in record['snapshots']:
        start, end = snapshot['qmp_start'], snapshot['qmp_end']
        demand(previous_end <= start < end <= len(entries), '快照范围无序或越界')
        previous_end = end
        demand(names[start:end] == ['query-status', 'query-block', 'qom-get', 'x-query-virtio-queue-status'],
               '快照缺少实际设备查询或混入诊断')
        covered.update(range(start, end))
        for index, field in enumerate(('status', 'blocks', 'realized', 'queue')):
            demand(response(entries[start + index]) == snapshot[field], '原始回复与快照不符')
        phase = snapshot['phase']
        count = 0
        if phase.startswith('after_reset_'):
            count = int(phase.removeprefix('after_reset_'))
        elif phase == 'before_quit':
            count = run['reset_count']
        demand(sum(i < end for i, _ in reset_events) == count, '复位快照未等到相应原生事件')
    demand({i for i, name in enumerate(names) if name in queries and name != 'query-status'} <= covered,
           '快照遗漏设备回复')


def inspect_snapshots(record, run, node):
    phases = ['ready'] + (['after_error'] if run['error'] else []) + ['after_stop']
    phases += ['after_reset_' + str(n + 1) for n in range(run['reset_count'])] + ['before_quit']
    snapshots = record['snapshots']
    demand([s['phase'] for s in snapshots] == phases, '生命周期快照不完整')
    times = [s['time_ns'] for s in snapshots]
    demand(all(type(t) is int and t > 0 for t in times) and times == sorted(set(times)), '快照时间无序')
    before = next(s for s in snapshots if s['phase'] == 'after_stop')
    before_tasks = {t['tid'] for t in before['threads']}
    lost_tasks = []
    for snapshot in snapshots:
        phase = snapshot['phase']
        reset = phase.startswith('after_reset_') or phase == 'before_quit'
        state = 'running' if phase in ('ready', 'after_error') else 'paused'
        if node == 0 and run['error'] and phase != 'ready':
            state = 'io-error'
        if reset:
            state = 'prelaunch'
        demand(snapshot['status'] == {'status': state, 'running': state == 'running'}, '复位后的运行状态不符')
        demand(snapshot['realized'] is True and snapshot['pins'] == [], '混入设备销毁或伪造引用观察')
        blocks = snapshot['blocks']
        failed = run['error'] if node == 0 and phase != 'ready' else 0
        demand(len(blocks) == 1 and blocks[0]['device'] == 'ssi-probe' and
               blocks[0]['io-status'] == {0: 'ok', 5: 'failed', 28: 'nospace'}[failed],
               '复位丢失了后端错误')
        inserted = blocks[0]['inserted']
        demand(inserted['drv'] == 'raw' and inserted['image']['virtual-size'] == 67108864 and
               inserted['cache'] == {'no-flush': False, 'direct': False, 'writeback': True}, '磁盘或刷盘设置不符')
        queue = snapshot['queue']
        waiting = int(node == 0 and bool(run['error']) and phase in ('after_error', 'after_stop'))
        demand(queue['name'] == 'virtio-blk' and queue['queue-index'] == 0 and queue['inuse'] == waiting,
               '请求未真正完成复位清理')
        if reset or node == 1:
            demand(queue['vring-desc'] == queue['vring-avail'] == queue['vring-used'] == 0,
                   '队列尚未复位或副节点意外使用设备')
        else:
            demand(queue['vring-desc'] > 0 and queue['last-avail-idx'] - queue['used-idx'] == waiting,
                   '客体请求描述符缺失')
        tasks = snapshot['threads']
        tids = [t['tid'] for t in tasks]
        demand(all(type(t) is int and t > 0 for t in tids) and len(set(tids)) == len(tids), '线程记录无效')
        demand({t['name'] for t in tasks if t['name'].startswith('CPU ')} == {f'CPU {n}/KVM' for n in range(4)},
               '复位期间 vCPU 线程丢失')
        if reset:
            lost = sorted(before_tasks - set(tids))
            demand(len(lost) == int(run['variant'] == 'baseline' and node == 1), '线程生命周期与候选不符')
            lost_tasks = lost
    return lost_tasks


def inspect_record(record, run, node):
    demand(record['schema'] == 1 and record['kernel'] == '7.1.0-rc3-sshpool-gvm-pf24' and
           record['node'] == node and record['pin_query'] == 'none', '实验身份或原生引用声明不符')
    demand(record['qemu_sha256'] == RUNTIMES[run['variant']] and record['capture_sha256'] == CAPTURE,
           '运行时或采集器哈希不符')
    demand(record['guest_kernel_sha256'] == '41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f' and
           record['initramfs_sha256'] == 'b32e4dccc48587ed4123a57d9c1bc80bdc3de2750b6d6182c19e3194772c2db7', '客体镜像身份不符')
    demand(record['injected_errno'] == (run['error'] if node == 0 else 0), '错误注入节点不符')
    baseline_timeout = run['variant'] == 'baseline' and node == 1
    if baseline_timeout:
        demand(record['forced_cleanup'] is True and len(record['errors']) == 1 and
               'timed out after 40 seconds' in record['errors'][0] and 'exit_observed_ns' not in record,
               '没有复现基线超时')
    else:
        demand(not record['errors'] and record['forced_cleanup'] is False, '强制清理不能当作正常退出')
    expected_exit = -9 if run['crash'] and node == 0 else int(bool(run['error']) or run['crash'])
    demand(type(record['qemu_exit']) is int and record['qemu_exit'] == expected_exit, '进程退出码不符')
    expected_action = 'wait_exit' if node == 1 else 'crash' if run['crash'] else 'quit'
    demand(record['actions'][-1]['request'] == {'op': expected_action}, '实际关闭动作不符')
    demand(record.get('injected_fault') == ('SIGKILL' if run['crash'] and node == 0 else None), '故障注入记录不符')
    elapsed = None
    if not baseline_timeout:
        elapsed = record['exit_observed_ns'] - record['actions'][-1]['time_ns']
        demand(0 < elapsed < 40000000000, '没有在实际退出截止时间内完成')
    # 基线超时的副节点没有处理关闭，不能要求它已经报告路由关闭失败。
    pins.inspect_device_write(record, node, run['error'], expect_peer_timeout=baseline_timeout)
    if run['crash'] and node == 1:
        demand('SSI router EOF before acknowledged drain' in record['stderr'], '暂停副节点未报告对端断连')
    inspect_qmp(record, run, node)
    lost = inspect_snapshots(record, run, node)
    return {'node': node, 'exit': record['qemu_exit'], 'elapsed_ns': elapsed,
            'forced_cleanup': record['forced_cleanup'], 'lost_task_ids': lost}


def check(data):
    run = data['run']
    demand(run['variant'] in RUNTIMES and run['runtime_sha256'] == RUNTIMES[run['variant']] and
           run['capture_sha256'] == CAPTURE, '运行版本身份不符')
    demand(run['action'] == 'reset' and run['reset_count'] in (1, 3) and run['pause_cycles'] == 0 and
           run['error'] in (0, 5, 28) and type(run['crash']) is bool, '场景不符')
    demand(not run['crash'] or run['error'] == 0, '未验证故障组合')
    demand(len(data['records']) == 2 and not run['node0_remaining'] and not run['node1_remaining'], '节点或清理记录缺失')
    baseline = run['variant'] == 'baseline'
    if baseline:
        demand(run['error'] == 5 and run['reset_count'] == 1 and not run['crash'] and
               run['capture_exits'] == [0, 1] and len(run['errors']) == 1, '基线并未复现预定失败')
    else:
        demand(not run['errors'] and run['capture_exits'] == [0, 0], '候选采集未完整结束')
    nodes = [inspect_record(record, run, node) for node, record in enumerate(data['records'])]
    return {'nodes': nodes, 'baseline_timeout_reproduced': baseline, 'reset_shutdown_verified': not baseline,
            'native_pins_observed': False, 'reset_resume_verified': False, 'full_ssi_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(check(json.loads(args.record.read_text())), ensure_ascii=False))
    except (ValueError, KeyError, IndexError, TypeError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
