#!/usr/bin/env python3
"""将真实设备、QMP 和原生 DSM 引用相互核对；取消请求不代表恢复数据。"""
import argparse
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('pending', Path(__file__).with_name('check-virtio-pending.py'))
pending = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pending)
demand, response = pending.demand, pending.response
RUNTIMES = {
    'baseline': 'eaf538242810ed26f9e1f0084474dac10892ea33b90f049004e4c28b907c4385',
    'candidate': '30da605a7cfa058512ded7d134123f2f8f3b1f8bcee5cd1a8a5f9d5db383e467',
}
CAPTURES = {'ad1f3de1e281758fe18499b4febbb02f03785aef948431f227c2d2c90d04568b',
            '469a42f62601738f45951c5913ebe6a0260beb97e79bf7bcf511e90432b53705'}
DEVICE = '/machine/peripheral/ssi-disk'
DISK_SHA = {False: '3b6a07d0d404fab4e23b6d34bc6696a6a312dd92821332385e5af7c01c421351',
            True: '2728a87677da0a44b53028a9a6973c893993c70646565058e67670a6c342db6d'}


def inspect_qmp(record, action, paired_error):
    entries = record['qmp']
    names = [e['request']['execute'] for e in entries]
    demand([e['request']['id'] for e in entries] == list(range(len(entries))), 'QMP 序号缺失')
    demand(names[0] == 'qmp_capabilities', '缺少 QMP 协商')
    expected_actions = ['stop']
    if action == 'unrealize':
        expected_actions.append('qom-set')
    if action == 'reset' and record['node'] == 0:
        expected_actions.append('system_reset')
    if record['node'] == 0:
        expected_actions.append('quit')
    queries = {'query-status', 'query-block', 'qom-get', 'x-query-virtio-queue-status', 'human-monitor-command'}
    demand([name for name in names[1:] if name not in queries] == expected_actions, '生命周期动作不符')
    for entry in entries:
        name = entry['request']['execute']
        arguments = entry['request'].get('arguments', {})
        if name in ('qom-get', 'qom-set'):
            expected = {'path': DEVICE, 'property': 'realized'}
            if name == 'qom-set':
                expected['value'] = False
            demand(arguments == expected, '设备管理身份不符')
        elif name == 'x-query-virtio-queue-status':
            demand(arguments == {'path': pending.DEVICE, 'queue': 0}, '队列身份不符')
        elif name == 'human-monitor-command':
            demand(arguments == {'command-line': 'ssi_device_pins'}, '混入其他 HMP 命令')
        else:
            demand(not arguments, '存在额外 QMP 参数')
        if name == 'quit' and record.get('quit_transport') != 'reply':
            demand(record.get('quit_transport') in ('eof', 'reset') and paired_error and
                   not any('id' in r for r in entry['responses']), '关闭回复不符')
        else:
            response(entry)
    # 查询结果必须落在对应快照的原始区间内，重复计数不能取自同一次回复。
    covered = set()
    previous_end = 0
    for snapshot in record['snapshots']:
        start, end = snapshot['qmp_start'], snapshot['qmp_end']
        demand(type(start) is int and type(end) is int and 0 < start < end <= len(entries), '快照区间越界')
        indices = set(range(start, end))
        demand(start >= previous_end and not covered.intersection(indices), '快照区间重叠或无序')
        previous_end = end
        covered.update(indices)
        fields = ['status', 'blocks', 'realized'] + (['queue'] if snapshot['realized'] else [])
        expected = ['query-status', 'query-block', 'qom-get']
        if snapshot['realized']:
            expected.append('x-query-virtio-queue-status')
        expected += ['human-monitor-command'] * 2
        demand(names[start:end] == expected and len(snapshot['pins']) == 2, '快照查询不完整')
        for index, field in enumerate(fields):
            demand(response(entries[start + index]) == snapshot[field], '快照与原始 QMP 不一致')
        demand([json.loads(response(e)) for e in entries[end - 2:end]] == snapshot['pins'], '原生引用回复不一致')
    demand({i for i, name in enumerate(names) if name != 'query-status' and name in queries} <= covered,
           '快照遗漏原始设备查询')
    events = [r['data'] for e in entries for r in e['responses'] if r.get('event') == 'BLOCK_IO_ERROR']
    error = record['injected_errno']
    demand(len(events) == int(bool(error)), '原生错误事件缺失或重复')
    if events:
        event = events[0]
        demand(event['device'] == 'ssi-probe' and event['qom-path'] == pending.DEVICE and
               event['operation'] == 'write' and event['action'] == 'stop' and
               event['nospace'] == (error == 28), '原生写入错误身份不符')


def inspect_snapshots(record, action, error, variant):
    phases = ['ready'] + (['after_error'] if error else []) + ['after_stop']
    if action != 'quit':
        phases.append('after_' + action)
    phases.append('before_quit')
    snapshots = record['snapshots']
    demand([s['phase'] for s in snapshots] == phases, '生命周期快照缺失')
    times = [s['time_ns'] for s in snapshots]
    demand(all(type(t) is int and t > 0 for t in times) and times == sorted(set(times)), '快照时间无序')
    active = record['node'] == 0
    for snapshot in snapshots:
        phase = snapshot['phase']
        initial = phase == 'ready'
        final = phase in ('after_' + action, 'before_quit')
        cancelled = final and action in ('reset', 'unrealize')
        retained = active and error and not initial and not (cancelled and (action == 'reset' or variant == 'candidate'))
        expected_pin = {'ret': 0, 'version': 1, 'active_ops': 0, 'read_refs': 2 if retained else 0,
                        'write_refs': 1 if retained else 0, 'error': 0, 'reserved': 0}
        demand(snapshot['pins'] == [expected_pin, expected_pin], '原生引用未按生命周期释放或查询失败')
        state = 'running' if phase in ('ready', 'after_error') else 'paused'
        if active and error and not initial:
            state = 'io-error'
        if final and action == 'reset':
            state = 'prelaunch'
        demand(snapshot['status'] == {'status': state, 'running': state == 'running'}, '运行状态不符')
        blocks = snapshot['blocks']
        expected_io = {0: 'ok', 5: 'failed', 28: 'nospace'}[error if active and not initial else 0]
        demand(len(blocks) == 1 and blocks[0]['device'] == 'ssi-probe' and blocks[0]['io-status'] == expected_io,
               '设备后端错误被清除')
        inserted = blocks[0]['inserted']
        demand(inserted['drv'] == 'raw' and inserted['image']['virtual-size'] == 67108864 and
               inserted['cache'] == {'no-flush': False, 'direct': False, 'writeback': True}, '磁盘类型或刷盘设置不符')
        unrealized = final and action == 'unrealize'
        demand(snapshot['realized'] is (not unrealized) and ('queue' in snapshot) == (not unrealized), '设备未实际销毁')
        if unrealized:
            continue
        queue = snapshot['queue']
        waiting = int(active and bool(error) and not initial and not cancelled)
        demand(queue['name'] == 'virtio-blk' and queue['queue-index'] == 0 and queue['inuse'] == waiting,
               '实际队列与待完成请求不符')
        if not active or (final and action == 'reset'):
            demand(queue['vring-desc'] == queue['vring-avail'] == queue['vring-used'] == 0, '队列意外处于活动状态')
        else:
            demand(queue['vring-desc'] > 0 and queue['last-avail-idx'] - queue['used-idx'] == waiting,
                   '客体描述符未配置或完成计数不符')


def inspect_record(record, run, node):
    error, action = run['error'], run['action']
    local_error = error if node == 0 else 0
    demand(record['schema'] == 1 and record['kernel'] == '7.1.0-rc3-sshpool-gvm-pf24' and
           record['node'] == node and record['injected_errno'] == local_error, '节点或实验身份不符')
    demand(record['qemu_sha256'] == RUNTIMES[run['variant']] and record['capture_sha256'] in CAPTURES,
           '未核对的运行时或采集器')
    demand(record['guest_kernel_sha256'] == '41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f' and
           record['initramfs_sha256'] == 'b32e4dccc48587ed4123a57d9c1bc80bdc3de2750b6d6182c19e3194772c2db7', '客体镜像身份不符')
    demand(not record['errors'] and record['forced_cleanup'] is False and
           type(record['qemu_exit']) is int and record['qemu_exit'] == int(bool(error)), '采集失败或实际退出码不符')
    config = '' if not local_error else ('[inject-error]\nevent = "pwritev"\n' +
        f'errno = "{local_error}"\niotype = "write"\nonce = "on"\nimmediately = "on"\n')
    demand(record['blkdebug_config'] == config, '错误注入配置不符')
    cmd = record['command']
    demand(all(cmd.count(flag) == 1 for flag in ('-drive', '-device', '-kernel', '-initrd', '-local-cpu')) and
           not set(cmd).intersection({'-S', '-netdev', '-hda', '-blockdev', '-fsdev', '-virtfs'}), '拓扑或磁盘边界不符')
    demand(cmd[cmd.index('-machine') + 1] == 'pc,accel=kvm,kernel-irqchip=split' and
           cmd[cmd.index('-smp') + 1] == '4,sockets=2,cores=2,threads=1' and
           cmd[cmd.index('-local-cpu') + 1].startswith(f'cpus=2,start={node * 2},iplist='), '没有使用预定 DSM 拓扑')
    drive = cmd[cmd.index('-drive') + 1]
    prefix = 'if=none,id=ssi-probe,format=raw,cache=writeback,werror=stop,rerror=stop,file=blkdebug:'
    demand(drive.startswith(prefix), '块层链路不符')
    paths = drive[len(prefix):].split(':')
    demand(len(paths) == 2 and paths[0].endswith('/blkdebug.conf') and
           paths[1] == paths[0][:-len('blkdebug.conf')] + 'disk.raw', '没有使用独立实验盘')
    demand(all(s['blocks'][0]['inserted']['file'] == drive.split('file=', 1)[1] for s in record['snapshots']),
           '查询的磁盘不属于本次实验')
    serial, stderr = record['serial'], record['stderr']
    demand(not re.search(r'Kernel panic|segmentation fault|terminating on signal|core dumped', serial + stderr, re.I), '客体崩溃')
    writes = re.findall(r'^virtio_blk_handle_write vdev (0x[0-9a-f]+) req (0x[0-9a-f]+) sector (\d+) nsectors (\d+)$', stderr, re.M)
    if node == 0:
        demand(serial.count('SSI_BLOCK_READY') == serial.count('SSI_BLOCK_WRITE_BEGIN') == 1 and
               serial.count('SSI_BLOCK_WRITE_OK') == int(not error) and 'SSI_BLOCK_WRITE_FAILED' not in serial,
               '客体实际写入标记不符')
        demand(len(writes) == 1 and writes[0][2:] == ('2048', '8'), '原生请求身份不符')
        tail = stderr[stderr.index('virtio_blk_handle_write'):]
        returns = re.findall(r'^virtio_blk_rw_complete vdev ' + writes[0][0] + r' req ' + writes[0][1] + r' ret (-?\d+)$', tail, re.M)
        demand(returns == [str(-error)], '原生写请求返回不符')
        demand(('virtio_blk_req_complete' in tail) == (not error) and
               ('virtqueue_fill' in tail) == (not error), '取消被误报为写入完成')
        fatal = "retains I/O status '" + ('nospace' if error == 28 else 'failed') + "'; terminating this node"
        demand((fatal in stderr) == bool(error), '未保留后端错误')
    else:
        demand(not writes and 'SSI_BLOCK_WRITE_BEGIN' not in serial, '副节点意外执行了磁盘写入')
        if error:
            demand(any(message in stderr for message in ('SSI missing or invalid drain acknowledgement',
                   'SSI router EOF before acknowledged drain')), '缺少对端故障传播证据')
    flushes = re.findall(r'^vm_stop_flush_all ret (-?\d+)$', stderr, re.M)
    demand(flushes and set(flushes) == {'0'}, '不是最终刷盘成功的场景')
    written = node == 0 and not error
    demand(record['payload_matches'] is written and record['payload_zero'] is (not written) and
           record['disk_sha256'] == DISK_SHA[written], '取消或副节点空盘被当成恢复')
    inspect_qmp(record, action, error)
    inspect_snapshots(record, action, error, run['variant'])
    return {'node': node, 'qemu_exit': record['qemu_exit'], 'payload_written': written,
            'last_pins': record['snapshots'][-1]['pins'][0]}


def check(data):
    run = data['run']
    demand(run['variant'] in RUNTIMES and run['runtime_sha256'] == RUNTIMES[run['variant']], '运行时身份错误')
    demand(run['action'] in ('quit', 'reset', 'unrealize') and run['error'] in (0, 5, 28) and
           run['pause_cycles'] == 0, '未支持的实验场景')
    demand(not run['errors'] and run['capture_exits'] == [0, 0] and not run['node0_remaining'] and
           not run['node1_remaining'] and len(data['records']) == 2, '采集或清理不完整')
    nodes = [inspect_record(r, run, node) for node, r in enumerate(data['records'])]
    leaked = run['variant'] == 'baseline' and run['error'] != 0 and run['action'] == 'unrealize'
    return {'nodes': nodes, 'native_pin_leak_reproduced': leaked,
            'native_pins_released': all(n['last_pins']['read_refs'] == n['last_pins']['write_refs'] == 0 for n in nodes),
            'storage_replicated': False, 'full_ssi_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(check(json.loads(args.record.read_text())), ensure_ascii=False))
    except (ValueError, KeyError, TypeError, IndexError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
