#!/usr/bin/env python3
"""核对真实客体请求、未完成队列、错误状态和退出码，不把复位当成数据恢复。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('flush', Path(__file__).with_name('check-shutdown-flush.py'))
flush = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flush)
demand, response = flush.demand, flush.response
DEVICE = '/machine/peripheral/ssi-disk/virtio-backend'
RUNTIMES = {'baseline': '6de20b75fb36ca84f4366ef8595f48895778a36e98ab30b7dd52dae717e0a4cb',
            'candidate': '2b434a5b8270b17d59e772ba2eaae231968da4fd6aa58fbb62aaa7889c566491'}


def inspect_qmp(record):
    entries = record['qmp']
    names = [entry['request']['execute'] for entry in entries]
    demand([entry['request']['id'] for entry in entries] == list(range(len(entries))), 'QMP 序号不连续')
    demand(names[0] == 'qmp_capabilities' and names[-1] == 'quit' and names.count('quit') == 1, 'QMP 生命周期不完整')
    action = record['action']
    allowed = {'qmp_capabilities', 'query-status', 'query-block', 'x-query-virtio',
               'x-query-virtio-queue-status', 'stop', 'quit'}
    action_command = {'reset': 'system_reset', 'resume': 'cont', 'unrealize': 'qom-set'}
    if action != 'quit':
        allowed.add(action_command[action])
        demand(names.count(action_command[action]) == 1, '生命周期动作重复或缺失')
    if action == 'unrealize':
        allowed.add('qom-get')
    demand(set(names) <= allowed and names.count('stop') == (2 if action == 'resume' else 1), '混入未声明的 QMP 动作')
    for entry in entries[:-1]:
        name = entry['request']['execute']
        if name in ('qom-set', 'qom-get'):
            expected = {'path': '/machine/peripheral/ssi-disk', 'property': 'realized'}
            if name == 'qom-set':
                expected['value'] = False
            demand(entry['request']['arguments'] == expected, '销毁的设备身份不符')
        if name == 'x-query-virtio-queue-status':
            demand(entry['request']['arguments'] == {'path': DEVICE, 'queue': 0}, '查询了错误的队列')
        replies = [r for r in entry['responses'] if 'id' in r]
        expected_error = {'class': 'GenericError', 'desc': 'No virtio devices found'}
        if name == 'x-query-virtio' and action == 'unrealize' and len(replies) == 1 and replies[0].get('error') == expected_error:
            demand(replies[0]['id'] == entry['request']['id'], '销毁后查询回复不匹配')
        else:
            response(entry)
    if record['quit_transport'] == 'reply':
        demand(response(entries[-1]) == {}, '关闭没有受理')
    else:
        demand(record['qemu_exit'] == 1 and record['quit_transport'] in ('reset', 'eof') and
               not any('id' in r for r in entries[-1]['responses']), '关闭传输状态不符')
    # 快照必须与保存的原始 QMP 回复逐项对应，不能只相信派生计数。
    blocks = [i for i, name in enumerate(names) if name == 'query-block']
    demand(len(blocks) == len(record['snapshots']), '快照或原始查询缺失')
    for i, snapshot in zip(blocks, record['snapshots']):
        demand(names[i - 1] == 'query-status' and response(entries[i - 1]) == snapshot['status'] and
               response(entries[i]) == snapshot['blocks'], '快照与原始运行或块状态不一致')
        if 'queue' in snapshot:
            demand(names[i + 1:i + 3] == ['x-query-virtio', 'x-query-virtio-queue-status'] and
                   response(entries[i + 1]) == snapshot['devices'] and response(entries[i + 2]) == snapshot['queue'],
                   '快照与原始设备或队列不一致')
        else:
            demand(names[i + 1:i + 3] == ['qom-get', 'x-query-virtio'] and
                   response(entries[i + 1]) is False and snapshot['realized'] is False and not snapshot['devices'],
                   '没有真实销毁设备')
    errors = [r['data'] for entry in entries for r in entry['responses'] if r.get('event') == 'BLOCK_IO_ERROR']
    demand(len(errors) == int(bool(record['injected_errno'])), '原生错误事件缺失或重复')
    if errors:
        demand(errors[0]['device'] == 'ssi-probe' and errors[0]['qom-path'] == DEVICE and
               errors[0]['operation'] == 'write' and errors[0]['action'] == 'stop' and
               errors[0]['nospace'] == (record['injected_errno'] == 28), '错误设备或处理策略不符')


def inspect_queue(record):
    action, error = record['action'], record['injected_errno']
    phases = ['ready', 'after_write', 'after_stop']
    if action != 'quit':
        phases.append('after_' + action)
    phases.append('before_quit')
    snapshots = record['snapshots']
    demand([s['phase'] for s in snapshots] == phases, '生命周期快照不完整')
    times = [s['time_ns'] for s in snapshots]
    demand(all(type(t) is int and t > 0 for t in times) and times == sorted(set(times)), '快照时间不连续')
    failed = {0: 'ok', 5: 'failed', 28: 'nospace'}[error]
    for s in snapshots:
        phase = s['phase']
        initial = phase == 'ready'
        final = phase in ('after_' + action, 'before_quit')
        recovered = final and action == 'resume'
        expected_io = 'ok' if initial or recovered else failed
        state = 'running' if initial or (phase == 'after_write' and not error) else 'io-error' if error else 'paused'
        if final and action in ('reset', 'resume'):
            state = 'prelaunch' if action == 'reset' else 'paused'
        demand(s['status'] == {'status': state, 'running': state == 'running'}, '运行状态不符')
        demand(len(s['blocks']) == 1 and s['blocks'][0]['device'] == 'ssi-probe' and
               s['blocks'][0]['io-status'] == expected_io, '块设备错误状态丢失')
        inserted = s['blocks'][0]['inserted']
        demand(inserted['drv'] == 'raw' and inserted['image']['virtual-size'] == 67108864 and
               inserted['cache'] == {'no-flush': False, 'direct': False, 'writeback': True}, '绕过刷盘或盘类型不符')
        if final and action == 'unrealize':
            demand('queue' not in s and s['realized'] is False and s['devices'] == [], '销毁后设备仍可见')
            continue
        queue = s['queue']
        pending = int(bool(error) and not initial and not (final and action in ('reset', 'resume')))
        demand(queue['inuse'] == pending and queue['queue-index'] == 0 and queue['name'] == 'virtio-blk', '待完成描述符数量不符')
    if error:
        before, stopped = snapshots[0]['queue'], snapshots[1]['queue']
        demand(stopped['last-avail-idx'] == before['last-avail-idx'] + 1 and
               stopped['used-idx'] == before['used-idx'], '失败写入被错误标记为已完成')


def check(row):
    record, run = row['record'], row['run']
    error, action, variant = run['error'], run['action'], run['variant']
    demand(variant in RUNTIMES and error in (0, 5, 28) and action in ('quit', 'reset', 'unrealize', 'resume'), '场景无效')
    demand(record['kernel'] == '6.8.0-147-generic' and record['dsm_observed'] is False, '不能冒充 DSM 实验')
    demand(record['qemu_sha256'] == RUNTIMES[variant] and record['capture_sha256'] == run['capture_sha256'], '运行时或采集器身份错误')
    demand(record['guest_kernel_sha256'] == '41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f' and
           record['initramfs_sha256'] == 'b32e4dccc48587ed4123a57d9c1bc80bdc3de2750b6d6182c19e3194772c2db7', '客体运行时不符')
    demand(record['injected_errno'] == error and record['action'] == action and run['capture_exit'] == 0 and
           not run['remaining'] and not record['errors'] and not record['forced_cleanup'], '采集失败或强制清理')
    failed = bool(error) and action != 'resume'
    expected_exit = int(variant == 'candidate' and failed)
    demand(type(record['qemu_exit']) is int and record['qemu_exit'] == expected_exit, '退出码不符')
    demand(record['directory_created_exclusively'] and record['image_bytes'] == 67108864 and
           record['write_bytes'] == 4096 and record['write_offset'] == 1048576, '实验盘写入边界不符')
    config = '' if not error else ('[inject-error]\nevent = "pwritev"\n' +
        f'errno = "{error}"\niotype = "write"\nonce = "on"\nimmediately = "on"\n')
    demand(record['blkdebug_config'] == config, '实际故障注入配置错误')
    cmd = record['command']
    demand(cmd.count('-drive') == cmd.count('-device') == cmd.count('-kernel') == cmd.count('-initrd') == 1 and
           '-S' not in cmd and '-local-cpu' not in cmd and '-netdev' not in cmd and '-hda' not in cmd and '-blockdev' not in cmd,
           '不是独立真实客体实验')
    demand(cmd[cmd.index('-machine') + 1] == 'pc,accel=kvm,kernel-irqchip=split', '没有使用 KVM')
    drive = cmd[cmd.index('-drive') + 1]
    prefix = 'if=none,id=ssi-probe,format=raw,cache=writeback,werror=stop,rerror=stop,file=blkdebug:'
    demand(drive.startswith(prefix), '磁盘链路或错误处理不符')
    paths = drive.removeprefix(prefix).split(':')
    demand(len(paths) == 2 and paths[0].endswith('/blkdebug.conf') and
           paths[1] == paths[0].removesuffix('blkdebug.conf') + 'disk.raw', '没有使用同一独立目录')
    for snapshot in record['snapshots']:
        demand(snapshot['blocks'][0]['inserted']['file'] == drive.split('file=', 1)[1], 'QMP 磁盘与启动参数不符')
    serial, stderr = record['serial'], record['stderr']
    demand(serial.count('SSI_BLOCK_READY') == serial.count('SSI_BLOCK_WRITE_BEGIN') == 1 and
           serial.count('SSI_BLOCK_WRITE_OK') == int(not failed) and 'SSI_BLOCK_WRITE_FAILED' not in serial,
           '真实客体写入标记缺失或多次启动')
    demand(not re.search(r'Kernel panic|segmentation fault|terminating on signal|core dumped', serial + stderr, re.I), '客体或运行时崩溃')
    writes = re.findall(r'^virtio_blk_handle_write vdev (0x[0-9a-f]+) req (0x[0-9a-f]+) sector (\d+) nsectors (\d+)$', stderr, re.M)
    demand(len(writes) == (2 if error and action == 'resume' else 1) and
           all(w == writes[0] and w[2:] == ('2048', '8') for w in writes), '不是原生单次请求及同一请求重试')
    tail = stderr[stderr.index('virtio_blk_handle_write'):]
    returns = re.findall(r'^virtio_blk_rw_complete vdev ' + writes[0][0] + r' req ' + writes[0][1] + r' ret (-?\d+)$', tail, re.M)
    expected = [-error] + ([0] if error and action == 'resume' else [])
    demand([int(v) for v in returns] == expected, '原生 virtio 请求错误返回不符')
    if failed:
        demand('virtio_blk_req_complete' not in tail and 'virtqueue_fill' not in tail, '失败请求被意外完成')
    else:
        demand('virtio_blk_req_complete' in tail and 'virtqueue_fill' in tail, '正常请求未完成')
    flushes = re.findall(r'^vm_stop_flush_all ret (-?\d+)$', stderr, re.M)
    demand(flushes and all(int(v) == 0 for v in flushes), '不是最终刷盘成功的历史错误场景')
    fatal = "QEMU block backend 'ssi-probe' retains I/O status '" + ('nospace' if error == 28 else 'failed') + "'; terminating this node"
    demand((fatal in stderr) == bool(expected_exit), '未保留原生块设备错误或误报正常退出')
    demand(record['payload_matches'] == (not failed) and record['payload_zero'] == failed and
           record['payload_sha256'] == hashlib.sha256((b'\0' if failed else b'\x5a') * 4096).hexdigest(), '磁盘内容与恢复状态不一致')
    inspect_qmp(record)
    inspect_queue(record)
    return {'variant': variant, 'action': action, 'errno': error, 'exit': expected_exit,
            'guest_write_completed': not failed, 'dsm_observed': False, 'full_ssi_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    print(json.dumps(check(json.loads(args.record.read_text())), ensure_ascii=False))


if __name__ == '__main__':
    main()
