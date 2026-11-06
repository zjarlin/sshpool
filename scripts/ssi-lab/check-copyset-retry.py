#!/usr/bin/env python3
"""复核页固定重试的真实请求、函数跟踪和响应，不把局部通过当作完整 DSM 验收。"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

ROW = re.compile(r'^\s*(.+)-(\d+)\s+\[(\d+)\]\s+\S+\s+(\d+\.\d+):\s+(\w+):\s*(.*)$')
NAMES = {'copy_lock', 'copy_locked', 'copy_unlock', 'copy_done'}


def inspect(data):
    if data['errors'] or not data.get('vm_closed') or not data['trace_cleanup_complete'] or data['remaining_tasks']:
        raise ValueError('实验或清理未完成')
    header = re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', data['trace'])
    if len(header) != 1 or header[0][0] != header[0][1]:
        raise ValueError('跟踪缓冲不完整')
    if not data['trace_stats']:
        raise ValueError('缺少逐 CPU 缓冲统计')
    for stats in data['trace_stats'].values():
        for field in ('overrun', 'commit overrun', 'dropped events'):
            if re.findall('^' + field + r': (\d+)$', stats, re.MULTILINE) != ['0']:
                raise ValueError('跟踪存在溢出或丢失')
    profile = [row.split() for row in data['kprobe_profile'].splitlines()]
    if len(profile) != 4 or {row[0] for row in profile} != NAMES or any(len(row) != 3 or int(row[2]) for row in profile):
        raise ValueError('函数探针遗漏或集合不完整')
    rows = []
    for line in data['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = ROW.fullmatch(line)
        if match is None:
            raise ValueError('无法识别的跟踪记录')
        name, pid, cpu, stamp, event, detail = match.groups()
        if event not in NAMES | {'tracing_mark_write'}:
            raise ValueError('混入未声明的跟踪事件')
        seconds, fraction = stamp.split('.')
        rows.append({'task': name.strip(), 'pid': int(pid), 'cpu': int(cpu),
                     'ns': int(seconds) * 1000000000 + int(fraction.ljust(9, '0')),
                     'event': event, 'detail': detail})
    if len(rows) != int(header[0][0]):
        raise ValueError('跟踪行数与头部不一致')
    per_cpu = Counter(row['cpu'] for row in rows)
    for name, stats in data['trace_stats'].items():
        if re.fullmatch(r'cpu\d+', name) is None or re.findall(r'^entries: (\d+)$', stats, re.MULTILINE) != [str(per_cpu[int(name[3:])])]:
            raise ValueError('逐 CPU 计数与事件不一致')
    if not per_cpu.keys() <= {int(name[3:]) for name in data['trace_stats']}:
        raise ValueError('跟踪 CPU 缺少统计')
    markers = [row['detail'] for row in rows if row['event'] == 'tracing_mark_write']
    wanted = ['owner_initialized'] + (['page_pinned'] if data['pin'] else []) + ['request_sent']
    wanted += ['unpin_begin', 'unpin_done'] if data['pin'] else []
    wanted += ['read_complete', 'close_begin', 'close_done']
    if markers != wanted or [event['phase'] for event in data['events']] != wanted:
        raise ValueError('请求与清理阶段缺失或错序')
    moments = [event['time_ns'] for event in data['events']]
    if any(now < before for before, now in zip(moments, moments[1:])):
        raise ValueError('控制端阶段时间倒退')
    frame = bytes.fromhex(data['request_hex'])
    if (len(frame) != 4110 or struct.unpack_from('<QHHH', frame) != (38, 0, 0, 42)
            or struct.unpack_from('<BB6xQBBH4x', frame, 14) != (1, 1, 2, 1, 0, 0)
            or any(frame[38:])):
        raise ValueError('需要唯一的完整读页请求')
    bounds = {row['detail']: index for index, row in enumerate(rows) if row['event'] == 'tracing_mark_write'}
    task_names = {int(pid): task['name'] for pid, task in data['initial_tasks'].items()}
    server_ids = {pid for pid, name in task_names.items() if name.startswith('dsm-conn/0:')}
    if len(task_names) != 9 or len(server_ids) != 8 or set(task_names.values()) != {
            'kvm-dsm/0', *(f'dsm-conn/0:{index}' for index in range(8))}:
        raise ValueError('服务线程身份不完整')
    completed = [row['pid'] for row in rows if row['event'] == 'copy_done']
    if len(completed) != 8 or set(completed) != server_ids:
        raise ValueError('缺少全部服务线程的退出边界')
    for index, row in enumerate(rows):
        if row['event'] in NAMES and row['pid'] not in server_ids:
            raise ValueError('混入其他线程的函数记录')
        if row['event'] in NAMES - {'copy_done'} and not bounds['request_sent'] < index < bounds['read_complete']:
            raise ValueError('锁操作不属于本次读请求')
    operations = [row for row in rows if row['event'] in NAMES - {'copy_done'}]
    if not operations or len({row['pid'] for row in operations}) != 1:
        raise ValueError('读页处理线程缺失或不唯一')
    pending = []
    counts = Counter()
    slots = set()
    for row in operations:
        event = row['event']
        counts[event] += 1
        if event in ('copy_lock', 'copy_unlock'):
            vfn = re.search(r'vfn=(0x[0-9a-f]+)', row['detail'])
            if vfn is None or int(vfn[1], 16) != data['vfn']:
                raise ValueError('操作了不同的页面')
            slot = re.search(r'slot=(0x[0-9a-f]+)', row['detail'])
            if slot is None:
                raise ValueError('缺少页面槽身份')
            slots.add(slot[1])
        if event == 'copy_lock':
            if pending:
                raise ValueError('锁入口重复')
            pending = ['entered']
        elif event == 'copy_locked':
            if pending != ['entered'] or not row['detail'].endswith('code=0'):
                raise ValueError('取锁失败或缺少入口')
            pending = ['locked']
        else:
            if pending != ['locked']:
                raise ValueError('解锁缺少成功取锁')
            pending = []
    if pending or len(slots) != 1:
        raise ValueError('缺少锁完成边界')
    retries = 0
    if data['pin']:
        retries = sum(row['event'] == 'copy_unlock' for row in rows[bounds['request_sent']:bounds['unpin_begin']])
        if retries < 2 or data.get('observed_retry_unlocks', 0) < 2 or data['response_before_unpin']:
            raise ValueError('没有证明固定期间的重试和无提前响应')
    # 客户端在读取结束后先关闭模拟连接，再关闭 VM；这段复位错误单独保留。
    during_read = rows[:bounds['read_complete']]
    failures = [int(re.search(r'code=(-?\d+)$', row['detail'])[1]) for row in during_read if row['event'] == 'copy_done']
    closing_codes = [int(re.search(r'code=(-?\d+)$', row['detail'])[1])
                     for row in rows[bounds['read_complete']:] if row['event'] == 'copy_done']
    response = data.get('response')
    digest = hashlib.sha256(bytes((index * 17 + 3) % 256 for index in range(4096))).hexdigest()
    if data['expected_page_sha256'] != digest:
        raise ValueError('预期页面内容不符')
    if response is not None:
        if (failures or data.get('response_error') or response != {
                'length': 4110, 'copyset': 1, 'version': 0, 'txid': 42, 'sha256': digest, 'matches': True}):
            raise ValueError('页面内容、副本集合、版本或响应事务不符')
        outcome = 'page_returned'
    else:
        if not data['pin'] or failures != [-22] or data.get('response_error') != 'timed out':
            raise ValueError('失败缺少真实处理线程退出和接收超时证据')
        rejected = next(index for index, row in enumerate(rows) if row['event'] == 'copy_done')
        if not bounds['unpin_begin'] < rejected < bounds['read_complete']:
            raise ValueError('处理线程退出不在解除固定后的接收窗口内')
        outcome = 'request_rejected_after_unpin'
    hits = {row[0]: int(row[1]) for row in profile}
    for event, count in counts.items():
        if hits[event] < count:
            raise ValueError('函数命中数小于跟踪记录数')
    return {'outcome': outcome, 'pin': data['pin'], 'retry_unlocks_before_unpin': retries,
            'handler_codes_during_read': failures, 'handler_codes_after_read': closing_codes,
            'trace_events': len(rows),
            'page_response_matches': response is not None, 'cleanup_complete': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--expect', choices=['page_returned', 'request_rejected_after_unpin'], default='page_returned')
    args = parser.parse_args()
    result = inspect(json.loads(args.record.read_text()))
    if result['outcome'] != args.expect:
        raise SystemExit('结果与预期不符：' + result['outcome'])
    print(json.dumps(result))


if __name__ == '__main__':
    main()
