#!/usr/bin/env python3
"""核对真实块设备关闭：正常路径证明握手，错误路径只证明失败停止。"""
import argparse
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('qemu_close', Path(__file__).with_name('check-qemu-close.py'))
close = importlib.util.module_from_spec(spec)
spec.loader.exec_module(close)
reset = close.load('check-reset-router')
pins = reset.pins
demand = close.demand
CAPTURE = 'e14478bf6d35682e41f1a4fc0df90c8b4eef66fe389ac7ada0af93a10d5edf20'


def inspect_snapshots(record, error, node):
    phases = ['ready'] + (['after_error'] if error else []) + ['after_stop', 'before_quit']
    snapshots = record['snapshots']
    demand([row['phase'] for row in snapshots] == phases, '块设备生命周期快照缺失')
    times = [row['time_ns'] for row in snapshots]
    demand(all(type(t) is int and t > 0 for t in times) and times == sorted(set(times)), '快照时间无序')
    for row in snapshots:
        failed = error if node == 0 and row['phase'] != 'ready' else 0
        state = 'running' if row['phase'] in ('ready', 'after_error') else 'paused'
        if failed:
            state = 'io-error'
        demand(row['status'] == {'status': state, 'running': state == 'running'}, '错误停止状态被覆盖')
        demand(row['pins'] == [] and row['realized'] is True, '诊断空样本不能当作零引用或已销毁')
        blocks = row['blocks']
        demand(len(blocks) == 1 and blocks[0]['device'] == 'ssi-probe' and
               blocks[0]['io-status'] == {0: 'ok', 5: 'failed', 28: 'nospace'}[failed], '块层错误丢失')
        inserted = blocks[0]['inserted']
        demand(inserted['drv'] == 'raw' and inserted['image']['virtual-size'] == 67108864 and
               inserted['cache'] == {'no-flush': False, 'direct': False, 'writeback': True}, '实验盘或刷盘设置错误')
        queue = row['queue']
        demand(queue['name'] == 'virtio-blk' and queue['queue-index'] == 0 and
               queue['inuse'] == int(bool(failed)), '失败请求未保留或正常请求未完成')
        if node == 0:
            demand(queue['vring-desc'] > 0 and queue['last-avail-idx'] - queue['used-idx'] == int(bool(failed)),
                   '描述符状态与真实请求不一致')
        else:
            demand(queue['vring-desc'] == queue['vring-avail'] == queue['vring-used'] == 0,
                   '副节点意外使用了独立磁盘')
        demand({task['name'] for task in row['threads'] if task['name'].startswith('CPU ')} ==
               {f'CPU {cpu}/KVM' for cpu in range(4)}, '关闭前 vCPU 线程缺失')


def inspect(data):
    run = data['run']
    error = run['error']
    demand(error in (0, 5, 28) and run['action'] == 'quit' and run['pause_cycles'] == 0, '不是本轮关闭矩阵')
    demand(run['physical_nodes'] == ([1, 0] if error == 28 else [0, 1]), '实际实验 VM 角色错误')
    demand(run['runtime_sha256'] == close.RUNTIME and not run['errors'] and
           run['trace_exits'] == run['capture_exits'] == [0, 0] and
           not run['node0_remaining'] and not run['node1_remaining'], '运行身份采集或回收失败')
    demand(len(data['records']) == len(data['traces']) == len(data['host_logs']) == 2, '缺少双端记录')
    demand(data['firewall']['before'] == data['firewall']['after'], '临时防火墙未精确恢复')
    analyses = []
    for node, record in enumerate(data['records']):
        demand(record['schema'] == 1 and record['kernel'] == '7.1.0-rc3-sshpool-gvm-pf28' and
               record['node'] == node and record['pin_query'] == 'none', '块实验身份错误')
        demand(record['qemu_sha256'] == close.RUNTIME and record['capture_sha256'] == CAPTURE,
               '运行时或块采集器身份错误')
        demand(record['guest_kernel_sha256'] == '41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f' and
               record['initramfs_sha256'] == 'b32e4dccc48587ed4123a57d9c1bc80bdc3de2750b6d6182c19e3194772c2db7',
               '客体镜像身份错误')
        demand(record['injected_errno'] == (error if node == 0 else 0) and not record['errors'] and
               not record['forced_cleanup'] and record['qemu_exit'] == int(bool(error)), '错误退出或强制清理被掩盖')
        action = 'quit' if node == 0 else 'wait_exit'
        demand(record['actions'][-1]['request'] == {'op': action}, '不是主节点发起单次退出')
        elapsed = record['exit_observed_ns'] - record['actions'][-1]['time_ns']
        demand(0 < elapsed <= 31_000_000_000, '进程关闭超过三十秒期限及观测余量')
        pins.inspect_device_write(record, node, error)
        reset.inspect_qmp(record, {**run, 'reset_count': 0, 'crash': False}, node)
        inspect_snapshots(record, error, node)
        capture = data['traces'][node]
        demand(capture['qemu_pid'] == record['pid'], '跟踪的不是实际块设备进程')
        if error:
            rows = close.inspect_capture(capture, node)
            demand(not any(row['name'] in ('kc_close', 'kc_closed', 'kc_fence', 'kc_fenced') for row in rows),
                   '块错误不能声称执行正常关闭协议')
            roots = [row for row in rows if row['name'] == 'kc_root_done']
            demand(len(roots) == 1 and roots[0]['comm'] == f'kvm-dsm/{node}', '失败退出没有回收根线程')
            demand(not re.search(r'SSI_(?:QUIESCE_COMPLETE|DEVICE_|DRAIN_COMPLETE|CLOSE_PINS|KERNEL_CLOSE_)', record['stderr']),
                   '块层失败被伪装成正常设备关闭')
            demand(re.search(r'kvm_dsm_stop: node-' + str(node) + r' dsm root server exited with -(?:4|104)',
                             data['host_logs'][node]), '丢失故障销毁的原始内核日志')
        analyses.append({'node': node, 'exit': record['qemu_exit'], 'close_ms': elapsed / 1_000_000})
    result = None
    if not error:
        result = close.inspect({'result': {'qemu_sha256': run['runtime_sha256'],
                                'qemu_ssh_exits': [row['qemu_exit'] for row in data['records']],
                                'close_trace_exits': run['trace_exits']},
                                'qemu_stderr': [row['stderr'] for row in data['records']],
                                'host_logs': data['host_logs'], 'traces': data['traces']})
    return {'errno': error, 'nodes': analyses, 'global_close': result,
            'failed_io_preserved': bool(error), 'persistent_io_accepted': False, 'full_ssi_accepted': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.record.read_text())), indent=2))
