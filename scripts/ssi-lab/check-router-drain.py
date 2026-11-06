#!/usr/bin/env python3
"""核对真实 QEMU 关闭屏障；路由排空不代表 DSM 关闭或磁盘持久化完成。"""
import argparse
import json
from pathlib import Path
import re
import struct


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def inspect(data):
    result = data['result']
    demand(not any(result.get(name) for name in ('harness_error', 'management_timeout', 'host_log_timeout', 'samples_errors')),
           '实验管理或日志采集没有完成')
    logs = data['qemu_stderr']
    demand(len(logs) == 2, '需要两个真实 QEMU 的 stderr')
    mode = data['mode']
    demand(mode in ('pair', 'invalid', 'early'), '未知实验场景')
    combined = '\n'.join(logs + data['host_logs'])
    demand(not re.search(r'segfault|segmentation fault|dumped core|HARNESS_TIMEOUT|terminating on signal', combined, re.I),
           '存在崩溃或强制终止')
    if mode != 'pair':
        demand(result['phases'].get('inject-router', {}).get('exit') == 0 and
               result.get('router_injection') == mode and result['qemu_ssh_exits'] == [1, 1],
               '没有完整注入和两端明确失败退出')
        demand(not any('poweroff' in name for name in result['phases']), '注入混入人工关机')
        injection = json.loads(data['injection_log'])
        version = 2 if mode == 'invalid' else 3
        demand(bytes.fromhex(injection['frame_hex']) == struct.pack('>HiIIIQ', 17, -1, version, 1, 0, 41789),
               '注入不是指定的完整排空帧')
        demand(injection['result'] in ('eof', 'error'), '注入连接未失败')
        if injection['result'] == 'error':
            demand(injection['errno'] in (32, 104), '未证明连接关闭或复位')
        demand(not any('SSI_DRAIN_' in text for text in logs), '尚未本地排空却出现确认或完成记录')
        expected_error = 'SSI invalid drain marker' if mode == 'invalid' else 'SSI local quiescence deadline expired'
        demand(expected_error in logs[0], '真实接收端没有返回指定错误')
        if mode == 'early':
            demand(injection['early_state'] == {'waiting': True}, '本地未排空时过早发送确认')
            demand(14000000000 <= injection['elapsed_ns'] <= 20000000000, '截止时间没有在预期窗口内生效')
        return {'outcome': 'invalid_marker_rejected' if mode == 'invalid' else 'early_marker_waited_then_failed',
                'kernel_shutdown_accepted': False, 'persistent_io_accepted': False}

    demand(result['qemu_ssh_exits'] == [0, 0], '排空正常对照没有两端成功退出')
    demand(result['phases'].get('poweroff', {}).get('exit') == 255 and
           'reboot: Power down' in data['serial_log'], '缺少同次客体关机记录')
    demand(not result.get('router_injection') and not result.get('fault_sent'), '正常关闭混入故障注入')
    demand(not re.search(r'SSI (?:invalid|duplicate|missing|router |local quiescence|drain |shutdown )|error: kvm run failed', '\n'.join(logs)),
           '路由或执行错误不能通过排空验收')
    nonces = {}
    events = []
    for node, text in enumerate(logs):
        rows = [row for row in text.splitlines() if row.startswith('SSI_DRAIN_')]
        demand(len(rows) == 4, '排空记录缺失或重复')
        local = re.fullmatch(r'SSI_DRAIN_LOCAL node=(\d+) stopped=(\d+) nonce=(\d+)', rows[0])
        demand(local is not None, '本地停止记录必须最先出现')
        local_node, stopped, nonce = map(int, local.groups())
        demand(local_node == node and stopped == 4 and nonce > 0, '节点或停止的 CPU 数量错误')
        demand(rows[-1] == f'SSI_DRAIN_COMPLETE node={node} peers=1', '完成必须晚于双向确认')
        nonces[node] = nonce
        directions = set()
        for row in rows[1:3]:
            match = re.fullmatch(r'SSI_DRAIN_ACK_(SENT|RECEIVED) node=(\d+) peer=(\d+) nonce=(\d+)', row)
            demand(match is not None, '确认日志格式不符')
            direction, local_node, peer, reply_nonce = match.groups()
            demand(direction not in directions and int(local_node) == node and int(peer) == 1 - node,
                   '确认重复或对端身份不符')
            directions.add(direction)
            events.append((direction, node, int(peer), int(reply_nonce)))
        demand(directions == {'SENT', 'RECEIVED'}, '不是完整双向确认')
    for direction, node, peer, nonce in events:
        owner = peer if direction == 'SENT' else node
        demand(nonce == nonces[owner], '两端确认的关闭序号不一致')
    return {'outcome': 'router_drained', 'nodes': 2, 'stopped_cpus_per_process': 4,
            'kernel_shutdown_accepted': False, 'persistent_io_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.record.read_text()))))


if __name__ == '__main__':
    main()
