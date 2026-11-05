#!/usr/bin/env python3
"""核验反复换写入方的客体日志；宿主执行归属与内核日志必须另行核对。"""
import argparse
import re
from pathlib import Path


def validate(log):
    """要求完整的两次分配、每次八轮校验，拒绝残缺或重复的成功记录。"""
    if 'STRESS_ERROR' in log:
        raise ValueError('客体报告 STRESS_ERROR')
    # 串口允许 printk 插入用户态的一行中间。只移走已知的完整诊断行，
    # 保留原始日志；拼回后仍要求每个轮次、计数和线程字段完整匹配。
    log = re.sub(
        r'\[\s*\d+\.\d+\] workqueue: [A-Za-z0-9_]+ hogged CPU for >\d+us \d+ times, consider switching to WQ_UNBOUND\r?\n',
        '', log)
    starts = re.findall(
        r'STRESS_START pid=(\d+) online_cpus=(\d+) bytes=(\d+) rounds=(\d+) allocations=(\d+)', log)
    if len(starts) != 1 or starts[0][1:] != ('4', '4194304', '8', '2'):
        raise ValueError('需要一次完整的四 CPU、4 MiB、两次分配测试')
    pid = starts[0][0]
    rounds = re.findall(r'STRESS_ROUND allocation=(\d+) round=(\d+) counter=(\d+)', log)
    expected_rounds = [(str(a), str(r), str((r + 1) * 512)) for a in range(2) for r in range(8)]
    if rounds != expected_rounds:
        raise ValueError('轮次缺失、重复、顺序错误或原子计数不匹配')
    threads = re.findall(
        r'STRESS_THREAD allocation=(\d+) pid=(\d+) tid=(\d+) requested_cpu=(\d+) observed_cpu=(\d+)', log)
    if len(threads) != 8:
        raise ValueError('每次分配都需要四个线程的执行记录')
    for allocation in ('0', '1'):
        group = [thread for thread in threads if thread[0] == allocation]
        if len(group) != 4 or len({thread[2] for thread in group}) != 4:
            raise ValueError('线程数或线程身份重复')
        if {thread[3] for thread in group} != {'0', '1', '2', '3'}:
            raise ValueError('CPU 覆盖不完整')
        if any(process != pid or requested != observed for _, process, _, requested, observed in group):
            raise ValueError('PID 或 CPU 亲和性不匹配')
    passes = re.findall(
        r'STRESS_PASS cpus=(\d+) rounds=(\d+) allocations=(\d+) counter_per_allocation=(\d+) bytes=(\d+)', log)
    if passes != [('4', '8', '2', '4096', '4194304')]:
        raise ValueError('缺少唯一的完整通过记录')
    if re.findall(r'STRESS_EXIT status=(\d+)', log) != ['0']:
        raise ValueError('缺少正常退出记录')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('serial_log', type=Path)
    args = parser.parse_args()
    try:
        validate(args.serial_log.read_text(errors='replace'))
    except ValueError as error:
        raise SystemExit(f'失败：{error}') from error
    print('客体压力测试通过：四 CPU、两次分配、每次八轮读写、每次原子计数 4096。')


if __name__ == '__main__':
    main()
