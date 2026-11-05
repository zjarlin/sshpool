#!/usr/bin/env python3
"""核查跨 CPU 时钟探针的完整记录，不代替启动告警和长期漂移检查。"""
import argparse
from pathlib import Path
import re

SAMPLE = re.compile(
    r'CLOCK_SAMPLE round=(\d+) cpu=(\d+) tsc=(\d+) mono=(\d+) raw=(\d+) boot=(\d+)')
TIMER = re.compile(r'CLOCK_TIMER cpu=(\d+) requested_ns=(\d+) elapsed_ns=(\d+)')


def validate(log):
    records = [line.strip() for line in log.splitlines() if line.strip().startswith('CLOCK_')]
    if len(records) != 38:
        raise ValueError('需要唯一一次完整探针：32 次采样、4 次定时器与开始结束标记')
    if records[0] != 'CLOCK_START online_cpus=4 rounds=8':
        raise ValueError('需要四 CPU 和八轮采样')
    if records[-1] != 'CLOCK_PASS cpus=4 samples=32 timers=4':
        raise ValueError('探针没有完整通过')
    previous = [0, 0, 0, 0]
    position = 1
    for round_number in range(8):
        for cpu in (0, 2, 1, 3):
            sample = SAMPLE.fullmatch(records[position])
            position += 1
            if sample is None:
                raise ValueError('采样记录损坏或出现错误标记')
            actual_round, actual_cpu, *values = map(int, sample.groups())
            if (actual_round, actual_cpu) != (round_number, cpu):
                raise ValueError('轮次或跨 CPU 顺序不完整')
            if any(now <= 0 or now < before for now, before in zip(values, previous)):
                raise ValueError('TSC 或应用时钟倒退/读数无效')
            previous = values
            if round_number == 7:
                timer = TIMER.fullmatch(records[position])
                position += 1
                if timer is None:
                    raise ValueError('缺少对应 CPU 的定时器记录')
                actual_cpu, requested, elapsed = map(int, timer.groups())
                if actual_cpu != cpu or requested != 20_000_000 or elapsed < requested:
                    raise ValueError('定时器 CPU 不匹配或提前到期')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    try:
        validate(args.log.read_text(errors='replace'))
    except ValueError as error:
        raise SystemExit(f'失败：{error}') from error
    print('时钟采样通过：四 CPU、32 次采样、四次定时器；不证明长期同步和频率一致。')


if __name__ == '__main__':
    main()
