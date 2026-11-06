#!/usr/bin/env python3
"""用独立时间窗口复核跨 CPU RTC 读取，不替代长期漂移和中断验收。"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re

READ = re.compile(
    r'RTCPROBE_READ round=(\d+) cpu=(\d+) observed_cpu=(\d+) status=(-?\d+) errno=(\d+) '
    r'year=(-?\d+) month=(-?\d+) day=(-?\d+) hour=(-?\d+) minute=(-?\d+) second=(-?\d+)')


def inspect(log, reference):
    start = reference['started_realtime_ns']
    end = reference['finished_realtime_ns']
    if not 0 < start <= end or end - start > 700 * 1000000000:
        raise ValueError('独立时间窗口缺失或无效')
    clocks = reference['host_clock_samples']
    expected_nodes = {'control': {0}, 'pair': {0, 1}}.get(reference['mode'])
    if expected_nodes is None or {sample['node'] for sample in clocks} != expected_nodes or len(clocks) != len(expected_nodes):
        raise ValueError('缺少独立宿主时间采样或节点重复')
    for sample in clocks:
        before, after = sample['controller_before_ns'], sample['controller_after_ns']
        if not start <= before <= after <= end or not before - 1000000000 <= sample['host_realtime_ns'] <= after + 1000000000:
            raise ValueError('宿主时钟与控制端时间窗口不一致')
    records = [line.strip() for line in log.splitlines() if line.strip().startswith('RTCPROBE_')]
    if len(records) != 35 or records[0] != 'RTCPROBE_START cpus=4 rounds=8':
        raise ValueError('需要一次完整的四 CPU、八轮、32 次 RTC 读取记录')
    failures = Counter()
    probe_range_failures = 0
    calendar_failures = 0
    reference_failures = 0
    observations = []
    for index, line in enumerate(records[1:33]):
        match = READ.fullmatch(line)
        if match is None:
            raise ValueError('RTC 读取明细损坏或包含错误标记')
        round_number, cpu, observed_cpu, status, error, *calendar = map(int, match.groups())
        if (round_number, cpu) != (index // 4, (0, 2, 1, 3)[index % 4]) or observed_cpu != cpu:
            raise ValueError('RTC 轮次、CPU 亲和性或读取顺序不匹配')
        if status not in (-1, 0) or (status == 0) != (error == 0):
            raise ValueError('ioctl 返回值与 errno 不一致')
        # C 探针只检查字段范围；二月三十一日等错误由下方完整日历检查识别。
        ranges = ((2000, 2099), (1, 12), (1, 31), (0, 23), (0, 59), (0, 59))
        in_ranges = all(lower <= value <= upper for value, (lower, upper) in zip(calendar, ranges))
        if status != 0 or not in_ranges:
            probe_range_failures += 1
        try:
            value = datetime(*calendar, tzinfo=timezone.utc)
            valid_calendar = 2000 <= value.year <= 2099
        except ValueError:
            value = None
            valid_calendar = False
        calendar_valid = status == 0 and valid_calendar
        if not calendar_valid:
            calendar_failures += 1
        # RTC 分辨率为秒；给启动、采样和网络传输保留两秒边界。
        in_window = calendar_valid and start - 2000000000 <= int(value.timestamp()) * 1000000000 <= end + 2000000000
        if calendar_valid and not in_window:
            reference_failures += 1
        valid = calendar_valid and in_window
        if not valid:
            failures[str(cpu)] += 1
        observations.append({'round': round_number, 'cpu': cpu, 'status': status, 'errno': error,
                             'calendar': calendar, 'calendar_valid': calendar_valid,
                             'within_reference_window': bool(in_window), 'valid': valid})
    count = sum(failures.values())
    if records[33] != f'RTCPROBE_RESULT reads=32 failures={probe_range_failures}':
        raise ValueError('RTC 汇总失败数与实际明细不一致')
    if records[34] != f'RTCPROBE_EXIT status={int(probe_range_failures != 0)}':
        raise ValueError('RTC 退出状态与实际明细不一致')
    return {'reads': len(observations), 'failures': count, 'probe_range_failures': probe_range_failures,
            'calendar_failures': calendar_failures,
            'reference_failures': reference_failures, 'failures_by_cpu': dict(failures),
            'observations': observations,
            'scope': 'RTC ioctl and calendar checks against sampled host/controller wall-clock bounds with 2s tolerance; not subsecond accuracy, interrupt delivery or long-term drift.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--reference', type=Path, required=True, help='实验驱动记录的控制端窗口与独立宿主采样 JSON')
    parser.add_argument('--expect-failures', type=int, default=0)
    args = parser.parse_args()
    try:
        if not 0 <= args.expect_failures <= 32:
            raise ValueError('预期失败数必须在 0 到 32 之间')
        report = inspect(args.log.read_text(errors='replace'), json.loads(args.reference.read_text()))
        if report['failures'] != args.expect_failures:
            raise ValueError(f"实际 {report['failures']} 次失败，与预期 {args.expect_failures} 不符")
    except ValueError as error:
        raise SystemExit('失败：' + str(error)) from error
    print(f"记录完整：32 次读取，{report['failures']} 次失败；不代表完整 RTC 或 SSI 验收。")


if __name__ == '__main__':
    main()
