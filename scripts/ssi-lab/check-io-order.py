#!/usr/bin/env python3
"""核验四 CPU 的真实 EDU 寄存器顺序测试，不把客体关机等同于通过。"""
import argparse
from pathlib import Path
import re


def inspect(log):
    if 'IORDER_ERROR' in log:
        raise ValueError('客体探针自身失败')
    if re.findall(r'IORDER_START cpus=(\d+) rounds=(\d+) device_id=([0-9a-f]+)', log) != [
            ('4', '64', '010000ed')]:
        raise ValueError('需要唯一一次四 CPU、64 轮、真实 EDU 设备的记录')
    rounds = [tuple(map(int, row)) for row in re.findall(
        r'IORDER_ROUND round=(\d+) checks=(\d+) failures=(\d+)', log)]
    if [(r, c) for r, c, _ in rounds] != [(r, (r + 1) * 4) for r in range(64)]:
        raise ValueError('缺少轮次或检查计数不匹配')
    threads = re.findall(r'IORDER_THREAD requested_cpu=(\d+) observed_cpu=(\d+)', log)
    if sorted(threads) != [(str(cpu), str(cpu)) for cpu in range(4)]:
        raise ValueError('线程 CPU 覆盖不完整')
    mismatches = re.findall(
        r'IORDER_MISMATCH round=(\d+) cpu=(\d+) check=(\d+) expected=([0-9a-f]{8}) observed=([0-9a-f]{8})', log)
    if log.count('IORDER_MISMATCH') != len(mismatches):
        raise ValueError('失败明细被截断或混入其他输出')
    seen = set()
    failures_by_round = [0] * 64
    for round_text, cpu_text, check_text, expected, observed in mismatches:
        round_number, cpu, check = int(round_text), int(cpu_text), int(check_text)
        if not 0 <= cpu < 4 or not 0 <= round_number < 64 or check // 4 != round_number:
            raise ValueError('失败记录的 CPU、轮次或编号无效')
        if check in seen or expected == observed:
            raise ValueError('失败记录重复或实际上没有差异')
        seen.add(check)
        failures_by_round[round_number] += 1
    total = 0
    for round_number, _, reported in rounds:
        total += failures_by_round[round_number]
        if total != reported:
            raise ValueError('失败明细与每轮累计数量不一致')
    final = re.findall(r'IORDER_FINAL_MISMATCH expected=([0-9a-f]{8}) observed=([0-9a-f]{8})', log)
    if log.count('IORDER_FINAL_MISMATCH') != len(final):
        raise ValueError('最后一次读回记录被截断')
    if len(final) > 1 or any(expected == observed for expected, observed in final):
        raise ValueError('最后一次读回记录无效')
    total += len(final)
    if re.findall(r'IORDER_RESULT checks=(\d+) failures=(\d+) expected_checks=(\d+)', log) != [
            ('256', str(total), '256')]:
        raise ValueError('缺少唯一完整结果或失败总数不一致')
    if re.findall(r'IORDER_EXIT status=(\d+)', log) != [str(int(total != 0))]:
        raise ValueError('退出标记与实际结果不一致')
    return {'checks': 256, 'failures': total}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.log.read_text(errors='replace'))
    except ValueError as error:
        raise SystemExit(f'证据不完整：{error}') from error
    print(f"设备顺序检查：{result['checks']} 次，失败 {result['failures']} 次。")
    raise SystemExit(int(result['failures'] != 0))


if __name__ == '__main__':
    main()
