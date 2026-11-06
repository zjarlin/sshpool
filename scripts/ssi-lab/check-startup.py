#!/usr/bin/env python3
"""核对真实 Linux KVM 启用、重试与关闭记录，不仅检查最终通过标记。"""
import argparse
from pathlib import Path
import re


def validate(log):
    if 'STARTUP_ERROR' in log:
        raise ValueError('探针自身出错')
    starts = re.findall(r'STARTUP_BEGIN mode=(\w+) kernel=(\S+)', log)
    if len(starts) != 1:
        raise ValueError('缺少唯一实验起点')
    mode, kernel = starts[0]
    rows = re.findall(
        r'STARTUP_ENABLE case=(\w+) result=(-?\d+) errno=(\d+) expected_errno=(\d+)', log)
    actual = [(label, int(result), int(code), int(expected))
              for label, result, code, expected in rows]
    # 这些是被测 Linux 的 errno；运行检查器的 macOS 数值不同，不能混用。
    expected = {
        'occupied': [('occupied', -1, 98, 98), ('retry', 0, 0, 0)],
        'cycles': [('cycle', 0, 0, 0)] * 64,
        'invalid': [('empty', -1, 22, 22), ('node_outside_list', -1, 22, 22),
                    ('too_many', -1, 22, 22), ('bad_pointer', -1, 14, 14),
                    ('retry', 0, 0, 0)],
    }
    if mode not in expected or actual != expected[mode]:
        raise ValueError('启用返回值、错误码或失败后的重试不符合契约')
    if log.count('STARTUP_ENABLE') != len(actual):
        raise ValueError('启用记录被截断')
    closed = 64 if mode == 'cycles' else 1
    if log.count('STARTUP_CLOSE_BEGIN') != closed or log.count('STARTUP_CLOSE_DONE') != closed:
        raise ValueError('VM 关闭记录缺失或重复')
    cycles = re.findall(r'STARTUP_CYCLE index=(\d+) released=(\d+)', log)
    expected_cycles = [(str(i), '1') for i in range(64)] if mode == 'cycles' else []
    if cycles != expected_cycles or log.count('STARTUP_CYCLE') != len(cycles):
        raise ValueError('启停轮次或释放后的端口绑定证据不完整')
    if re.findall(r'STARTUP_RESULT passed=(\d+)', log) != ['1']:
        raise ValueError('最终结果缺失或失败')
    # 不能仅累计次数：关闭必须发生在启用后，释放证明必须发生在关闭后。
    sequence = [f'STARTUP_BEGIN mode={mode} kernel={kernel}']
    for index, (label, result, code, expected_code) in enumerate(expected[mode]):
        sequence.append(f'STARTUP_ENABLE case={label} result={result} '
                        f'errno={code} expected_errno={expected_code}')
        if mode == 'cycles':
            sequence.extend(['STARTUP_CLOSE_BEGIN', 'STARTUP_CLOSE_DONE',
                             f'STARTUP_CYCLE index={index} released=1'])
    if mode != 'cycles':
        sequence.extend(['STARTUP_CLOSE_BEGIN', 'STARTUP_CLOSE_DONE'])
    sequence.append('STARTUP_RESULT passed=1')
    observed = [line for line in log.splitlines() if 'STARTUP_' in line]
    if observed != sequence:
        raise ValueError('启动、关闭和释放证明的顺序或完整性不符合契约')
    return {'mode': mode, 'kernel': kernel, 'enable_checks': len(actual), 'closed_vms': closed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    try:
        result = validate(args.log.read_text(errors='replace'))
    except ValueError as error:
        raise SystemExit(f'失败：{error}') from error
    print(f"启动检查通过：{result['mode']}，{result['enable_checks']} 次启用检查，"
          f"{result['closed_vms']} 次 VM 关闭。")


if __name__ == '__main__':
    main()
