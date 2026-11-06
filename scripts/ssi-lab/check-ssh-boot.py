#!/usr/bin/env python3
"""检查 SSH 客体启动日志；通过仅代表启动门槛，不代替双节点执行与文件传输验收。"""
import argparse
from pathlib import Path
import re


def check_errors(log):
    """QEMU 的推荐核数提示不等于内核告警；其他匹配错误都保留。"""
    log = re.sub(
        r'^(?:qemu[^:\r\n]*:)?[ \t]*warning: Number of (?:SMP cpus|hotpluggable cpus) requested '
        r'\(\d+\) exceeds the recommended cpus supported by KVM \(\d+\)\r?$',
        '', log, flags=re.MULTILINE)
    failures = (
        r'WARNING:', r'BUG:', r'Kernel panic', r'Oops:',
        r'soft lockup', r'hard LOCKUP', r'blocked for more than',
        r'rcu.*(?:detected stalls|self-detected stall)',
        r'TSC warp', r'Marking TSC unstable',
        r'hctosys: unable to read the hardware clock',
        r'RTC time:.*date: (?:\d{4}-00-\d{2}|\d{4}-\d{2}-00)',
        r'Lost \d+ RTC interrupts',
        r'Long readout interval, skipping watchdog check',
        r'Failed to (?:disable|set MAC)', r'EEPROM Checksum Is Not Valid',
        r'KVM_DSM_\w+ failed', r'access mismatch',
        r'failed to handle page fault', r'ktcp_receive.*error',
        r'kvm-dsm:.*failed with -\d+', r'error: kvm run failed',
        r'dsm.*exited (?:server loop, error|with) -\d+',
        r'Failed to synchronize CPU state', r'segfault|segmentation fault',
        r'dumped core', r'Distributed KVM failure; terminating this node',
        r'virtio: .*failed', r'RTNETLINK answers:',
    )
    for pattern in failures:
        if re.search(pattern, log, re.IGNORECASE):
            raise ValueError(f'启动日志存在未解决错误：{pattern}')


def validate(log):
    """拒绝带严重内核、时钟、网络或 DSM 错误的就绪记录。"""
    check_errors(log)
    kernels = re.findall(r'Linux version (\S+)', log)
    ready = re.findall(r'SSH_GUEST_READY kernel=(\S+) cpus=(\d+)', log)
    if len(kernels) != 1 or ready != [(kernels[0], '4')]:
        raise ValueError('需要同一次启动、匹配内核版本且四 CPU 在线的唯一就绪记录')
    listening = 'Server listening on 0.0.0.0 port 22.'
    if log.count(listening) != 1 or log.index(listening) < log.index('SSH_GUEST_READY'):
        raise ValueError('需要就绪之后唯一的 OpenSSH 监听记录')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('serial_log', type=Path)
    parser.add_argument('--host-log', type=Path, action='append', default=[],
                        help='可重复传入两节点本轮宿主日志；不会替代人工核查日志完整性')
    args = parser.parse_args()
    try:
        validate(args.serial_log.read_text(errors='replace'))
        for path in args.host_log:
            check_errors(path.read_text(errors='replace'))
    except ValueError as error:
        raise SystemExit(f'失败：{error}') from error
    print('启动日志门槛通过；仍需 SSH、双节点执行、SFTP 和正常关机的独立证据。')


if __name__ == '__main__':
    main()
