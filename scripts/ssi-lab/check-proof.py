#!/usr/bin/env python3
"""核验客体串口中的同进程结果；节点侧执行记录仍需单独核对。"""
import argparse
import re
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('serial_log', type=Path)
args = parser.parse_args()
log = args.serial_log.read_text(errors='replace')
if 'PROOF_ERROR' in log:
    raise SystemExit('失败：客体报告 PROOF_ERROR')

starts = re.findall(r'PROOF_START pid=(\d+) online_cpus=(\d+) bytes=(\d+)', log)
if len(starts) != 1 or starts[0][1:] != ('4', '33554432'):
    raise SystemExit('失败：需要一次完整的四 CPU、32 MiB 测试')
pid = starts[0][0]
threads = re.findall(
    r'PROOF_THREAD pid=(\d+) tid=(\d+) requested_cpu=(\d+) observed_cpu=(\d+) checksum=(\d+)', log)
if len(threads) != 4 or len({thread[1] for thread in threads}) != 4:
    raise SystemExit('失败：需要四个不同线程')
if {thread[2] for thread in threads} != {'0', '1', '2', '3'}:
    raise SystemExit('失败：CPU 覆盖不完整')

# 这里只复核日志中的固定参考结果；客体自身还逐字校验实际共享内存。
checksums = {
    '0': '9881296914831760266',
    '1': '14269900721331050332',
    '2': '5704288491290152150',
    '3': '5860889749692592215',
}
for process, _, requested, observed, checksum in threads:
    if process != pid or requested != observed or checksum != checksums[requested]:
        raise SystemExit('失败：PID、CPU 亲和性或计算结果不匹配')
if re.findall(r'PROOF_PASS cpus=(\d+) shared_counter=(\d+) memory_verified_bytes=(\d+)', log) != [
    ('4', '512', '33554432')
]:
    raise SystemExit('失败：共享内存或原子计数未通过')
if re.findall(r'PROOF_EXIT status=(\d+)', log) != ['0']:
    raise SystemExit('失败：缺少正常测试退出记录')
print('客体结果通过：同一 PID、四个 CPU、32 MiB 校验、原子计数 512；仍须核对双节点执行证据。')
