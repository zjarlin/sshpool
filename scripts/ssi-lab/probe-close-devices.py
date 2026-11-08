#!/usr/bin/env python3
"""复用真实块设备客体采集，在独占 PF28 上验证全局关闭候选。"""
import importlib.util
import os
from pathlib import Path
import platform
import sys


def main():
    if platform.machine() != 'x86_64' or platform.release() != '7.1.0-rc3-sshpool-gvm-pf28':
        raise SystemExit('仅用于独占 PF28 x86 实验节点')
    if '--pin-query' not in sys.argv or sys.argv[sys.argv.index('--pin-query') + 1] != 'none':
        raise SystemExit('普通关闭候选不含 HMP 固定引用诊断入口')
    # 原 PF24 采集源码绑定历史证据；复用真实客体、QMP 和块层观测，只切换研究内核。
    source = Path(__file__).with_name('probe-virtio-dsm-pins.py')
    spec = importlib.util.spec_from_file_location('device_capture', source)
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    capture.RESEARCH = '7.1.0-rc3-sshpool-gvm-pf28'
    os.environ['SSHPOOL_LAB_GLOBAL_CLOSE'] = '1'
    capture.main()


if __name__ == '__main__':
    main()
