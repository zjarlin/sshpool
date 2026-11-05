#!/usr/bin/env python3
"""只在指定研究内核创建无 vCPU、无磁盘的 KVM 实例，验证 DSM 设备写入与脏页位图。"""
import argparse
import ctypes
import errno
import fcntl
import mmap
import os
import platform
import socket
import struct

PAGE = 4096
KVM_CREATE_VM = 0xAE01
KVM_CHECK_EXTENSION = 0xAE03
KVM_SET_USER_MEMORY_REGION = 0x4020AE46
KVM_GET_DIRTY_LOG = 0x4010AE42
KVM_ENABLE_CAP = 0x4068AEA3
KVM_CAP_DIRTY_LOG_RING = 192
KVM_CAP_X86_DSM = 249
DSM_ENABLE = 0x4010AEF0
DSM_MEMCPY = 0x4020AEF1


def enable_dsm(vm):
    """仅有回环节点零，不联系其他设备，地址数组存活到 ioctl 返回。"""
    address = ctypes.create_string_buffer(b'127.0.0.1')
    peers = (ctypes.c_void_p * 1)(ctypes.addressof(address))
    fcntl.ioctl(vm, DSM_ENABLE, struct.pack('=IIQ', 0, 1, ctypes.addressof(peers)))


def enable_ring(vm):
    capability = struct.pack('=II4Q64s', KVM_CAP_DIRTY_LOG_RING, 0, PAGE, 0, 0, 0, b'')
    fcntl.ioctl(vm, KVM_ENABLE_CAP, capability)


def expected_error(operation, expected):
    try:
        operation()
    except OSError as error:
        if error.errno == expected:
            return
        raise AssertionError(f'错误码为 {error.errno}，预期 {expected}') from error
    raise AssertionError(f'操作意外成功，预期错误码 {expected}')


def read_dirty(vm):
    bitmap = ctypes.c_uint64(0)
    request = struct.pack('=IIQ', 0, 0, ctypes.addressof(bitmap))
    fcntl.ioctl(vm, KVM_GET_DIRTY_LOG, request)
    return bitmap.value


def copy_request(write, guest, source, length):
    # ABI 中 bool 后有七字节对齐；write=true 表示用户缓冲区写入客体。
    return struct.pack('=?7xQQQ', write, guest, source, length)


def device_write(vm, memory):
    enable_dsm(vm)
    address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
    region = struct.pack('=IIQQQ', 0, 1, 0x100000, PAGE * 3, address)
    fcntl.ioctl(vm, KVM_SET_USER_MEMORY_REGION, region)
    read_dirty(vm)
    source = ctypes.create_string_buffer(bytes(range(32)))
    request = copy_request(True, address + PAGE - 16, ctypes.addressof(source), 32)
    fcntl.ioctl(vm, DSM_MEMCPY, request)
    if memory[PAGE - 16:PAGE + 16] != bytes(range(32)):
        raise AssertionError('跨页写入内容不一致')
    dirty = read_dirty(vm)
    if dirty != 0b11:
        raise AssertionError(f'跨页写入的 dirty bitmap 为 {dirty:#b}，预期 0b11')
    target = ctypes.create_string_buffer(32)
    request = copy_request(False, address + PAGE - 16, ctypes.addressof(target), 32)
    fcntl.ioctl(vm, DSM_MEMCPY, request)
    if target.raw != bytes(range(32)) or read_dirty(vm) != 0:
        raise AssertionError('读取内容不一致或只读操作意外标脏')
    request = copy_request(True, address + PAGE * 2, ctypes.addressof(source), 32)
    fcntl.ioctl(vm, DSM_MEMCPY, request)
    if memory[PAGE * 2:PAGE * 2 + 32] != bytes(range(32)) or read_dirty(vm) != 0b100:
        raise AssertionError('单页内容或脏页位图不一致')
    request = copy_request(True, address, 1, 1)
    expected_error(lambda: fcntl.ioctl(vm, DSM_MEMCPY, request), errno.EFAULT)
    request = copy_request(True, address, 1, 0)
    fcntl.ioctl(vm, DSM_MEMCPY, request)
    request = copy_request(True, (1 << 64) - 1, 1, 2)
    expected_error(lambda: fcntl.ioctl(vm, DSM_MEMCPY, request), errno.EINVAL)


def slot_remove(vm, memory):
    enable_dsm(vm)
    address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
    # 从奇数 GFN 起步，删除和重建同时覆盖活动及备份反向映射。
    region = struct.pack('=IIQQQ', 0, 0, 0x101000, PAGE * 3, address)
    empty = struct.pack('=IIQQQ', 0, 0, 0x101000, 0, address)
    for _ in range(2):
        fcntl.ioctl(vm, KVM_SET_USER_MEMORY_REGION, region)
        fcntl.ioctl(vm, KVM_SET_USER_MEMORY_REGION, empty)


def alias_remove(vm, memory):
    enable_dsm(vm)
    address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
    # 同一用户映射对应两个客体地址，覆盖链表形式的反向映射及销毁。
    primary = struct.pack('=IIQQQ', 0, 0, 0x100000, PAGE * 3, address)
    alias = struct.pack('=IIQQQ', 1, 0, 0x201000, PAGE * 3, address)
    empty = struct.pack('=IIQQQ', 1, 0, 0x201000, 0, address)
    fcntl.ioctl(vm, KVM_SET_USER_MEMORY_REGION, primary)
    fcntl.ioctl(vm, KVM_SET_USER_MEMORY_REGION, alias)
    fcntl.ioctl(vm, KVM_SET_USER_MEMORY_REGION, empty)
    fcntl.ioctl(vm, KVM_SET_USER_MEMORY_REGION, alias)


def ring_before_dsm(vm, _memory):
    enable_ring(vm)
    expected_error(lambda: enable_dsm(vm), errno.EOPNOTSUPP)


def dsm_before_ring(vm, _memory):
    enable_dsm(vm)
    expected_error(lambda: enable_ring(vm), errno.EOPNOTSUPP)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    args = parser.parse_args()
    if platform.machine() != 'x86_64' or platform.release() != args.require_kernel:
        raise SystemExit('实际架构或内核与显式指定的研究目标不一致')
    # 拒绝与已运行的 DSM 客体争抢监听端口。
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 37710))
    failures = 0
    with open('/dev/kvm', 'r+b', buffering=0) as kvm:
        for capability in (KVM_CAP_X86_DSM, KVM_CAP_DIRTY_LOG_RING):
            if fcntl.ioctl(kvm, KVM_CHECK_EXTENSION, capability) <= 0:
                raise SystemExit(f'缺少本测试所需 KVM capability {capability}')
        for operation in (device_write, slot_remove, alias_remove, ring_before_dsm, dsm_before_ring):
            print(f'DEVICE_PROBE_BEGIN case={operation.__name__}', flush=True)
            with mmap.mmap(-1, PAGE * 3) as memory:
                vm = fcntl.ioctl(kvm, KVM_CREATE_VM, 0)
                passed = False
                try:
                    operation(vm, memory)
                    passed = True
                except (OSError, AssertionError) as error:
                    failures += 1
                    print(f'DEVICE_PROBE_FAIL case={operation.__name__} error={error}', flush=True)
                finally:
                    # 保持用户映射存活到 VM 销毁；退出卡死不能提前输出通过。
                    print(f'DEVICE_PROBE_CLOSE case={operation.__name__}', flush=True)
                    os.close(vm)
                if passed:
                    print(f'DEVICE_PROBE_PASS case={operation.__name__}', flush=True)
    print(f'DEVICE_PROBE_EXIT failures={failures}', flush=True)
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
