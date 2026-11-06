"""SSI 准入探针：只创建临时空 KVM 对象，读取能力和时钟，不执行客体或访问磁盘。"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import time


def collect():
    report = {
        'schema': 1,
        'collected_unix_ns': time.time_ns(),
        'system': platform.system(),
        'arch': platform.machine(),
        'kernel': platform.release(),
        'machine_id_sha256': '',
        'logical_cpus': os.cpu_count() or 0,
        'memory_bytes': 0,
        'api_version': 0,
        'get_tsc_khz': 0,
        'tsc_control': 0,
        'adjust_clock': 0,
        'tsc_adjust': False,
        'vcpus': [],
        'closed_fds': 0,
        'errors': [],
    }
    if report['system'] != 'Linux' or report['arch'] != 'x86_64':
        report['errors'].append('此实验运行时需要 x86_64 Linux KVM')
        return report
    descriptors = []
    try:
        identity = Path('/etc/machine-id').read_text().strip()
        if len(identity) != 32 or any(c not in '0123456789abcdef' for c in identity):
            raise ValueError('machine-id 缺失或格式错误，不能排除重复 SSH 别名')
        report['machine_id_sha256'] = hashlib.sha256(identity.encode()).hexdigest()
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemTotal:'):
                report['memory_bytes'] = int(line.split()[1]) * 1024
        kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
        descriptors.append(kvm)
        report['api_version'] = fcntl.ioctl(kvm, 0xae00, 0)
        if report['api_version'] != 12:
            raise ValueError('只支持已核验的 KVM API 12')
        for name, capability in (('get_tsc_khz', 61), ('tsc_control', 60), ('adjust_clock', 39)):
            report[name] = fcntl.ioctl(kvm, 0xae03, capability)
        # 查询 KVM 可提供给客体的 CPUID，不用宿主 /proc/cpuinfo 推断客体能力。
        cpuid = bytearray(8 + 256 * 40)
        struct.pack_into('<II', cpuid, 0, 256, 0)
        fcntl.ioctl(kvm, 0xc008ae05, cpuid)
        count = struct.unpack_from('<I', cpuid)[0]
        if count > 256:
            raise ValueError('CPUID 返回条目超出缓冲区')
        for offset in range(8, 8 + count * 40, 40):
            leaf, index, flags, eax, ebx, ecx, edx = struct.unpack_from('<7I', cpuid, offset)
            if leaf == 7 and index == 0:
                report['tsc_adjust'] = bool(ebx & (1 << 1))
        vm = fcntl.ioctl(kvm, 0xae01, 0)
        descriptors.append(vm)
        for index in range(2):
            vcpu = fcntl.ioctl(vm, 0xae41, index)
            descriptors.append(vcpu)
            frequency = fcntl.ioctl(vcpu, 0xaea3, 0)
            # HAS_DEVICE_ATTR 仅核对偏移接口存在；不设置任何 TSC 偏移或频率。
            attribute = struct.pack('<IIQQ', 0, 0, 0, 0)
            fcntl.ioctl(vcpu, 0x4018aee3, attribute)
            clock = bytearray(48)
            fcntl.ioctl(vm, 0x8030ae7c, clock)
            value, flags, realtime, host_tsc = struct.unpack('<QI4xQQ16x', clock)
            report['vcpus'].append({
                'index': index, 'tsc_khz': frequency, 'offset_supported': True,
                'clock': value, 'clock_flags': flags, 'realtime': realtime, 'host_tsc': host_tsc,
            })
    except (OSError, ValueError) as error:
        report['errors'].append(str(error))
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
                report['closed_fds'] += 1
            except OSError as error:
                report['errors'].append(str(error))
    return report


if __name__ == '__main__':
    print(json.dumps(collect(), ensure_ascii=False))
