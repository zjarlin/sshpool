#!/usr/bin/env python3
"""只读采集指定实验 VM 的资源限额和 ESXi 调度计数；不修改任何配置。"""
import argparse
from datetime import datetime, timezone
import getpass
import json
from pathlib import Path
import ssl

COUNTERS = {'cpu.ready.summation', 'cpu.maxlimited.summation', 'cpu.costop.summation',
            'cpu.usage.average', 'cpu.usagemhz.average'}


def allocation(value):
    """保留资源分配语义，避免只看客体 nproc 而遗漏管理层限速。"""
    return {'limit': value.limit, 'reservation': value.reservation,
            'expandable_reservation': value.expandableReservation,
            'shares': {'level': str(value.shares.level), 'shares': value.shares.shares}}


def assess(report):
    """保守判定：缺指标、有限额或窗口内曾限速均不能作为未限速性能基线。"""
    blockers = []
    if not report['nodes']:
        return ['没有实验节点']
    for node in report['nodes']:
        label = node['moid']
        if node['cpu']['limit'] != -1:
            blockers.append(f"{label}: VM CPU limit={node['cpu']['limit']} MHz")
        if node['memory']['limit'] != -1 and node['memory']['limit'] < node['memory_mb']:
            blockers.append(f"{label}: VM memory limit={node['memory']['limit']} MiB")
        if not node['resource_pools']:
            blockers.append(f'{label}: 缺少资源池层级')
        for pool in node['resource_pools']:
            # 根资源池由 ESXi 汇报主机可用总量，不能把它误认成管理员施加的子池限额。
            if pool['is_root']:
                continue
            for kind in ('cpu', 'memory'):
                if pool[kind]['limit'] != -1:
                    blockers.append(f"{label}: resource pool {pool['moid']} {kind} limit={pool[kind]['limit']}")
        samples = node['performance']
        if not samples:
            blockers.append(f'{label}: 缺少实时性能样本')
        for sample in samples:
            intervals, values = sample['intervals'], sample['values']
            names = [row['counter'] for row in values]
            if set(names) != COUNTERS or len(names) != len(COUNTERS) or not intervals:
                blockers.append(f'{label}: 性能指标集合不完整')
                continue
            stamps = [datetime.fromisoformat(row['timestamp']) for row in intervals]
            if any(stamp.tzinfo is None for stamp in stamps):
                blockers.append(f'{label}: 性能时间缺少时区')
                continue
            if any(a >= b for a, b in zip(stamps, stamps[1:])) or any(row['interval'] != 20 for row in intervals):
                blockers.append(f'{label}: 性能时间窗口错误')
            for row in values:
                numbers = row['values']
                if row.get('instance') != '' or len(numbers) != len(intervals) or any(n < 0 for n in numbers):
                    blockers.append(f"{label}: 指标 {row['counter']} 有缺失样本")
                if row['counter'] == 'cpu.maxlimited.summation' and any(n > 0 for n in numbers):
                    blockers.append(f'{label}: 采样窗口包含 CPU 限速')
    return blockers


def collect(service, vm_ids, annotation, max_samples):
    """按明确的 MoID 和归属注解双重限定读取目标，记录父资源池的限额。"""
    from pyVmomi import vim
    content = service.RetrieveContent()
    manager = content.perfManager
    counters = {c.key: c.groupInfo.key + '.' + c.nameInfo.key + '.' + c.rollupType
                for c in manager.perfCounter}
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    report = {'schema': 1, 'collected_utc': datetime.now(timezone.utc).isoformat(), 'nodes': []}
    try:
        targets = sorted([vm for vm in view.view if vm._moId in vm_ids], key=lambda vm: vm._moId)
        if {vm._moId for vm in targets} != set(vm_ids):
            raise ValueError('指定 MoID 不存在或不可见')
        if any(vm.config.annotation != annotation for vm in targets):
            raise ValueError('实验 VM 归属注解不匹配')
        for vm in targets:
            host = vm.runtime.host
            if vm.runtime.powerState != 'poweredOn' or host is None:
                raise ValueError('性能检查需要实验 VM 已启动')
            ids = [metric for metric in manager.QueryAvailablePerfMetric(entity=vm, intervalId=20)
                   if counters.get(metric.counterId) in COUNTERS and metric.instance == '']
            query = vim.PerformanceManager.QuerySpec(entity=vm, metricId=ids, intervalId=20, maxSample=max_samples)
            samples = manager.QueryPerf(querySpec=[query]) if ids else []
            pools = []
            pool = vm.resourcePool
            while isinstance(pool, vim.ResourcePool):
                pools.append({'moid': pool._moId, 'is_root': isinstance(pool.parent, vim.ComputeResource),
                              'cpu': allocation(pool.config.cpuAllocation),
                              'memory': allocation(pool.config.memoryAllocation)})
                pool = pool.parent
            hw = host.summary.hardware
            report['nodes'].append({
                'moid': vm._moId, 'vcpus': vm.config.hardware.numCPU, 'memory_mb': vm.config.hardware.memoryMB,
                'cpu': allocation(vm.config.cpuAllocation), 'memory': allocation(vm.config.memoryAllocation),
                'resource_pools': pools,
                'host': {'moid': host._moId, 'cores': hw.numCpuCores, 'threads': hw.numCpuThreads,
                         'mhz_per_core': hw.cpuMhz, 'current_cpu_mhz': host.summary.quickStats.overallCpuUsage},
                'performance': [{'intervals': [{'timestamp': s.timestamp.isoformat(), 'interval': s.interval}
                                               for s in entry.sampleInfo],
                                 'values': [{'counter': counters[v.id.counterId], 'instance': v.id.instance,
                                             'values': list(v.value)} for v in entry.value]} for entry in samples]})
    finally:
        view.Destroy()
    report['blockers'] = assess(report)
    report['distinct_physical_hosts'] = len({node['host']['moid'] for node in report['nodes']})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', required=True)
    parser.add_argument('--vm', action='append', required=True, help='精确的 ESXi MoID，可重复')
    parser.add_argument('--annotation', required=True)
    parser.add_argument('--max-samples', type=int, default=8)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--insecure', action='store_true', help='仅对已核对身份的私有实验 ESXi 跳过 TLS 校验')
    args = parser.parse_args()
    if len(set(args.vm)) != len(args.vm) or not 1 <= args.max_samples <= 60:
        parser.error('VM 不能重复，样本数必须在 1 到 60 之间')
    if args.output.exists():
        parser.error('拒绝覆盖既有证据')
    from pyVim.connect import SmartConnect, Disconnect
    context = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()
    secret = getpass.getpass('ESXi password: ')
    service = SmartConnect(host=args.host, user=args.user, pwd=secret, sslContext=context)
    del secret
    try:
        report = collect(service, args.vm, args.annotation, args.max_samples)
    finally:
        Disconnect(service)
    with args.output.open('x') as output:
        output.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'blockers': report['blockers'], 'distinct_physical_hosts': report['distinct_physical_hosts']}))
    raise SystemExit(2 if report['blockers'] else 0)


if __name__ == '__main__':
    main()
