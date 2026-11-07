#!/usr/bin/env python3
"""核对已脱敏物理主机记录；构建卸载成功不等于跨物理 SSI 或存储容错。"""
import argparse
import json
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check(data):
    require(data['schema'] == 1, '未知证据协议')
    privacy = data['privacy']
    require(all(privacy[key] is True for key in (
        'addresses_removed', 'credentials_removed', 'private_paths_removed', 'disk_serials_removed')),
        '公开证据未完成脱敏')
    require(privacy['company_files_used'] is False, '实验不得使用公司文件')

    host = data['physical_host']
    require(host['ssh_access_verified'] is True and host['architecture'] == 'x86_64', 'SSH 或宿主架构证据缺失')
    require(host['packages'] == 2 and host['physical_cores'] == 16 and host['logical_cpus'] == 32,
            '物理 CPU 拓扑不符')
    require(host['memory_bytes'] >= 60 * 1024 ** 3, '物理内存容量证据不足')
    require(host['numeric_identity_differs_from_guest'] is True, '宿主与客体身份未区分')
    kvm = host['kvm']
    require(kvm['available_to_worker_user'] is True and kvm['api_version'] == 12, 'KVM 实际访问未成立')
    require(kvm['get_tsc_khz_supported'] is True and kvm['tsc_control_supported'] is False,
            'TSC 能力记录与实测不符')
    docker = host['docker']
    require(docker['server_version'] == docker['client_version'] == '29.1.3', 'Docker 版本不符')
    require(docker['cgroup_version'] == 'v2' and all(docker[key] is True for key in (
        'memory_limit', 'cpu_cfs_quota', 'pids_limit')), '容器资源限制能力不完整')
    config = host['critical_configuration']
    require(config['unchanged_during_experiment'] is True, '关键配置未通过前后核对')
    for name in ('fstab', 'grub', 'sshd_config'):
        require(config[f'{name}_sha256_before'] == config[f'{name}_sha256_after'], f'{name} 前后哈希不一致')
        require(len(config[f'{name}_sha256_before']) == 64, f'{name} 哈希格式错误')

    vm = data['isolated_vm']
    require(vm['vcpus'] == 8 and vm['memory_mib'] == 12288 and vm['root_overlay_mib'] == 102400,
            '隔离 VM 配额不符')
    require(vm['sparse_overlay'] is True and vm['physical_host_cpu_execution_observed'] is True,
            '没有可复核的物理 KVM 执行证据')
    ticks = vm['kvm_vcpu_thread_ticks']
    require(len(ticks) == 8 and all(type(value) is int and value >= 300 for value in ticks),
            'vCPU 线程执行样本不完整')
    require(vm['host_business_directory_mounted'] is False and vm['host_business_block_device_passed'] is False and
            vm['virtfs_or_9p_configured'] is False, '实验 VM 暴露了宿主数据路径')
    require(vm['clean_powerdown_observed'] is True and vm['qemu_exit_observed'] is True and
            vm['remaining_qemu_process'] is False, '实验 VM 未正常退出')

    build = data['build_offload']
    require(build['platform'] == 'linux/amd64' and build['image'] == 'rust:1.93-alpine',
            '构建平台或镜像不符')
    require(build['image_digest'].startswith('sha256:') and len(build['image_digest']) == 71,
            '镜像 digest 无效')
    require(build['command'] == ['cargo', 'build', '--release'] and build['network'] is False,
            '不是预期的离线 Cargo 构建')
    require(build['phase'] == 'succeeded' and build['exit_code'] == 0 and build['cleanup_confirmed'] is True and
            build['container_remaining'] is False, '构建或清理未闭环')
    require(build['artifact_runs_on_worker'] is True and build['worker_output'].startswith('SSHPOOL_OK amd64'),
            '产物未在真实 Worker 上执行')
    require(build['cross_architecture_execution_on_arm64_entry_refused'] is True and
            build['cross_architecture_error'] == 'exec format error', '架构边界未被验证')
    require(len(build['artifact_sha256']) == 64, '产物哈希无效')

    storage = data['storage']
    require(storage['additional_disk_discovered'] is True and
            storage['additional_disk_filesystem_identified'] is False and
            storage['additional_disk_ownership_confirmed'] is False, '额外磁盘归属描述不保守')
    for key in ('additional_disk_touched', 'mount_created', 'lvm_created', 'raid_created', 'osd_created',
                'ceph_deployed', 'distributed_storage_verified', 'safe_to_reuse_without_owner_confirmation'):
        require(storage[key] is False, f'未经确认的存储状态 {key} 不得为真')

    cross = data['cross_physical_preflight']
    require(cross['esxi_tsc_khz'] != cross['physical_host_tsc_khz'], '把不同频率错误地描述为相同')
    require(cross['native_tsc_precheck_passed'] is False, '当前运行时不能通过不同 TSC 频率预检')
    for key in ('same_process_across_physical_hosts', 'cpu_and_memory_capacity_aggregated'):
        require(cross[key] is False, f'跨物理 SSI 结论 {key} 没有证据')

    claims = data['claims']
    require(claims['real_physical_cpu_execution'] is True and claims['real_build_offload'] is True,
            '已完成的物理计算卸载被遗漏')
    for key in ('full_ssi_accepted', 'automatic_host_failover_verified',
                'database_migration_or_failover_verified', 'no_raid_distributed_storage_verified'):
        require(claims[key] is False, f'未完成能力 {key} 不得标记为真')
    return {
        'logical_cpus': host['logical_cpus'],
        'memory_bytes': host['memory_bytes'],
        'isolated_vm_vcpus': vm['vcpus'],
        'build_offload_verified': True,
        'cross_physical_ssi_verified': False,
        'distributed_storage_verified': False,
        'full_ssi_accepted': False
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    print(json.dumps(check(json.loads(args.evidence.read_text())), ensure_ascii=False))


if __name__ == '__main__':
    main()
