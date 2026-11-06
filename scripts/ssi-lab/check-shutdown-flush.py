#!/usr/bin/env python3
"""核对真实写入、blkdebug 刷盘失败和进程退出，不以 QMP 受理或读回成功冒充持久化。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('router', Path(__file__).with_name('check-router-drain.py'))
router = importlib.util.module_from_spec(spec)
spec.loader.exec_module(router)
demand = router.demand
DATA_SHA = hashlib.sha256(b'\x5a' * 65536).hexdigest()
WRITE = 'qemu-io ssi-probe "write -P 0x5a 0 64k"'
READ = 'qemu-io ssi-probe "read -P 0x5a 0 64k"'


def response(entry):
    replies = [r for r in entry['responses'] if 'id' in r]
    demand(len(replies) == 1 and replies[0].get('id') == entry['request']['id'] and
           'return' in replies[0] and 'error' not in replies[0], 'QMP 回复缺失或失败')
    return replies[0]['return']


def inspect_record(record, run, node, error, paired, expected_exit):
    demand(record['node'] == node and record['injected_errno'] == error and record['paired'] == paired, '场景身份不符')
    demand(record['kernel'] == ('7.1.0-rc3-sshpool-gvm-pf24' if paired else '6.8.0-147-generic'), '实验内核错误')
    demand(record['qemu_sha256'] == run['runtime_sha256'] and record['capture_sha256'] == run['capture_sha256'], '采集或运行时身份不符')
    demand(not record['errors'] and not record['forced_cleanup'] and record['qemu_exit'] == expected_exit and
           type(record['qemu_exit']) is int, '采集失败强制清理或进程退出不符')
    demand(record['directory_created_exclusively'] and record['image_regular'] and
           record['image_bytes'] == record['image_size_after'] == 67108864 and record['write_bytes'] == 65536, '测试盘边界不符')
    config = '' if error == 0 else ('[inject-error]\nevent = "flush_to_disk"\n' +
                                  f'errno = "{error}"\niotype = "flush"\nimmediately = "on"\n')
    demand(record['blkdebug_config'] == config, '实际错误配置不符')
    demand(record['data_matches'] and record['data_sha256'] == DATA_SHA, '读回内容不符')
    demand(0 < record['prepared_ns'] < record['action_ns'] and record['elapsed_ns'] > 0, '时间记录不符')
    command = record['command']
    demand('-S' in command and '-kernel' not in command and '-initrd' not in command and '-hda' not in command, '不是暂停的无客体代码诊断')
    demand(command[command.index('-machine') + 1] == 'pc,accel=kvm,kernel-irqchip=split', '没有明确使用 KVM')
    demand(command.count('-drive') == 1 and command.count('-device') == 1, '不允许额外磁盘或设备')
    drive = command[command.index('-drive') + 1]
    prefix = 'if=none,id=ssi-probe,format=raw,cache=writeback,file=blkdebug:'
    demand(drive.startswith(prefix), '没有使用指定 blkdebug 链路')
    paths = drive.removeprefix(prefix).split(':')
    demand(len(paths) == 2 and paths[0].endswith('/blkdebug.conf') and
           paths[1] == paths[0].removesuffix('blkdebug.conf') + 'disk.raw', '配置和磁盘不在同一独立目录')
    demand(command[command.index('-qmp') + 1] == 'unix:' + paths[0].removesuffix('blkdebug.conf') +
           'qmp.sock,server=on,wait=off', 'QMP 不属于同一次实验目录')
    demand(command[command.index('-device') + 1] == 'virtio-blk-pci,drive=ssi-probe,id=ssi-disk,disable-modern=on,vectors=0', '不是测试 virtio 块设备')
    demand(command.count('-local-cpu') == int(paired), '分布式拓扑不符')
    if paired:
        demand(command[command.index('-local-cpu') + 1].startswith(f'cpus=2,start={node * 2},iplist='), '节点 vCPU 范围不符')

    action = 'wait' if paired and node == 1 else 'quit'
    demand(record['action'] == action, '关闭发起方错误')
    entries = record['qmp']
    names = ['qmp_capabilities', 'query-status', 'query-block', 'human-monitor-command',
             'human-monitor-command', 'query-blockstats'] + (['quit'] if action == 'quit' else [])
    demand([e['request']['execute'] for e in entries] == names and
           [e['request']['id'] for e in entries] == list(range(len(names))), 'QMP 顺序不完整')
    demand(response(entries[0]) == {} and response(entries[1]) == {'status': 'prelaunch', 'running': False}, '客体已运行或协商失败')
    blocks = response(entries[2])
    demand(len(blocks) == 1 and blocks[0]['device'] == 'ssi-probe' and
           blocks[0]['qdev'] == '/machine/peripheral/ssi-disk/virtio-backend', '测试块设备不存在')
    inserted = blocks[0]['inserted']
    demand(inserted['drv'] == 'raw' and not inserted['ro'] and inserted['image']['virtual-size'] == 67108864 and
           inserted['cache'] == {'no-flush': False, 'direct': False, 'writeback': True}, '绕过刷盘或错误块层配置')
    demand(inserted['file'] == drive.split('file=', 1)[1], 'QMP 磁盘与启动参数不一致')
    demand(entries[3]['request']['arguments'] == {'command-line': WRITE} and
           entries[4]['request']['arguments'] == {'command-line': READ}, '没有执行指定真实写读')
    demand(response(entries[3]) == response(entries[4]) == '', 'HMP 写读报错')
    stats = response(entries[5])
    demand(len(stats) == 1 and stats[0]['device'] == 'ssi-probe' and
           stats[0]['stats']['wr_highest_offset'] == 65536, '块层没有观察到完整写入')
    if action == 'quit':
        transport = record.get('quit_transport', {'kind': 'reply'})
        if transport == {'kind': 'reply'}:
            demand(response(entries[-1]) == {}, '关闭请求未受理')
        else:
            demand(expected_exit == 1 and transport in ({'kind': 'eof'}, {'kind': 'reset', 'errno': 104}), '非预期 QMP 中断')
            demand(not any('id' in r for r in entries[-1]['responses']), '回复和连接中断记录冲突')
    for entry in entries:
        demand(not any('error' in r for r in entry['responses']), '存在 QMP 错误')
        for event in (r for r in entry['responses'] if 'event' in r):
            demand(action == 'quit' and event['event'] == 'SHUTDOWN' and
                   event['data'] == {'guest': False, 'reason': 'host-qmp-quit'}, '混入其他关机原因')
    stdout, stderr = record['stdout'], record['stderr']
    for operation in ('wrote', 'read'):
        demand(stdout.count(f'{operation} 65536/65536 bytes at offset 0') == 1, '真实写读结果缺失')
    demand(not re.search(r'verification failed|segfault|segmentation fault|dumped core|terminating on signal', stdout + stderr, re.I), '内容错误崩溃或强制终止')
    writes = re.findall(r'^blk_co_pwritev blk 0x[0-9a-f]+ bs 0x[0-9a-f]+ offset (\d+) bytes (\d+) flags (0x[0-9a-f]+)$', stderr, re.M)
    demand(writes == [('0', '65536', '0x0')], '缺少真实非 FUA 块层写入跟踪')
    flushes = [int(v) for v in re.findall(r'^vm_stop_flush_all ret (-?\d+)$', stderr, re.M)]
    if error or expected_exit == 0 or not paired:
        demand(flushes == [-error], '真实停止刷盘返回不符')
    else:
        demand(flushes in ([], [0]), '另一端故障时出现未解释刷盘返回')
    fatal = f'QEMU device shutdown/flush failed ({-error}); terminating this node'
    if error and run['variant'] == 'candidate':
        demand(stderr.count(fatal) == 1, '缺少保留原错误的失败日志')
    else:
        demand('QEMU device shutdown/flush failed' not in stderr, '没有本地刷盘故障却触发相同日志')
    return {'node': node, 'native_flush_returns': flushes, 'qemu_exit': expected_exit,
            'cached_data_readback_verified': True, 'power_loss_durability_verified': False}


def inspect(data):
    run = data['run']
    demand(run['variant'] in ('baseline', 'candidate'), '未知版本')
    paired = 'records' in data
    if not paired:
        demand(run['capture_exit'] == 0 and not run['remaining'], '单节点采集或清理失败')
        error, node = run['error'], run['node']
        demand(node in (0, 1) and error in (0, 5, 28), '单节点场景错误')
        code = int(run['variant'] == 'candidate' and error != 0)
        nodes = [inspect_record(data['record'], run, node, error, False, code)]
        lost = error != 0 and run['variant'] == 'baseline'
    else:
        fault = run['fault_node']
        demand(fault in (-1, 0, 1) and run['capture_exits'] == [0, 0] and not run['errors'] and
               not run['node0_remaining'] and not run['node1_remaining'], '配对采集或清理失败')
        demand(len(data['records']) == 2 and set(run['ready']) == {'0', '1'}, '缺少两节点准备记录')
        code = int(run['variant'] == 'candidate' and fault >= 0)
        nodes = []
        for node, record in enumerate(data['records']):
            error = (5 if node == 0 else 28) if node == fault else 0
            demand(run['ready'][str(node)] == {'ready': True, 'node': node, 'pid': record['pid']}, '配对进程身份不符')
            nodes.append(inspect_record(record, run, node, error, True, code))
            marker = f'SSI_DRAIN_COMPLETE node={node} peers=1'
            demand(record['stderr'].count(marker) == int(code == 0), '故障关闭不能被正常排空标记掩盖')
            if code == 1 and node != fault:
                demand(any(message in record['stderr'] for message in
                           ('SSI missing or invalid drain acknowledgement',
                            'SSI router EOF before acknowledged drain')), '缺少对端断连造成的明确路由失败')
        lost = fault >= 0 and run['variant'] == 'baseline'
    return {'nodes': nodes, 'flush_error_ignored_reproduced': lost,
            'failure_exit_verified': not lost and any(n['qemu_exit'] == 1 for n in nodes),
            'whole_vm_shutdown_verified': False, 'persistent_io_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(json.loads(args.record.read_text())), indent=2))
    except (ValueError, KeyError, IndexError, TypeError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
