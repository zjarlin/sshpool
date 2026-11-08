"""核查限定 QEMU 实验的设备清理、双端屏障与原生关闭；不认证时钟或持久化。"""
from collections import defaultdict
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kernel = load('check-kernel-close')
demand = kernel.demand
RUNTIME = 'dee8df74fb42f472a8741d991f2cdcbd748ecc1107e68e510860ea726a39938f'
TRACE = 'ce80a3b7565b92c271ff25af3f2fd6d94222cccbfc8848e9e8b460346f2c7686'


def inspect_barrier(logs, kind):
    """只核对双向屏障，不用伪造客体 poweroff 来适配 QMP quit。"""
    nonces, replies = {}, []
    for node, log in enumerate(logs):
        rows = [line for line in log.splitlines() if line.startswith(f'SSI_{kind}_')]
        demand(len(rows) == 4, '屏障事件缺失或重复')
        local = re.fullmatch(rf'SSI_{kind}_LOCAL node=(\d+) stopped=4 nonce=(\d+)', rows[0])
        demand(local is not None and int(local[1]) == node and int(local[2]) > 0,
               '本地四个 vCPU 尚未全部停止')
        nonces[node] = int(local[2])
        demand(rows[-1] == f'SSI_{kind}_COMPLETE node={node} peers=1', '屏障完成早于双向确认')
        directions = set()
        for line in rows[1:3]:
            reply = re.fullmatch(rf'SSI_{kind}_ACK_(SENT|RECEIVED) node=(\d+) peer=(\d+) nonce=(\d+)', line)
            demand(reply is not None and int(reply[2]) == node and int(reply[3]) == 1 - node,
                   '屏障确认端点错误')
            directions.add(reply[1])
            replies.append((reply[1], node, int(reply[4])))
        demand(directions == {'SENT', 'RECEIVED'}, '屏障确认方向重复')
    for direction, node, nonce in replies:
        demand(nonce == nonces[1 - node if direction == 'SENT' else node], '两端屏障代际不一致')
    return nonces[0]


def inspect_capture(capture, node):
    demand(capture['node'] == node and capture['kernel'] == '7.1.0-rc3-sshpool-gvm-pf28',
           '原生记录节点或内核错误')
    demand(capture['qemu_sha256'] == RUNTIME and capture['probe_sha256'] == TRACE,
           '跟踪进程或采集器身份不符')
    demand(not capture['errors'] and not capture['qemu_present_after'] and not capture['remaining_tasks']
           and capture['trace_cleanup_complete'], '退出后存在进程线程或未完成跟踪')
    rows, marks = kernel.native.parse(capture, {name for _, name, _ in kernel.probe.PROBES})
    demand(list(marks) == ['capture_begin', 'capture_end'], '关闭跟踪窗口不完整')
    return rows


def inspect(data):
    result = data['result']
    demand(result['qemu_sha256'] == RUNTIME, 'QEMU 候选身份错误')
    demand(not any(result.get(name) for name in ('harness_error', 'management_timeout', 'host_log_timeout', 'samples_errors')),
           '实验采集未完整完成')
    demand(result['qemu_ssh_exits'] == [0, 0] and result['close_trace_exits'] == [0, 0],
           'QEMU 或原生采集没有在两端成功退出')
    demand(len(data['traces']) == len(data['qemu_stderr']) == len(data['host_logs']) == 2,
           '两端原始记录不完整')
    generation = inspect_barrier(data['qemu_stderr'], 'QUIESCE')
    inspect_barrier(data['qemu_stderr'], 'DRAIN')
    analyses = []
    for node, (capture, log, host) in enumerate(zip(data['traces'], data['qemu_stderr'], data['host_logs'])):
        rows = inspect_capture(capture, node)
        demand(f'SSI_ROUTER_READY node={node} peers=1 version=6' in log, '没有协议六准入')
        demand(not re.search(r'WARNING:|BUG:|Oops:|Kernel panic|hung task|kvm-dsm:.*failed|exited server loop, error', host),
               '宿主错误不能被正常退出覆盖')
        demand(not re.search(r'SSI close failed|shutdown/flush failed|retains I/O status|failed \(-|unpin failed|pin failed|'
                            r'SSI (?:invalid|duplicate|missing|router |local quiescence|drain |shutdown )|'
                            r'segfault|segmentation fault|dumped core|HARNESS_TIMEOUT|terminating on signal', log, re.I),
               'QEMU 清理或关闭失败')
        events = [line for line in log.splitlines() if line.startswith(('SSI_QUIESCE_COMPLETE',
                  'SSI_DEVICE_UNREALIZED', 'SSI_DRAIN_COMPLETE', 'SSI_CLOSE_PINS',
                  'SSI_KERNEL_CLOSE_', 'SSI_DEVICE_CLOSE_COMPLETE'))]
        demand(events[0] == f'SSI_QUIESCE_COMPLETE node={node} peers=1', '设备清理早于双端 CPU 屏障')
        devices = [line for line in events if line.startswith('SSI_DEVICE_UNREALIZED')]
        demand(len(devices) == 1 and all(line in ('SSI_DEVICE_UNREALIZED type=virtio-net-device',
                                       'SSI_DEVICE_UNREALIZED type=virtio-blk-device') for line in devices),
               '缺少受支持设备的真实销毁记录')
        expected = [events[0], *devices, f'SSI_DRAIN_COMPLETE node={node} peers=1',
                    'SSI_CLOSE_PINS ret=0 version=1 active=0 read=0 write=0 error=0 reserved=0',
                    f'SSI_KERNEL_CLOSE_BEGIN generation={generation} timeout_ms=15000',
                    f'SSI_KERNEL_CLOSE_RESULT generation={generation} ret=0',
                    'SSI_DEVICE_CLOSE_COMPLETE']
        demand(events == expected, '设备解除、路由封闭与内核关闭顺序错误')
        ioctls = kernel.pair_calls(rows, 'kc_ioctl', 'kc_return')
        demand(len(ioctls) >= 2 and [call['input']['ioctl'] for call in ioctls[-2:]] ==
               [0x8020aef9, kernel.probe.CLOSE] and all(call['code'] == 0 for call in ioctls[-2:]),
               '缺少关闭前的真实零引用查询或最终关闭 ioctl')
        calls = kernel.pair_calls(rows, 'kc_close', 'kc_closed')
        demand(len(calls) == 1 and calls[0]['code'] == 0, '没有唯一成功的原生关闭调用')
        close = calls[0]
        kvm = close['input']['kvm']
        demand(close['start']['pid'] == capture['qemu_pid'], '关闭不属于 QEMU 主线程')
        demand(not any(row['name'] == 'kc_fail' for row in rows), '原生关闭掩盖了故障')
        finished = [row for row in rows if row['name'] == 'kc_root_done']
        demand(len(finished) == 1 and kernel.fields(finished[0])['kvm'] == kvm
               and finished[0]['comm'] == f'kvm-dsm/{node}'
               and close['start']['index'] < finished[0]['index'] < close['end']['index'],
               '成功返回未等待正确根线程回收')
        fences = kernel.pair_calls(rows, 'kc_fence', 'kc_fenced')
        demand(len(fences) == 1 and fences[0]['code'] == 0 and
               fences[0]['input'] == {'kvm': kvm, 'generation': generation}, '本地封闭代际或结果错误')
        close_ioctls = [row for row in rows if row['name'] == 'kc_ioctl' and
                        kernel.fields(row)['ioctl'] == kernel.probe.CLOSE]
        demand(len(close_ioctls) == 1 and close_ioctls[0]['pid'] == capture['qemu_pid'] and
               close_ioctls[0]['index'] < close['start']['index'], '没有实际 KVM_DSM_CLOSE ioctl')
        later = [row for row in rows if row['name'] == 'kc_ioctl' and row['index'] > close['start']['index']]
        demand(not later, '设备在关闭入口封闭后仍发起 VM ioctl')
        returns = [row for row in rows if row['name'] == 'kc_return' and row['pid'] == capture['qemu_pid']
                   and row['index'] > close['end']['index']]
        demand(len(returns) == 1 and kernel.fields(returns[0])['code'] == 0, 'VM ioctl 没有成功返回')
        connections = defaultdict(list)
        for call in kernel.pair_calls(rows, 'kc_request', 'kc_ack'):
            demand(call['code'] == 0 and call['input']['kvm'] == kvm and
                   call['input']['generation'] == generation, '入站关闭确认失败或代际不同')
            connections[call['input']['conn']].append(call)
        for calls in connections.values():
            phases = [row['input']['phase'] for row in calls]
            demand(phases in ([4], [5, 6, 7]), '连接没有完成完整关闭阶段')
            if phases == [4]:
                demand(fences[0]['end']['index'] < calls[0]['end']['index'], '页面准入未封闭就确认 CLOSE')
        demand(sorted([call['input']['phase'] for call in calls] for calls in connections.values()) ==
               [[4], [5, 6, 7]], '必须包含本轮的数据连接与管理连接')
        eofs = kernel.pair_calls(rows, 'kc_eof', 'kc_eof_done')
        demand(len(eofs) == len(connections) and {row['input']['conn'] for row in eofs} == set(connections),
               '连接 EOF 缺失或重复')
        for call in eofs:
            demand(call['code'] == -kernel.LINUX_ENODATA and call['input']['kvm'] == kvm and
                   connections[call['input']['conn']][-1]['end']['index'] < call['start']['index']
                   and call['end']['index'] < finished[0]['index'], 'EOF 未晚于确认或根线程过早回收')
        states = re.findall(r'DSM_CLOSE_RESULT node=(\d+) generation=(\d+) accepted=(\d+) closed=(\d+) eof=(\d+) result=(-?\d+)', host)
        demand(len(states) == 1, '缺少内核最终连接集合计数')
        actual_node, actual_generation, accepted, closed, eof, code = map(int, states[0])
        demand((actual_node, actual_generation, code) == (node, generation, 0) and
               accepted == eof == len(connections) and closed + 1 == accepted, '接受过的连接被遗漏')
        elapsed_ms = (close['end']['time'] - close['start']['time']) * 1000
        demand(0 < elapsed_ms <= 15500, '原生关闭超过总期限')
        analyses.append({'node': node, 'generation': generation, 'connections': accepted,
                         'native_events': len(rows), 'close_ms': elapsed_ms})
    return {'nodes': analyses, 'scoped_qemu_close_verified': True,
            'persistent_io_accepted': False, 'full_ssi_accepted': False}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.record.read_text())), indent=2))
