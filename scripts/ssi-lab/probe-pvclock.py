#!/usr/bin/env python3
"""通过已校验的管理 SSH，在独立研究 VM 验证跨节点 pvclock 页面更新。"""
import argparse
import asyncio
import ipaddress
import json
from pathlib import Path
import shlex


class Worker:
    def __init__(self, node, process, log):
        self.node = node
        self.process = process
        self.log = log

    async def receive(self):
        line = await asyncio.wait_for(self.process.stdout.readline(), 45)
        if not line:
            raise RuntimeError(f'节点 {self.node} 在响应前退出')
        result = json.loads(line)
        self.log.write(json.dumps({'node': self.node, **result}) + '\n')
        self.log.flush()
        return result

    async def command(self, value):
        self.process.stdin.write((value + '\n').encode())
        await self.process.stdin.drain()
        result = await self.receive()
        expected = 'tick' if value.startswith('tick') else value
        if value == 'quit':
            expected = 'closed'
        if result.get('op') != expected:
            raise RuntimeError(f'节点 {self.node} 响应与 {value} 不匹配')
        return result


def check_exchange(before, previous, latest, observed, cpu, reader_node):
    """核对内核实际写回的版本、远端可见内容及同页其他字段，不采信通过标记。"""
    record = latest['records'][cpu]
    valid = (record['version'] > previous['records'][cpu]['version']
             and record['version'] % 2 == 0
             and record['time'] > 0 and record['multiplier'] > 0)
    same = (latest['records'] == observed['records']
            and latest['marker'] == observed['marker'] == reader_node + 1)
    unchanged = previous['records'] == before['records']
    preserved = latest['records'][1 - cpu] == previous['records'][1 - cpu]
    return {'pass': valid and same and unchanged and preserved,
            'valid_update': valid, 'peer_matches': same,
            'claim_preserves_records': unchanged,
            'update_preserves_other_record': preserved}


async def run(args, log):
    workers = []
    errors = []
    failures = []
    checks = 0
    try:
        for node, host in enumerate(args.host):
            peers = args.peer if len(args.host) == 2 else ['127.0.0.1', '-']
            remote = shlex.join(['timeout', '--kill-after=5', '180', args.worker,
                                 str(node), *peers, args.require_kernel])
            # 拒绝复用其他 DSM 实例的监听端口；实验节点仍必须由操作者独占。
            preflight = (
                "set -eu; listeners=$(ss -H -ltn '( sport = :37710 or sport = :37711 )'); "
                "if test -n \"$listeners\"; then echo 'DSM port already in use' >&2; exit 2; fi; exec ")
            process = await asyncio.create_subprocess_exec(
                'ssh', '-F', str(args.ssh_config), '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15',
                '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3',
                host, preflight + remote, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE)
            workers.append(Worker(node, process, log))
        for worker in workers:
            ready = await worker.receive()
            if ready != {'op': 'ready', 'node': worker.node, 'nodes': len(workers)}:
                raise RuntimeError('节点启动参数与实际实例不一致')

        # 两条记录先在正确取得所有权的节点上初始化。
        for cpu in range(2):
            writer = workers[cpu % len(workers)]
            await writer.command('claim')
            await writer.command(f'tick{cpu}')
        for round_number in range(4):
            for cpu in range(2):
                writer = workers[cpu % len(workers)]
                reader = workers[(1 - cpu) % len(workers)]
                await writer.command('claim')
                before = await writer.command(f'tick{cpu}')
                # 另一节点的显式写入强制转移同页所有权。
                await reader.command('claim')
                previous = await reader.command('read')
                latest = await writer.command(f'tick{cpu}')
                observed = await reader.command('read')
                result = {'round': round_number, 'cpu': cpu,
                          **check_exchange(before, previous, latest, observed, cpu, reader.node)}
                print('PVCLOCK_CHECK ' + json.dumps(result), flush=True)
                log.write('PVCLOCK_CHECK ' + json.dumps(result) + '\n')
                log.flush()
                checks += 1
                if not result['pass']:
                    failures.append(result)
    except (OSError, ValueError, RuntimeError, asyncio.TimeoutError) as error:
        errors.append(str(error) or type(error).__name__)
    finally:
        # 先关从节点，再关主节点；每个 closed 标记都在 VM fd 释放之后。
        for worker in reversed(workers):
            try:
                await worker.command('quit')
            except (OSError, ValueError, RuntimeError, asyncio.TimeoutError) as error:
                errors.append(f'节点 {worker.node} 关闭失败：{error}')
            try:
                status = await asyncio.wait_for(worker.process.wait(), 45)
                if status != 0:
                    errors.append(f'节点 {worker.node} 退出码 {status}')
            except asyncio.TimeoutError:
                # 这里只回收本地 SSH，远端状态仍标记未确认，不能输出成功。
                errors.append(f'节点 {worker.node} 远端清理未确认，需核对实验宿主')
                worker.process.kill()
                await worker.process.wait()
        result = {'checks': checks, 'failures': len(failures), 'errors': errors}
        log.write('PVCLOCK_RESULT ' + json.dumps(result) + '\n')
        print('PVCLOCK_RESULT ' + json.dumps(result), flush=True)
    return checks != 8 or bool(failures or errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, required=True)
    parser.add_argument('--host', action='append', required=True)
    parser.add_argument('--peer', action='append', default=[])
    parser.add_argument('--worker', default='ssi/probe-pvclock')
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    if len(args.host) not in (1, 2):
        parser.error('显式提供一个对照节点或两个实验节点')
    if len(args.host) == 2:
        peers = [ipaddress.IPv4Address(value) for value in args.peer]
        if len(peers) != 2 or peers[0] == peers[1]:
            parser.error('双节点需要两个不同的实际 IPv4 地址')
    elif args.peer:
        parser.error('单节点对照固定使用回环地址')
    # 不覆盖历史记录，日志目录由操作者明确选择。
    with args.log.open('x') as log:
        raise SystemExit(asyncio.run(run(args, log)))


if __name__ == '__main__':
    main()
