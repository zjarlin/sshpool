#!/usr/bin/env python3
"""顺序驱动真实 DSM 页面交接；页面校验与 ioctl 内耗时独立于管理 SSH 往返。"""
import argparse
import asyncio
import importlib.util
import ipaddress
import json
from pathlib import Path
import shlex

spec = importlib.util.spec_from_file_location('pvclock', Path(__file__).with_name('probe-pvclock.py'))
pvclock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pvclock)


def validate_timing(record, node):
    if (record['node'] != node or record['ioctl_result'] != 0 or record['tid'] <= 0
            or not 0 <= record['begin_ns'] < record['end_ns']
            or record['elapsed_ns'] != record['end_ns'] - record['begin_ns']):
        raise ValueError('ioctl 身份、返回值或内部计时无效')


def page_checksum(seed):
    page = bytearray((i * 17 + seed * 13 + (seed >> ((i % 8) * 8))) % 256 for i in range(4096))
    page[:8] = seed.to_bytes(8, 'little')
    checksum = 14695981039346656037
    for byte in page:
        checksum = ((checksum ^ byte) * 1099511628211) % (1 << 64)
    return f'{checksum:016x}'


async def burst(workers, count, output):
    for worker in workers:
        worker.process.stdin.write(f'burst {count} {(worker.node + 1) * 1000000}\n'.encode())
    await asyncio.gather(*(worker.process.stdin.drain() for worker in workers))

    async def collect(worker):
        base = (worker.node + 1) * 1000000
        seen = set()
        for _ in range(count * 2):
            record = await worker.receive()
            validate_timing(record, worker.node)
            seed = record['seed']
            if (record['op'] != 'write' or seed in seen or not base < seed <= base + count * 2
                    or record['observed_seed'] != seed or record['checksum'] != page_checksum(seed)
                    or record['thread'] != (seed - base - 1) // count):
                raise RuntimeError('并发写入记录或内容校验错误')
            seen.add(seed)
        done = await worker.receive()
        if done != {'op': 'burst_done', 'node': worker.node, 'count': count, 'base': base}:
            raise RuntimeError('并发工作线程未全部结束')

    await asyncio.gather(*(collect(worker) for worker in workers))
    endpoints = {(worker.node + 1) * 1000000 + count * multiple
                 for worker in workers for multiple in (1, 2)}
    finals = []
    for worker in workers:
        worker.process.stdin.write(b'read 0\n')
        await worker.process.stdin.drain()
        record = await worker.receive()
        validate_timing(record, worker.node)
        if (record['op'] != 'read' or record['seed'] != 0 or record['observed_seed'] not in endpoints
                or record['checksum'] != page_checksum(record['observed_seed'])):
            raise RuntimeError('并发结束后的整页内容不是某个线程的最终写入')
        finals.append((record['observed_seed'], record['checksum']))
    if len(set(finals)) != 1:
        raise RuntimeError('并发结束后节点页面不一致')
    output.write('LATENCY_BURST ' + json.dumps({'count': count, 'nodes': len(workers),
                                               'final_seed': finals[0][0], 'checksum': finals[0][1]}) + '\n')
    output.flush()


async def run(args, output):
    workers, errors = [], []
    samples = 0
    burst_writes = 0
    try:
        for node, host in enumerate(args.host):
            peers = args.peer if len(args.host) == 2 else ['127.0.0.1', '-']
            remote = shlex.join(['sudo', 'python3', args.trace_worker, '--worker', args.worker,
                                 '--node', str(node), '--peer', peers[0], '--peer', peers[1],
                                 '--require-kernel', args.require_kernel,
                                 '--output', f'{args.remote_output}-node{node}.json'])
            process = await asyncio.create_subprocess_exec(
                'ssh', '-F', str(args.ssh_config), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
                '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3', host, remote,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
            workers.append(pvclock.Worker(node, process, output))
        for worker in workers:
            ready = await worker.receive()
            if (ready['op'], ready['node'], ready['nodes']) != ('ready', worker.node, len(workers)):
                raise RuntimeError('启动参数不一致')
        for round_number in range(args.rounds):
            writer = round_number % len(workers)
            reader = (1 - writer) % len(workers)
            seed = round_number + 1
            operations = [(writer, 'write'), (writer, 'read'), (reader, 'read'), (reader, 'read'), (writer, 'read')]
            for step, (node, operation) in enumerate(operations):
                worker = workers[node]
                worker.process.stdin.write(f'{operation} {seed}\n'.encode())
                await worker.process.stdin.drain()
                record = await worker.receive()
                if (record['op'], record['seed'], record['observed_seed'], record['checksum']) != (
                        operation, seed, seed, page_checksum(seed)):
                    raise RuntimeError('页面内容或响应身份不符')
                validate_timing(record, worker.node)
                output.write('LATENCY_SAMPLE ' + json.dumps({'round': round_number, 'step': step,
                                                             'node': node, 'operation': operation}) + '\n')
                output.flush()
                samples += 1
        if args.burst_count:
            await burst(workers, args.burst_count, output)
            burst_writes = args.burst_count * 2 * len(workers)
    except (OSError, ValueError, RuntimeError, asyncio.TimeoutError) as error:
        errors.append(str(error) or type(error).__name__)
    finally:
        for worker in reversed(workers):
            try:
                await worker.command('quit')
                status = await asyncio.wait_for(worker.process.wait(), 30)
                if status:
                    errors.append(f'节点 {worker.node} 退出 {status}')
            except (OSError, ValueError, RuntimeError, asyncio.TimeoutError) as error:
                errors.append(f'节点 {worker.node} 清理未确认：{error}')
        result = {'samples': samples, 'rounds': args.rounds, 'nodes': len(workers),
                  'burst_writes': burst_writes, 'errors': errors}
        output.write('LATENCY_RESULT ' + json.dumps(result) + '\n')
        output.flush()
        print(json.dumps(result), flush=True)
    return bool(errors) or samples != args.rounds * 5


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, required=True)
    parser.add_argument('--host', action='append', required=True)
    parser.add_argument('--peer', action='append', default=[])
    parser.add_argument('--worker', required=True)
    parser.add_argument('--trace-worker', required=True)
    parser.add_argument('--remote-output', required=True)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--rounds', type=int, default=32)
    parser.add_argument('--burst-count', type=int, default=256)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    if len(args.host) not in (1, 2) or not 4 <= args.rounds <= 128 or not 0 <= args.burst_count <= 512:
        parser.error('需要一到两台节点和四到一百二十八轮')
    if len(args.host) == 2:
        peers = [ipaddress.IPv4Address(value) for value in args.peer]
        if len(peers) != 2 or peers[0] == peers[1]:
            parser.error('需要两个不同 IPv4 地址')
    elif args.peer:
        parser.error('单节点固定使用回环地址')
    with args.log.open('x') as output:
        raise SystemExit(asyncio.run(run(args, output)))


if __name__ == '__main__':
    main()
