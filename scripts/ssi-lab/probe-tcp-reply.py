#!/usr/bin/env python3
"""以指定 TCP 源端口检查双节点返回通路，记录握手和实际回显结果。"""
import argparse
import hashlib
import json
import socket
import struct
import time

PAYLOAD = b'sshpool isolated TCP reply probe\n' * 4


def report(record):
    print(json.dumps(record), flush=True)


def receive(sock):
    """按已知长度读取，拒绝将短读或 EOF 当成完整回显。"""
    data = b''
    while len(data) < len(PAYLOAD):
        part = sock.recv(len(PAYLOAD) - len(data))
        if not part:
            raise EOFError('完整探针数据到达之前连接结束')
        data += part
    if data != PAYLOAD:
        raise ValueError('探针数据不一致')
    return hashlib.sha256(data).hexdigest()


def execute(args):
    """测试 socket 自己持有并关闭，不操作其他进程或连接。"""
    result = {'mode': args.mode, 'local': [args.local, args.port], 'peer': [args.peer, args.peer_port]}
    start = time.monotonic_ns()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(3 if args.mode == 'server' else 1.5)
        # 该探针只测试回显，关闭使用 RST，避免测试源端口遗留 TIME-WAIT。
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.bind((args.local, args.port))
        try:
            if args.mode == 'server':
                sock.listen(1)
                report({'op': 'ready', 'local': list(sock.getsockname())})
                connection, peer = sock.accept()
                with connection:
                    connection.settimeout(1.5)
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    result['accepted_peer'] = list(peer)
                    result['payload_sha256'] = receive(connection)
                    connection.sendall(PAYLOAD)
            else:
                report({'op': 'bound', 'local': list(sock.getsockname())})
                sock.connect((args.peer, args.peer_port))
                result['connected_peer'] = list(sock.getpeername())
                sock.sendall(PAYLOAD)
                result['payload_sha256'] = receive(sock)
            result['success'] = True
        except (OSError, EOFError, ValueError) as error:
            result.update(success=False, error=type(error).__name__, errno=getattr(error, 'errno', None),
                          message=str(error), tcp_state=sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 1)[0])
    result['elapsed_ns'] = time.monotonic_ns() - start
    report({'op': 'result', **result})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('server', 'client'))
    parser.add_argument('local')
    parser.add_argument('port', type=int)
    parser.add_argument('peer')
    parser.add_argument('peer_port', type=int)
    execute(parser.parse_args())


if __name__ == '__main__':
    main()
