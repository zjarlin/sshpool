#!/usr/bin/env python3
"""生成独占双节点实验的临时 nft 规则；只输出规则，不修改宿主。"""
import argparse
import ipaddress
import re

PORTS = '{ 37710, 37711, 40000, 40001 }'
PROTECTED = '{ 37710-37773, 40000-40063 }'


def rules(peer, label):
    """仅信任指定 IPv4 对端，兼顾监听请求和落入保护区间的 TCP 返回包。"""
    address = ipaddress.IPv4Address(peer)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError('需要明确的非回环实验对端 IPv4 地址')
    if not re.fullmatch(r'sshpool-[a-z0-9-]{1,48}', label):
        raise ValueError('规则标签必须是 sshpool- 开头的短小写标识')
    prefix = f'insert rule inet sshpool_ssi_lab input ip saddr {address}'
    return (f'{prefix} tcp dport {PORTS} accept comment "{label}-request"\n'
            f'{prefix} tcp sport {PORTS} tcp dport {PROTECTED} accept comment "{label}-reply"\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('peer')
    parser.add_argument('label')
    args = parser.parse_args()
    try:
        print(rules(args.peer, args.label), end='')
    except ValueError as error:
        parser.exit(2, f'{error}\n')


if __name__ == '__main__':
    main()
