#!/usr/bin/env python3
"""读取 ELF 动态符号表里引用的最高 GLIBC 符号版本（只读，无第三方依赖）。

   scripts/glibc-symbol-version.py <二进制>

与 `readelf --dyn-syms --wide | grep GLIBC_` 等价，但 Mac 上也能跑，
发布流水线与本地演练因此可以共用同一道闸门，而不是「CI 里才有基线检查」。
"""
import struct
import sys

SHT_GNU_VERNEED = 0x6FFFFFFE


def fail(message):
    # 退出码 2 与 release-baseline.sh 一致：表示"基线无法成立"，不是普通用法错误。
    print(message, file=sys.stderr)
    raise SystemExit(2)


def read(path):
    data = open(path, 'rb').read()
    if data[:4] != b'\x7fELF':
        fail(f'{path} 不是 ELF')
    if data[4] != 2:
        fail(f'{path} 不是 64 位 ELF')
    endian = '<' if data[5] == 1 else '>'
    (shoff,) = struct.unpack_from(endian + 'Q', data, 0x28)
    shentsize, shnum = struct.unpack_from(endian + 'HH', data, 0x3A)

    sections = []
    for index in range(shnum):
        # Elf64_Shdr: sh_name u32, sh_type u32, sh_flags u64, sh_addr u64, sh_offset u64,
        #             sh_size u64, sh_link u32, sh_info u32, sh_addralign u64, sh_entsize u64
        base = shoff + index * shentsize
        (kind,) = struct.unpack_from(endian + 'I', data, base + 4)
        (offset,) = struct.unpack_from(endian + 'Q', data, base + 24)
        (size,) = struct.unpack_from(endian + 'Q', data, base + 32)
        (link,) = struct.unpack_from(endian + 'I', data, base + 40)
        sections.append({'kind': kind, 'offset': offset, 'size': size, 'link': link})

    # 版本需求在 .gnu.version_r（SHT_GNU_verneed），不在 .dynsym 的符号名里：
    # 符号名叫 `open64`，要求的最低 glibc 写在这张表里。
    versions = set()
    for section in sections:
        if section['kind'] != SHT_GNU_VERNEED:
            continue
        strings = sections[section['link']]
        cursor = section['offset']
        end_of_section = section['offset'] + section['size']
        while cursor < end_of_section:
            # Verneed: u16 version, u16 cnt, u32 file, u32 aux, u32 next
            (aux_count,) = struct.unpack_from(endian + 'H', data, cursor + 2)
            (aux_offset,) = struct.unpack_from(endian + 'I', data, cursor + 8)
            aux = cursor + aux_offset
            for _ in range(aux_count):
                (name_offset,) = struct.unpack_from(endian + 'I', data, aux + 8)
                (next_aux,) = struct.unpack_from(endian + 'I', data, aux + 12)
                start = strings['offset'] + name_offset
                end = data.index(b'\0', start)
                name = data[start:end].decode('utf-8', 'replace')
                if name.startswith('GLIBC_'):
                    versions.add(name[len('GLIBC_'):])
                if not next_aux:
                    break
                aux += next_aux
            (next_need,) = struct.unpack_from(endian + 'I', data, cursor + 12)
            if not next_need:
                break
            cursor += next_need

    if not versions:
        fail(f'{path}: 没有 GLIBC_ 版本需求（静态链接或非 glibc 目标？）')

    def key(text):
        parts = [int(part) for part in text.split('.')]
        return (parts + [0, 0, 0])[:3]

    return max(versions, key=key)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('用法: glibc-symbol-version.py <二进制>', file=sys.stderr)
        raise SystemExit(1)
    print(read(sys.argv[1]))
