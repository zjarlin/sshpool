#!/usr/bin/env python3
"""从 Gherkin 场景标签生成状态索引；只校验规格和证据链接，不冒充 BDD 执行器。"""
from collections import Counter
from pathlib import Path
import argparse
import re

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
statuses = ['verified', 'partial', 'planned', 'research']
rows = []
total = Counter()
for path in sorted((root / 'features').glob('*.feature')):
    count = Counter()
    tags = set()
    evidence = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith('# evidence:'):
            evidence = line.split(':', 1)[1].strip()
        if line.startswith('@'):
            tags.update(re.findall(r'@(\w+)', line))
        if not line.startswith('Scenario:'):
            continue
        state = tags.intersection(statuses)
        if len(state) != 1:
            raise SystemExit(f'{path.name}: each scenario needs exactly one status: {line}')
        state = next(iter(state))
        if state == 'verified':
            if not evidence:
                raise SystemExit(f'{path.name}: verified scenario needs evidence: {line}')
            source = evidence.split('::')[0].split('#')[0]
            if not (root / source).is_file():
                raise SystemExit(f'{path.name}: missing evidence {source}')
            if '::' in evidence:
                function = evidence.split('::')[1]
                if f'fn {function}(' not in (root / source).read_text():
                    raise SystemExit(f'{path.name}: missing test {function}')
        count[state] += 1
        tags.clear()
        evidence = None
    rows.append(f'| [{path.name}]({path.name}) | ' + ' | '.join(str(count[s]) for s in statuses) + ' |')
    total.update(count)
text = '''# 功能验收索引

这些 Gherkin 文件保留完整目标，并明确当前实现边界。它们尚未接入 Cucumber step runner；自动化证据由 Rust 测试提供，真实链路证据在 `docs/validation.md`。不能把语法索引通过当作场景测试通过。

- `@verified`：有明确自动化测试或真实验收记录，场景内有 evidence 引用。
- `@partial`：已有代码，但仍缺全部实现或完整验收。
- `@planned`：后续实现，无当前可用承诺。
- `@research`：需要独立实验，不属于本版生产能力。
- `@p0`：当前版本闭环；`@p1`：下一版本；`@p2`：后续扩展。

下面是场景数量，不是按工作量计算的完成百分比。更新标签后运行 `python3 scripts/feature-status.py`。

| 功能文件 | 已验证 | 部分完成 | 待实现 | 研究 |
| --- | ---: | ---: | ---: | ---: |
'''
text += '\n'.join(rows) + '\n| 合计 | ' + ' | '.join(str(total[s]) for s in statuses) + ' |\n'
target = root / 'features/README.md'
if args.check:
    if not target.exists() or target.read_text() != text:
        raise SystemExit('Feature index is stale; run python3 scripts/feature-status.py')
else:
    target.write_text(text)
print('Scenarios: ' + ', '.join(f'{s}={total[s]}' for s in statuses))
