# 功能验收索引

这些 Gherkin 文件保留完整目标，并明确当前实现边界。它们尚未接入 Cucumber step runner；自动化证据由 Rust 测试提供，真实链路证据在 `docs/validation.md`。不能把语法索引通过当作场景测试通过。

- `@verified`：有明确自动化测试或真实验收记录，场景内有 evidence 引用。
- `@partial`：已有代码，但仍缺全部实现或完整验收。
- `@planned`：后续实现，无当前可用承诺。
- `@research`：需要独立实验，不属于本版生产能力。
- `@p0`：当前版本闭环；`@p1`：下一版本；`@p2`：后续扩展。

下面是场景数量，不是按工作量计算的完成百分比。更新标签后运行 `python3 scripts/feature-status.py`。

| 功能文件 | 已验证 | 部分完成 | 待实现 | 研究 |
| --- | ---: | ---: | ---: | ---: |
| [001-workspace.feature](001-workspace.feature) | 2 | 1 | 1 | 0 |
| [010-nodes.feature](010-nodes.feature) | 2 | 1 | 1 | 0 |
| [020-scheduling.feature](020-scheduling.feature) | 4 | 0 | 2 | 0 |
| [030-data-boundaries.feature](030-data-boundaries.feature) | 4 | 0 | 1 | 0 |
| [040-lifecycle.feature](040-lifecycle.feature) | 3 | 2 | 0 | 0 |
| [050-build-adapters.feature](050-build-adapters.feature) | 1 | 1 | 2 | 0 |
| [060-isolation.feature](060-isolation.feature) | 0 | 2 | 1 | 1 |
| [070-access-network.feature](070-access-network.feature) | 2 | 0 | 3 | 0 |
| [080-audit.feature](080-audit.feature) | 1 | 0 | 2 | 0 |
| [090-delivery.feature](090-delivery.feature) | 1 | 1 | 2 | 0 |
| [100-ssi-research.feature](100-ssi-research.feature) | 0 | 0 | 0 | 3 |
| 合计 | 20 | 8 | 15 | 4 |
