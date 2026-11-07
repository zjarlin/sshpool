# 代码阅读顺序

1. `main.rs`：CLI 输入、控制面启动、构建包装器。
2. `config.rs` / `model.rs`：节点、资源策略和持久任务记录。Rust `struct` 可按 Kotlin `data class` 阅读。
3. `client.rs` → `api.rs`：源码快照上传、任务提交、日志跟随、产物下载。
4. `scheduler.rs`：兼容性与资源门槛，然后排序。
5. `runner.rs`：受限容器创建、导入、执行、导出、核验清理及重启恢复。
6. `transport.rs`：统一的系统 OpenSSH 调用与 shell 参数引用。
7. `archive.rs`：源文件和产物的路径、类型及大小边界。
8. `gateway.rs`：SSH 字节透传，后端负责整个 SSH 协议。
9. `ssi.rs` → `ssi_probe.py`：`sshpool ssi-preflight node-a node-b` 的独立预检；复用 OpenSSH，创建临时空 KVM 对象，拒绝不同原生 TSC 频率。预检不会登记 Worker 或启动 SSI。
10. `migration.rs`：迁移前后的内容级指纹、差异报告与链式操作日志；只做判定，编排在 `tests/migration_live.rs`。
11. `state_audit.rs`：应用状态与持久化约定的清单协议、只读探针脚本（`PROBE_SCRIPT`）与 `assess` 判定；同样只做判定，什么都不改。

示例入口：`sshpool run --project examples/project`。没有插件注册体系，也没有为单一实现增加 trait 或 DI 层。
