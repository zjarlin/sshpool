# sub2api 应用迁移演练

入口是 `tests/sub2api_migration_live.rs`。Rust 测试通过现有 OpenSSH transport 上传 `rehearse.py` 与 `src/migration.rs` 的指纹程序，Python 在 Worker 上编排一次性 Docker 环境；Rust 最后独立解析两次迁移及两次旧实例冻结观测的完整指纹，并复核操作日志。

```sh
SSHPOOL_LIVE_NODE=okm182-lan \
  cargo test --locked --test sub2api_migration_live -- --ignored --nocapture
```

Worker 需要 Python 3.9+、Docker，以及脚本中列出的本地镜像。应用固定为 `8c06464b` 对应的镜像 digest。演练不自动拉取镜像。全部容器、卷和网络均以新 UUID 命名并带 `io.sshpool.rehearsal` 标签，不能把已有实例作为输入。数据库只使用新建的 `demo` 库与合成用户；应用不配置外部供应商。

应用、PostgreSQL、Redis 分别运行在 A/B/return 的内部网络。入口 Caddy 单独连接桥接网络，只发布宿主 `127.0.0.1` 的随机端口。所有业务请求都通过这个固定端口，响应头验证实际处理请求的一侧。

演练按以下顺序执行：

1. 创建 A，登录；SQL 仅生成合成兑换码，通过真实用户兑换 API 入账。
2. 入口切到维护响应，停止 A 的应用与后台 worker，确认进程正常退出。
3. 在应用停机后、数据引擎冻结前调用应用自带的认证缓存失效入队函数，并植入对应陈旧缓存值。随后冻结两个数据引擎、真实试写验证拒绝，保存 PostgreSQL、Redis、应用配置卷并记录 SHA-256。
4. 校验备份后恢复到 B 的新卷；启动应用前比较全部表、序列、Redis 键和配置文件。
5. 切到 B，验证旧 access token、refresh session、新登录、重复充值去重、新充值和序列推进；等待真实认证缓存失效 worker 消费队列，确认陈旧缓存值被删除。
6. B 再次停写、备份，恢复到原侧的全新卷，再切回。B 上新增的充值必须保留；重复请求不能再次入账，返回侧还必须能继续产生新的序列值。
7. 核对两个旧实例一直冻结，正反向备份仍完整；清理本轮资源并核查残留。

Redis 比较使用精确绝对到期毫秒；原始指纹与共同比较时刻同时留档，只排除届时已到期的键。永久键、未到期键、表内容和序列的任何差异都使演练失败。集合和哈希先排序，嵌套与二进制数据用 MessagePack 编码后求摘要。

原始结果存于 `target/live-evidence/sub2api-migration/<uuid>/`。其中的 `rehearsal.tar` 保留两份恢复包、报告、逐步记录；`migration-journal.jsonl` 为完整成功运行生成可独立校验的摘要链。备份包含本轮合成凭据，只在私有的、被 Git 忽略的目录留档。失败运行仍保留步骤与失败报告，清理错误会使测试失败。

离线准入检查：

```sh
python3 -m unittest discover -s scripts/sub2api-migration -p 'test_*.py'
```

这里验收的是同一 Worker 上的隔离演示迁移，充值账本和认证缓存失效队列代表本轮覆盖的业务路径。供应商推理扣费、图片队列、长连接、跨主机传输、增量复制和网络分区接管仍需各自验收。维护期间有明确停机窗口；这不是生产自动高可用的证据。
