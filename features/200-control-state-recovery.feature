Feature: 控制面任务状态跨物理故障域恢复
  已确认任务状态要能在单台物理主机失效后恢复；运行中的 CPU、内存与临时容器不承诺继续。

  # evidence: src/mirror.rs::startup_requires_the_configured_number_of_distinct_live_domains
  @verified @automated @p0
  Scenario: quorum 2 允许本地加一个远端确认
    Given 控制面配置两台独立物理故障域的副本
    And 每次发布要求两个不同故障域确认
    When 本地控制面和任意一台远端副本可用
    Then 已确认状态仍能恢复
    And 本机已有任务而全部远端离线时拒绝宣称满足启动 quorum
    And 本机目录丢失时可由保留提交回执的一个远端副本恢复

  # evidence: src/mirror.rs::quorum_three_requires_two_remote_commit_domains
  @verified @automated @p0
  Scenario: quorum 3 必须有两个远端独立确认
    Given 配置要求本地和两台远端故障域共同确认
    When 只有一台远端保留可读提交
    Then 不以一台副本的证明冒充三故障域提交
    And 三台实际可读故障域都一致时才允许恢复该版本

  # evidence: src/mirror.rs::unreadable_newer_published_revision_cannot_fall_back_to_an_older_quorum
  @verified @automated @p0
  Scenario: 新发布的已确认版本损坏时不静默使用旧状态
    Given 一个 revision 已由达到配置 quorum 的故障域发布
    When 该 revision 的归档或提交证明损坏
    Then 恢复失败并保留旧目录供诊断
    And 不用旧 revision 冒充最新已确认状态

  # evidence: src/mirror.rs::startup_checks_health_quorum_even_when_local_jobs_exist
  @verified @automated @p0
  Scenario: 本机已有状态仍核对远程故障域
    Given 本机存在任务记录
    And 配置承诺本地加远端冗余
    When 启动时没有远程副本可达
    Then 拒绝启动并且不删除本机文件
    And 不以目录存在证明远程副本仍可恢复

  # evidence: tests/boundaries.rs::enabled_replicas_require_distinct_failure_domains_and_positive_quorum
  @verified @automated @p0
  Scenario: 重复主机与重复故障域不能增加 quorum
    Given 两台 SSH 目标可能属于同一物理主机
    When 登记状态副本
    Then 重复主机身份或重复 failure domain 被拒绝
    And 保留字 local 不能作为远端故障域
    And 零副本配置不能声称跨机 quorum

  # evidence: tests/boundaries.rs::replica_namespace_cannot_escape_the_dedicated_remote_root
  @verified @automated @p0
  Scenario: 副本命名空间不能逃逸专用目录
    Given 配置用一个命名空间隔离多组控制面状态
    When 命名空间包含空值、绝对路径、斜杠或父目录片段
    Then 配置校验拒绝该副本
    And 远端写入只允许发生在 ~/.sshpool-replica 下

  # evidence: src/state.rs::failed_write_cannot_reuse_a_reserved_revision
  @verified @automated @p0
  Scenario: 失败写入不回用旧版本号
    Given 一个任务已预留 revision 并在发布中失败
    When 控制面重启并继续更新
    Then 新候选使用更大 revision
    And 失败的候选不能被当作已提交状态
    And 版本溢出明确失败而不回绕

  # evidence: src/mirror.rs::a_candidate_without_commit_proof_is_not_recoverable
  @verified @automated @p0
  Scenario: 准备完成但未提交的候选不可恢复
    Given 副本只有候选清单和内容对象
    When 候选没有提交证明
    Then 不向恢复方发布该状态
    And 不把对象已经落盘当成任务已经确认

  # evidence: src/mirror.rs::same_revision_with_different_bundle_digests_is_a_conflict
  @verified @automated @p0
  Scenario: 同一版本内容不一致时拒绝恢复
    Given 两个故障域报告同一个任务 revision
    When 任务归档摘要不同
    Then 报告副本冲突并拒绝选择任意一方
    And 只有任务元数据、源码快照、日志、事件与已声明产物一致时才可恢复

  # evidence: src/mirror.rs::same_revision_with_different_receipts_is_a_conflict
  @verified @automated @p0
  Scenario: 同一版本的不同提交回执不能拼成 quorum
    Given 两个故障域报告相同 revision 和归档摘要
    When 两份远端证明引用了不同的本地提交回执
    Then 报告副本冲突并拒绝选择任意一份
    And 不从两个不同提交尝试拼接故障域确认

  # evidence: src/mirror.rs::duplicate_replica_copies_do_not_satisfy_quorum
  @verified @automated @p0
  Scenario: 同一故障域的多份副本不能重复计数
    Given 两个别名指向同一物理主机
    When 二者都保存相同 revision
    Then quorum 只计算一次该 failure domain
    And 不从两份同盘副本推断独立容灾

  # evidence: src/mirror.rs::recovery_requires_quorum_and_rejects_conflicting_equal_versions
  @verified @automated @p0
  Scenario: 已完成尝试只通过新 quorum 公开
    Given 容器执行和清理结果已经得到
    When 控制面准备重试或发布终态
    Then 先为带结果的候选达到配置 quorum
    And 未能确认 quorum 时不宣称成功或持久完成

  # evidence: src/runner.rs::confirmed_cleanup_is_required_before_worker_failover
  @partial @p0
  Scenario: 旧 Worker 清理未确认时禁止换机重跑
    Given 任务幂等、禁网且尚有重试额度
    And 旧 Worker 的实际容器状态不能证明已经停止
    When SSH 超时或删除命令失败
    Then 任务进入 interrupted 并隔离旧 Worker
    And 控制面不自动分发到另一 Worker
    And 只有远端看门狗证明旧容器终止后才允许后续自动重跑

  # evidence: docs/validation.md#control-state-recovery
  @partial @manual @p0
  Scenario: 控制面主机丢失后从远端故障域恢复
    Given 两个独立物理故障域已持有内容寻址归档
    When 控制面工作和状态目录不可用
    Then 从仍可读的故障域恢复任务、日志、事件与产物引用
    And 恢复后配置、token 和私钥由运维从独立备份重新提供
    And 只有实际重跑故障注入后才把整个场景标为已验证

  @research @p0
  Scenario: PostgreSQL Redis 事务一致性单独验收
    Given sub2api PostgreSQL 与 Redis 的现有镜像、版本和持久卷
    When 注入应用、数据库、网络或整机故障
    Then 证明已确认事务的 RPO 与 RTO
    And 旧写入方无法继续提交
    And 不把任务状态复制、Ceph 健康或容器重启等同于数据库 HA
    And 在真实服务和演示数据验收前保持数据库迁移计划
