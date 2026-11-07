Feature: 可解释且谨慎的任务生命周期
  断线不等于远程进程已经停止。

  # evidence: docs/validation.md#jobs
  @verified @manual @p0
  Scenario: 从提交到产物交付
    Given 任务输入已验证
    When 容器执行完毕
    Then 日志退出码和显式产物返回工作台
    And 只有核验任务标签后才能删除容器

  # evidence: tests/api.rs::restart_marks_queued_work_interrupted_without_replaying_it
  @verified @automated @p0
  Scenario: 重启不盲目重放
    Given 控制面磁盘存在未完成任务
    When 控制面重新启动
    Then 核对旧容器并记录中断
    And 不自动重放旧命令

  # evidence: tests/boundaries.rs::retry_and_path_policies_fail_closed
  @verified @automated @p0
  Scenario: 重试必须满足幂等和禁网
    Given 项目请求自动重试
    When 项目未声明幂等或开启网络
    Then 配置校验失败

  # evidence: tests/boundaries.rs::uncertain_cleanup_quarantines_the_worker
  # evidence: tests/watchdog_live.rs::stopped_remote_container_is_proven_and_removed
  # evidence: tests/watchdog_live.rs::running_container_is_never_waved_through
  # evidence: tests/api.rs::reconcile_proves_an_expired_lease_without_restarting
  @verified @automated @p0
  Scenario: 故障切换必须先确认旧任务结束
    Given 首个 Worker 发生基础设施错误
    And 任务幂等禁网且仍有重试额度
    When 旧容器确认不存在或删除
    Then 尝试另一个兼容 Worker
    But 确定的编译失败不重试
    And 仍在运行的容器即使租约过期也拒绝放行

  # evidence: tests/api.rs::reconcile_waits_for_the_recorded_watchdog_lease
  # evidence: tests/api.rs::reconcile_requeues_only_proven_idempotent_offline_jobs
  # evidence: tests/api.rs::reconcile_never_claims_cleanup_for_a_running_job
  # evidence: src/runner.rs::attempted_nodes_include_attempts_without_a_recorded_outcome
  # evidence: tests/boundaries.rs::a_later_success_cannot_clear_an_older_worker_quarantine
  @verified @automated @p0
  Scenario: 隔离状态可以在线解除而不重启控制面
    Given 某台 Worker 上一次容器清理未得到确认
    When SSH 不可达且容器租约尚未到期
    Then 报告剩余秒数并继续拒绝把任务派给该 Worker
    When 租约到期或远端确认容器已停止
    Then 记录证据来源并解除隔离
    And 只有幂等禁网且仍有重试额度的任务才重新排队
    And 已执行过的 Worker 不会因为重跑被再次选中

  @partial @manual @p0
  Scenario: 取消与超时
    Given 任务正在运行
    When 用户取消或超过执行期限
    Then 请求停止并核对任务容器
    And 清理无法确认时标记中断并隔离节点
