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

  @partial @manual @p0
  Scenario: 故障切换必须先确认旧任务结束
    Given 首个 Worker 发生基础设施错误
    And 任务幂等禁网且仍有重试额度
    When 旧容器确认不存在或删除
    Then 尝试另一个兼容 Worker
    But 确定的编译失败不重试

  @partial @manual @p0
  Scenario: 取消与超时
    Given 任务正在运行
    When 用户取消或超过执行期限
    Then 请求停止并核对任务容器
    And 清理无法确认时标记中断并隔离节点
