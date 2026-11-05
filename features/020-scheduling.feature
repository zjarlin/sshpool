Feature: 在业务预留和兼容性约束内调度
  首版分派整个构建，不把多个节点内存加给单进程。

  # evidence: docs/validation.md#hardware-proof
  @verified @manual @p0
  Scenario: 使用工作台之外的真实硬件
    Given 入口工作台为 ARM64 且独立 Linux Worker 为 x86_64
    When 从同一 SSH 入口提交 linux/amd64 任务
    Then Worker 本机 Docker 中出现带该任务标识的计算进程
    And 工作台没有执行该任务的容器
    And 计算结果回传后校验一致且远端清理得到确认

  # evidence: docs/validation.md#hardware-proof
  @verified @manual @p0
  Scenario: 工作台指标与计算池能力分开报告
    Given 客户端只连接统一 SSH 工作台
    When 执行 uname free 或 top
    Then 显示该工作台的内核与资源
    And sshpool status 分节点报告资源快照
    And 任务记录标明实际 Worker 而非伪造合并内存

  # evidence: tests/boundaries.rs::scheduler_protects_reserves_platform_and_concurrent_slots
  @verified @automated @p0
  Scenario: 资源与架构硬过滤
    Given 节点有内存磁盘负载并发或平台不满足要求
    When 控制面选择 Worker
    Then 排除该节点并保留原因
    And 已接收任务的资源计入预约

  # evidence: tests/boundaries.rs::uncertain_cleanup_quarantines_the_worker
  @verified @automated @p0
  Scenario: 不给状态未知的节点继续分配
    Given 旧任务容器清理没有得到确认
    When 调度下一项任务
    Then 隔离该 Worker
    And 核对成功后才允许重新接单

  @planned @p1
  Scenario: 有限期持久队列
    Given 暂时没有足够资源而用户允许等待
    When 提交任务
    Then 持久化排队期限和优先级
    And 节点恢复后重新调度
    And 控制面重启不丢失排队请求

  @planned @p2
  Scenario: 根据预计完成时间选择节点
    Given 多个节点都满足硬约束
    When 排序候选节点
    Then 综合输入缓存网络成本工具链和历史运行时间
    And 不仅依据静态优先级和 CPU 负载
