Feature: 在业务预留和兼容性约束内调度
  首版分派整个构建，不把多个节点内存加给单进程。

  # evidence: tests/hardware_live.rs::an_arm64_workbench_offloads_an_amd64_build_to_an_independent_worker
  @verified @automated @p0
  Scenario: 使用工作台之外的真实硬件
    Given 入口工作台为 ARM64 且独立 Linux Worker 为 x86_64
    When 从同一 SSH 入口提交 linux/amd64 任务
    Then Worker 本机 Docker 中出现带该任务标识的计算进程
    And 工作台没有执行该任务的容器
    And 计算结果回传后校验一致且远端清理得到确认

  # evidence: tests/hardware_live.rs::workbench_and_pool_capabilities_are_reported_separately
  @verified @automated @p0
  Scenario: 工作台指标与计算池能力分开报告
    Given 客户端只连接统一 SSH 工作台
    When 执行 uname free 或 top
    Then 显示该工作台的内核与资源
    And sshpool status 分节点报告资源快照
    And 任务记录标明实际 Worker 而非伪造合并内存

  # evidence: tests/scheduling_lock.rs::an_unreachable_worker_does_not_hold_the_scheduling_lock
  @verified @automated @p0
  Scenario: 探测不阻塞任务派发
    Given 一台节点 TCP 可连接但从不发送 SSH banner
    When 控制面在探测这台节点的同时派发其他任务
    Then 调度锁不被探测占用
    And 探测仍按 ConnectTimeout 收敛并记录原因
    And 并发探测只产生一轮 SSH 且共享同一份快照
    And 没有探测快照的节点被拒绝分配
    And 探测期间被停用的节点不会接到任务

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

  # evidence: tests/api.rs::limited_queue_waits_once_and_cancel_wakes_the_runner
  @verified @automated @p1
  Scenario: 有限期持久队列
    Given 暂时没有足够资源而用户允许等待
    When 提交任务
    Then 持久化排队期限和优先级
    And 无候选节点时保持排队且只记录一次等待事件
    And 取消或可用节点变化会结束等待
    And 默认零等待仍立即失败

  # evidence: tests/api.rs::restart_retains_only_a_valid_unexpired_queue_request
  @verified @automated @p1
  Scenario: 重启只恢复仍有效的排队请求
    Given 控制面在任务被节点领取前重启
    When 恢复持久化任务
    Then 仅源码合法且原期限未过的未尝试任务继续排队
    And 恢复不延长绝对截止时间
    And 过期缺失或损坏源码的任务按谨慎语义中断

  @planned @p2
  Scenario: 根据预计完成时间选择节点
    Given 多个节点都满足硬约束
    When 排序候选节点
    Then 综合输入缓存网络成本工具链和历史运行时间
    And 不仅依据静态优先级和 CPU 负载
