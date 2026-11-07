Feature: 运行时与资源隔离
  保护宿主公司数据和业务资源。

  # evidence: src/isolation.rs::host_access_and_writable_root_are_rejected
  # evidence: tests/isolation_live.rs::declared_isolation_holds_on_a_real_container
  # evidence: tests/isolation_live.rs::tampered_container_is_refused_before_start
  @verified @automated @p0
  Scenario: 容器无宿主文件权限
    Given 使用预批准且不声明 VOLUME 的镜像
    When 创建构建容器
    Then 使用非 root 只读根文件系统和空 capability
    And 没有宿主 bind mount 或 Docker socket
    And 默认网络关闭
    But 容器必须在启动前按真实 runtime 配置复核
    And 复核失败时停在 Created 状态且不启动

  # evidence: src/isolation.rs::resource_limits_must_match_the_request
  # evidence: src/isolation.rs::non_executable_workspace_is_rejected
  # evidence: tests/isolation_live.rs::declared_isolation_holds_on_a_real_container
  @verified @automated @p0
  Scenario: 工作空间和执行资源受限
    Given 任务配置 CPU 内存进程日志工作空间与时间限额
    When 超过限额
    Then 对应资源控制拒绝分配或终止任务
    And 工作区 tmpfs 被计入任务内存
    And 工作区允许执行编译产物而临时目录禁止执行
    And 实际 cgroup 上限必须与请求一致

  # evidence: src/scheduler.rs::business_budget_allows
  # evidence: tests/boundaries.rs::swap_usage_above_the_budget_stops_new_work
  # evidence: tests/boundaries.rs::a_kernel_without_psi_cannot_satisfy_a_pressure_budget
  # evidence: tests/boundaries.rs::disk_water_level_is_enforced_as_an_available_floor
  # evidence: tests/boundaries.rs::an_over_budget_node_is_excluded_by_the_hard_filter_not_outranked
  # evidence: tests/metrics.rs::a_measured_but_over_budget_node_stays_ready_and_loses_business_budget
  # evidence: tests/scheduling_live.rs::an_over_budget_host_stops_taking_work_before_any_container_exists
  # evidence: docs/evidence/isolation-slo-20261108.json
  @partial @automated @p1
  Scenario: 业务 SLO 实测
    Given 业务持续承受基线和峰值流量
    When Worker 并行执行构建
    Then 测量 swap 用量 内存压力 IO 压力和磁盘水位
    And 超出预算时暂停接单
    But 业务延迟与错误率需要业务侧埋点，尚未测量
    And 只读采样，不主动压测业务峰值

  @research @p2
  Scenario: 比较 Landlock 与 microVM
    Given 使用专门的测试环境
    When 比较 rootless 容器 Landlock seccomp 和 microVM
    Then 使用同一硬件工具链与攻击样本测量
    And 不把 Landlock 的 TCP 端口规则等同于完整网络隔离
    And 不直接采用来源不明的启动耗时
