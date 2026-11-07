Feature: 持久任务审计
  审计能解释失败阶段，不能泄露控制面凭据。

  # evidence: tests/delivery_live.rs::unified_entry_delivers_logs_exit_code_and_artifacts
  @verified @automated @p0
  Scenario: 任务阶段事件
    Given 任务被接收并选择 Worker
    When 执行从输入导入到容器清理
    Then 事件记录包含提交分配创建导入执行导出清理和终态
    And CLI 可以按任务 ID 查询事件

  # evidence: docs/validation.md#access-audit
  @verified @automated @p1
  Scenario: 可查询的用户访问审计
    Given 控制面支持多个授权用户
    When 用户访问状态或提交任务
    Then 记录主体权限决定与请求标识
    And token 私钥和敏感环境值不进入日志

  # evidence: tests/metrics_live.rs::scraping_is_parseable_and_never_writes_the_access_audit
  # evidence: tests/boundaries.rs::metrics_endpoint_cannot_reuse_a_control_plane_port
  # evidence: tests/metrics_live.rs::scraping_without_a_token_is_refused_without_leaking_samples
  # evidence: tests/access_network.rs::the_metrics_port_requires_the_root_token_over_tls
  # evidence: tests/access_network.rs::the_metrics_listener_negotiates_http1_only
  # evidence: tests/boundaries.rs::a_public_metrics_listener_must_be_allowed_explicitly
  # evidence: docs/validation.md#external-observation
  @verified @automated @p2
  Scenario: 外部观测系统
    Given 部署者配置指标和日志后端
    When 任务执行或节点故障
    Then 可以查询排队时间执行时间错误分类与资源水位
    And 抓取必须带根 token，数值不暴露给匿名客户端或借出的短期凭据
