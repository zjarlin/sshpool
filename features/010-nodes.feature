Feature: 显式登记异构 SSH 节点
  节点 SSH 凭据保留在控制面，构建容器不接触它们。

  # evidence: tests/nodes_live.rs::existing_aliases_are_reported_per_host_and_failures_stay_isolated
  @verified @automated @p0
  Scenario: 使用现有别名接入多台主机
    Given 管理员有可用的 SSH 别名和主机校验
    When 执行 node add 和 doctor
    Then 独立报告 Linux ARM64 Linux x86_64 和 macOS 的能力
    And 单节点错误不吞掉其他节点的探测结果

  # evidence: tests/scheduling_live.rs::an_unreachable_node_is_reported_but_never_chosen
  @verified @automated @p0
  Scenario: 单节点不可达不吞掉其他节点
    Given 一台节点不可达且优先级高于可达节点
    When 查询状态并提交任务
    Then 不可达节点带着探测原因出现在状态里
    And 可达节点的探测结果不受影响
    And 任务仍然派给可达节点并完成清理

  # evidence: tests/boundaries.rs::unapproved_images_are_rejected_even_when_already_installed
  @verified @automated @p0
  Scenario: 已有业务镜像不自动授权
    Given Worker 安装了包含公司数据的镜像
    When 构建请求未被允许清单批准的镜像
    Then 调度拒绝该任务

  @partial @p1
  Scenario: WSL2 计算节点
    Given Windows 的 SSH 直接进入 WSL2 Linux
    When 探测可执行 Linux 容器的 Docker 引擎
    Then 可以按 Linux 能力登记
    But Windows OpenSSH 的 PowerShell 环境被明确拒绝

  # evidence: tests/api.rs::node_switch_persists_and_rejects_an_active_job
  # evidence: tests/api.rs::node_update_applies_to_memory_and_disk_without_a_restart
  # evidence: tests/scheduling_live.rs::an_online_budget_update_takes_effect_without_a_restart
  # evidence: docs/evidence/node-update-20261108.json
  @verified @automated @p1
  Scenario: 在线禁用和恢复节点
    Given 管理员需要维护某个 Worker
    When 执行 node disable 或 node enable
    Then 不重启控制面也能调整接单状态
    And 仍有活动任务时拒绝禁用
    And 连续切换多个节点后重启仍保留全部选择

  # evidence: tests/api.rs::node_update_applies_to_memory_and_disk_without_a_restart
  # evidence: tests/api.rs::an_online_budget_change_reaches_the_next_scheduling_decision
  # evidence: tests/api.rs::node_update_refuses_to_overwrite_an_external_config_edit
  # evidence: tests/api.rs::clearing_a_budget_is_persisted_to_the_config_file
  # evidence: tests/scheduling_live.rs::an_online_budget_update_takes_effect_without_a_restart
  # evidence: docs/evidence/node-update-20261108.json
  @verified @automated @p1
  Scenario: 在线调整节点调度设置
    Given 管理员要在业务高峰期调整某台 Worker 的资源预留或业务预算
    When 执行 node update 提交只含要改字段的补丁
    Then 不重启控制面也能让新设置进入下一次调度决策
    And 新设置先原子落盘再替换内存视图
    And 取消一项预算与保持原值必须能区分
    But 控制面运行期间手改的配置不会被在线更新静默覆盖
