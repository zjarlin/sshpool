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

  # evidence: tests/api.rs::node_prepare_pulls_before_approving_and_reaches_the_next_decision
  # evidence: tests/api.rs::a_failed_pull_leaves_the_configuration_unchanged
  # evidence: tests/api.rs::the_pull_does_not_hold_the_scheduling_lock
  # evidence: tests/scheduling_live.rs::an_online_image_prepare_takes_effect_without_a_restart
  # evidence: docs/evidence/node-prepare-20261108.json
  @verified @automated @p1
  Scenario: 在线准备并授权镜像
    Given 控制面正在运行，某台 Worker 上还没有某张镜像
    When 执行 node prepare 指定该节点与镜像
    Then 控制面先在 Worker 上真实拉取，成功后才写入允许清单
    And 不重启控制面，下一次提交就能用这张镜像运行并确认清理
    But 拉取失败时配置与内存都不变
    And 已经授权过的镜像不重复拉取

  # evidence: tests/api.rs::node_prepare_refuses_to_overwrite_an_external_config_edit
  @verified @automated @p2
  Scenario: 准备镜像不覆盖运行期间的手改
    Given 控制面运行期间有人直接编辑了 config.toml
    When 执行 node prepare
    Then 在发起远端拉取之前就拒绝
    And 配置文件保持手改后的内容

  # evidence: tests/boundaries.rs::the_image_name_rule_is_shared_by_builds_and_preparation
  # evidence: tests/api.rs::node_prepare_rejects_bad_input_before_touching_the_worker
  @verified @automated @p2
  Scenario: 非法镜像名不触达远端
    Given 镜像名为空、以连字符开头或含空白
    When 提交构建或执行 node prepare
    Then 两处用同一条规则拒绝
    And Worker 上没有发生任何拉取

  # evidence: tests/api.rs::node_revoke_removes_the_approval_and_reaches_the_next_decision
  # evidence: tests/scheduling_live.rs::revoking_an_image_takes_effect_without_a_restart
  # evidence: docs/evidence/node-revoke-20261108.json
  @verified @automated @p1
  Scenario: 在线撤销镜像授权
    Given 控制面正在运行，某台 Worker 已获准使用某张镜像
    When 执行 node revoke 指定该节点与镜像
    Then 只收缩允许清单，不删除 Worker 上的镜像层
    And 不重启控制面，下一次提交同一张镜像就在派发前被拒绝且不创建容器
    But 重复撤销返回 revoked=false，不写盘

  # evidence: tests/api.rs::node_revoke_refuses_while_that_image_is_running
  @verified @automated @p1
  Scenario: 运行中的镜像不能被撤销
    Given 某台 Worker 上的活动任务正在使用某张镜像
    When 执行 node revoke 撤销这张镜像
    Then 拒绝，错误里带 job id
    And 允许清单与 config.toml 都不变
    But 撤销另一张没有在跑的镜像仍然成功

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
