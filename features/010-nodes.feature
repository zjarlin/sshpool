Feature: 显式登记异构 SSH 节点
  节点 SSH 凭据保留在控制面，构建容器不接触它们。

  # evidence: docs/validation.md#nodes
  @verified @manual @p0
  Scenario: 使用现有别名接入多台主机
    Given 管理员有可用的 SSH 别名和主机校验
    When 执行 node add 和 doctor
    Then 独立报告 Linux ARM64 Linux x86_64 和 macOS 的能力
    And 单节点错误不吞掉其他节点的探测结果

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
  @verified @automated @p1
  Scenario: 在线禁用和恢复节点
    Given 管理员需要维护某个 Worker
    When 执行 node disable 或 node enable
    Then 不重启控制面也能调整接单状态
    And 仍有活动任务时拒绝禁用
    And 连续切换多个节点后重启仍保留全部选择
