Feature: 保护源码与公司文件
  任务只接触明确导入的文件和构建镜像。

  # evidence: tests/boundaries.rs::source_snapshot_respects_ignore_rules_and_excludes_credentials
  @verified @automated @p0
  Scenario: 输入仅来自明确项目
    Given 用户指定一个项目而不是整个 home
    When 创建快照
    Then 遵循忽略规则并排除常见凭据文件
    And 不扫描无关目录

  # evidence: tests/boundaries.rs::source_cannot_follow_symlink_to_company_data
  @verified @automated @p0
  Scenario: 不跟随源码链接
    Given 项目文件链接到外部公司数据
    When 创建输入归档
    Then 拒绝该链接而不是读取目标内容

  # evidence: tests/boundaries.rs::tar_traversal_links_and_undeclared_outputs_are_rejected
  @verified @automated @p0
  Scenario: 拒绝危险归档和未声明产物
    Given tar 包含穿越路径软硬链接特殊文件或未声明输出
    When 控制面校验
    Then 拒绝发布归档

  # evidence: tests/boundaries.rs::fetching_never_overwrites_existing_directory
  @verified @automated @p0
  Scenario: 产物回传不覆盖源工程
    Given 输出目录已经存在
    When 用户 fetch
    Then 命令失败且原文件内容不变

  @planned @p1
  Scenario: 一致性快照与内容摘要
    Given 用户编辑文件同时提交构建
    When 创建源码快照
    Then 检测并发变更或使用一致性视图
    And 任务记录包含可复现的源码摘要
