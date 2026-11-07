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

  # evidence: tests/boundaries.rs::source_snapshot_is_deterministic_and_records_sha256
  @verified @automated @p1
  Scenario: 一致性快照与内容摘要
    Given 用户编辑文件同时提交构建
    When 创建源码快照
    Then 检测并发变更或使用一致性视图
    And 任务记录包含可复现的源码摘要

  # evidence: tests/api.rs::source_digest_mismatch_cleans_staging_without_publishing_a_job
  @verified @automated @p1
  Scenario: 上传归档内容与声明摘要一致
    Given 客户端声明源码归档摘要
    When 控制面完成上传
    Then 服务端独立重算并比较摘要
    And 不匹配时删除本次暂存且不发布任务
