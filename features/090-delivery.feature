Feature: 部署发布和运维
  开源仓库不能包含真实节点地址与公司凭据。

  # evidence: docs/validation.md#deployment
  @verified @manual @p0
  Scenario: 稳定宿主登录后启动
    Given Mac 上存在独立 Lima 工作台
    When 启用专用 LaunchAgent
    Then 登录后启动工作台与控制面
    And 服务不会修改公司既有数据目录

  @partial @p0
  Scenario: 可审查的公开源码交付
    Given 代码和文档完成检查
    When 发布到 GitHub
    Then 仓库使用 MIT 许可且包含锁定依赖和 CI
    And 发布内容不含私钥 token 或真实节点地址

  @planned @p1
  Scenario: 跨平台版本发布
    Given Linux 和 macOS 构建全部通过
    When 发布版本标签
    Then 提供经过兼容性验证的二进制和校验和
    And 说明支持的系统版本

  @planned @p1
  Scenario: 升级迁移和状态保留
    Given 有历史配置和任务归档
    When 升级或清理到期任务
    Then 先验证格式和目录归属
    And 有可恢复的备份与明确保留策略
