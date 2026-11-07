Feature: 身份与网络边界
  入口安全和任务调度是分别验收的能力。

  # evidence: tests/api.rs::unauthorized_upload_cannot_create_state
  @verified @automated @p0
  Scenario: 未授权请求不产生任务状态
    Given 请求没有有效 Bearer token
    When 访问任务接口
    Then 返回 401 且不创建任务目录

  # evidence: tests/api.rs::malformed_and_oversized_uploads_remove_only_their_own_staging
  @verified @automated @p0
  Scenario: 非法上传只清理本次临时数据
    Given 已授权请求上传畸形或超大输入
    When 接收失败
    Then 只删除本次请求创建的暂存目录
    And 相邻文件保持不变

  @planned @p1
  Scenario: Warpgate 可选认证和录制
    Given 部署者需要多用户 SSO 或双因素认证
    When 将 Warpgate 放在统一入口前
    Then 它承担目标授权和会话录制
    And SSHPool 继续承担构建调度

  @planned @p2
  Scenario: 自动接入 NAT 后的节点
    Given 节点不能接受公网入站
    When 使用经验证的反向通道或 Headscale 配置
    Then 节点可以接单而不覆盖现有 LAN 路由
    And 已可用的 LAN 公网映射或 frp 入口无需被替换

  # evidence: docs/validation.md#access-network
  # evidence: tests/access_network.rs::https_verifies_the_certificate_and_short_lived_credentials_can_be_revoked
  @verified @automated @p1
  Scenario: 跨不可信网络的控制面
    Given 工作台与控制面跨越不可信网络
    When 传输任务输入与访问 token
    Then 使用校验证书的 HTTPS 或 SSH 隧道
    And 可短期签发并撤销访问凭据

  # evidence: tests/access_network.rs::a_read_only_credential_can_read_but_cannot_change_node_state
  # evidence: docs/validation.md#access-network
  @verified @automated @p1
  Scenario: 短期凭据按主体限制权限
    Given 一条签发给工作台的短期凭据
    When 它调用读接口与写接口
    Then 读接口返回 200
    And 未被授予的权限返回 403 且写明缺哪一项
    And 没有 scopes 字段的旧记录降级为只读
