Feature: 一个稳定的 Linux SSH 工作台
  客户端只配置一个 SSH 地址，编辑和文件留在稳定工作台。

  # evidence: docs/validation.md#ssh
  @verified @manual @p0
  Scenario: 登录统一入口
    Given 已固定 Linux 工作台的主机公钥
    When 客户端执行 ssh sshpool
    Then 会话运行在稳定宿主的 Linux 虚拟机
    And 工作台没有挂载宿主公司的目录

  # evidence: tests/boundaries.rs::gateway_preserves_full_duplex_bytes_and_half_close
  @verified @automated @p0
  Scenario: SSH 字节透明传输
    Given 前端代理和 OpenSSH 后端建立连接
    When 双方发送二进制数据并半关闭输入
    Then 双向内容与 EOF 语义保持一致

  # evidence: scripts/check-ssh-parity.sh
  # evidence: docs/evidence/ssh-parity-20261107.json
  @verified @automated @p0
  Scenario: 标准文件传输和端口转发
    Given 统一入口使用后端 OpenSSH 认证
    When 客户端使用 PTY SFTP scp rsync 或本地端口转发
    Then 操作效果与直连该工作台一致
    And 两个入口呈现同一主机公钥

  @planned @p1
  Scenario: IDE 和 AI 客户端兼容矩阵
    Given 一个全新客户端只配置统一 SSH 地址
    When VS Code Remote SSH JetBrains Gateway 或 AI 远程主机连接
    Then 安装组件和重新连接均有实际验收记录
