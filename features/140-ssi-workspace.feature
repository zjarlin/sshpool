Feature: 从普通 SSH 登录真实的共享 Linux 客体
  这里的 shell 必须属于跨节点客体，不能连接入口宿主后冒充 SSI。

  # evidence: docs/ssi-workspace.md
  @verified @p0
  Scenario: 单节点对照先验证发行版与 OpenSSH 客体
    Given 固定哈希的官方 Linux 内核和隔离 initramfs
    When 用普通 KVM 启动并提供回环 SSH 入口
    Then 使用已核对主机密钥与显式导入的公钥完成登录
    And 密码登录关闭且未挂载宿主目录
    And 能执行命令和通过 SFTP 收发实验文件

  @partial @p0
  Scenario: SSH 会话中的同一进程实际使用两个执行节点
    Given 两节点运行一致的发行版内核和 OpenSSH 客体镜像
    When 普通 SSH 客户端连接该客体并运行四线程内存测试
    Then 看到客体的 Linux 内核与四个在线 CPU
    And 同一进程的线程计算与页面交接校验通过
    And 节点侧证据确认 vCPU 分属两个 KVM 实例

  @planned @p0
  Scenario: 实验文件系统与宿主数据没有共享挂载
    Given SSH 客体只使用自身 initramfs 和内存文件系统
    When 通过 SFTP 创建读取和删除测试文件
    Then 操作只发生在客体内存中
    And 明确告知关机即丢失且尚不支持持久化工作区
    And 不将该结果视为 Docker 和数据库验收
