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
    And 启动日志通过内核时钟与网络错误门槛
    And SFTP 文件往返校验一致且两边 QEMU 正常退出

  @partial @p0
  Scenario: 设备访问遵守跨节点内存一致性
    Given virtio 网卡队列由两个节点上的客体线程访问
    When 设备读取队列描述符并写回完成状态
    Then 队列缓存不能绕过 DSM 页面所有权
    And 单节点对照与双节点 SSH 文件传输分别留有证据
    And 仅出现 sshd 监听或就绪标记不能标记通过

  @research @p0
  Scenario: 跨节点时钟与调度稳定
    Given 客体 vCPU 使用不同 KVM 实例提供的计时信息
    When 重复启动并跨 CPU 检查单调时钟和定时器
    Then 不出现 TSC 偏移计时器队列告警或软锁死
    And 不通过关闭 watchdog 或隐藏告警获得通过结果

  # evidence: docs/evidence/ssi-clock-baseline-20261105.txt
  @verified @p0
  Scenario: 实验文件系统与宿主数据没有共享挂载
    Given SSH 客体只使用自身 initramfs 和内存文件系统
    When 通过 SFTP 创建读取和删除测试文件
    Then 操作只发生在客体内存中
    And 明确告知关机即丢失且尚不支持持久化工作区
    And 不将该结果视为 Docker 和数据库验收
