Feature: SSI 传输等待不挤占客体计算资源
  先在真实 KVM 监听器和独占实验 VM 中验证，不将同一 ESXi 的结果当作跨物理机性能。

  # evidence: docs/evidence/ssi-receive-probes-20261106.json
  @verified @p0
  Scenario: 空闲连接和未完整接收的帧都能让出 CPU
    Given 只有停止的 vCPU 和一个已建立的 DSM 回环连接
    When 不发送请求以及只发送八字节不完整帧
    Then 接收线程等待网络而不反复调用非阻塞接收
    And 两个独立测量窗口中的接收线程总 CPU 用量都低于零点一个核心
    And 关闭连接和 VM 后没有残留的接收线程
    And 保持半帧连接开放时销毁 VM 也能中断等待并回收线程
    And EOF 错误继续被记录而不被伪装成正常协议关闭

  @partial @p0
  Scenario: 等待改动保留事务分流和页面交接正确性
    Given 多个 vCPU 共用同一 DSM 连接并有不同事务编号
    When 指定事务尚未收到数据或者已收到半帧
    Then 空缓冲区时让出接收锁给其他事务
    And 半帧由同一读者接收完整后再解析
    And 跨节点 pvclock 探针与完整客体内存和 SFTP 校验分别通过

  @research @p0
  Scenario: 显式关闭协议区分任务结束与节点故障
    Given 请求仍在传输或者对端已退出
    When 客体正常关机或某个节点失联
    Then 正常关闭须完成双方确认和在途请求排空
    And 故障退出必须传递给客体管理层且不能伪装成干净关机

  @research @p0
  Scenario: 重启实验时处理端口占用与监听失败
    Given 上一实例已经退出但 TCP 连接尚未完全回收
    When 尝试再次创建分布式客体
    Then 前置检查拒绝仍占用实验端口的所有 TCP 状态
    And 内核监听失败应向整个实例传播而不留下半启动节点
    And 退出失败的实例无需重置宿主即可完整回收

  @research @p0
  Scenario: 多物理机性能有可重复的负载对照
    Given 实际部署在不同物理机且网络和资源配额明确
    When 运行相同输入的编译内存和磁盘负载
    Then 分别报告单节点与分布式吞吐和尾延迟
    And 区分有用计算传输等待与采样工具开销
    And 不把客体显示更多 CPU 当作性能相加的证据
