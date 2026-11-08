Feature: SSI 远端设备操作具有可验证的完成边界
  一个客体的本地与远端 vCPU 访问同一设备模型。
  不把设备模拟完成确认等同于磁盘持久化、PCI 总线屏障或数据库事务提交。

  # evidence: docs/evidence/ssi-device-order-20261106.json
  @verified @p0
  Scenario: 远端 MMIO 写入完成后才允许客体继续
    Given 四个客体 CPU 分布在两个专用实验 VM
    And CPU 在同一互斥锁下访问未绑定驱动的 EDU 测试设备
    When 在接收端设备锁之外为每次远端寄存器写入注入五十毫秒延迟
    Then 基线记录可复核的旧值读取
    And 完成确认候选通过相同客体的全部二百五十六次检查
    And 检查器从每次失败明细重算结果并拒绝缺失轮次

  # evidence: docs/evidence/ssi-router-startup-20261108.json
  @partial @p0
  Scenario: 不兼容的设备完成协议在客体启动前失败
    Given 两端的路由协议版本不一致
    When 启动握手校验版本
    Then 双方在首次 KVM_RUN 前返回协议错误
    And 不把旧数据当作 MMIO 完成确认
    And 保留失败日志及实验实例清理证据

  @research @p0
  Scenario: 设备访问故障不能被当作成功完成
    Given 远端设备操作正在发送接收或执行
    When 请求截断确认损坏或连接中断
    Then 明确报告失败而不让客体继续使用未完成的结果
    And 有界地停止相关 vCPU 并回收连接
    And 不因双向设备回调或中断转发引入死锁

  @research @p0
  Scenario: 正常设备关机没有并发销毁错误
    Given 客体已完成操作并请求正常关机
    When 路由线程与主循环同时处理关闭
    Then 等待在途设备请求完成并按顺序销毁设备
    And 两端无段错误或残留线程

  @research @p0
  Scenario: 通用 PIO 和合并 MMIO 具有完整设备顺序
    Given 分布式客体已禁用本地合并 PIO 注册
    When 交错访问端口设备与合并 MMIO 区域并注入延迟或连接故障
    Then 写操作完成与错误有明确的跨节点协议
    And 不把 RTC 索引读取修正当作所有设备的屏障和完成确认

  @research @p0
  Scenario: 持久磁盘与数据库另行验证刷盘语义
    Given 已验证的跨节点 MMIO 与 DMA 访问路径
    When 接入独立实验磁盘及后续 Ceph 存储
    Then 单独验证写屏障刷盘断电恢复与节点故障
    And Docker PostgreSQL 与 Redis 使用独立数据验证恢复一致性
    And 不把同一 ESXi 内的两个 VM 当作物理故障冗余
