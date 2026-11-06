Feature: SSI 设备访问的脏页和反向映射
  这些是实际 KVM 接口实验，不代表完整设备一致性或数据库恢复已经通过。

  # evidence: docs/evidence/ssi-device-memory-20261105.txt
  @verified @p0
  Scenario: 无 vCPU 的设备写入更新脏页位图
    Given 两个隔离节点各自运行固定哈希的 PF5 研究内核
    When 通过 DSM MEMCPY 跨两个页面写入并读取数据
    Then 内容一致且只有对应两页的 dirty bitmap 置位
    And 只读操作不会标脏且后续单页写入只标记该页
    And 无效源地址返回 EFAULT 且零长度成功和溢出被拒绝
    And 每个实例成功关闭后才输出通过

  # evidence: docs/evidence/ssi-device-memory-20261105.txt
  @verified @p0
  Scenario: 奇数页号和映射清理不会被误认为 KVM 锁
    Given DSM 编码页号与 KVM 普通页表映射使用不同的互斥机制
    When 删除重建含奇偶页的内存槽并创建删除地址别名
    Then 跨页访问保留原页号且活动和备份映射可以释放
    And 同一用户内存对应多个客体地址的链表清理可以完成
    And 测试结束没有遗留进程或 DSM 线程

  # evidence: docs/evidence/ssi-device-memory-20261105.txt
  @verified @p0
  Scenario: DSM 拒绝无法记录设备脏页的 dirty ring 模式
    Given DSM 设备写入没有关联的运行中 vCPU
    When 先开启 dirty ring 再开启 DSM 或按相反顺序开启
    Then 两种顺序的第二步都返回 EOPNOTSUPP
    And 不通过删除内核 WARN 来假装支持该组合

  @partial @p0
  Scenario: 短 DMA 传输释放完整映射范围
    Given 设备映射长度大于实际传输长度
    When 完成短传输或取消零字节传输
    Then 取消固定的页面范围与最初固定范围一致
    And 在双节点上验证远端可重新取得所有页面
    And 核对重复取消和设备复位后的引用计数

  @planned @p0
  Scenario: 所有地址别名和异常路径都正确记录设备写入
    Given 同一用户页对应多个开启脏页记录的客体内存槽
    When 设备写入以及用户缓冲区出现部分复制失败
    Then 每个受影响的客体映射都被标脏
    And 未映射范围不会被当成可信内核缓冲区访问
    And 并发删除内存槽也不会遗漏或重复释放映射

  # evidence: docs/evidence/ssi-rtc-20261106.json
  @research @p0
  Scenario: 页所有权与副本集合在并发交接中一致
    Given 双节点客体交错进行 vCPU 读写和设备访问
    When 页所有者转移并降级共享权限
    Then 本地仍可读的页面保留正确的副本集合成员
    And 读页请求不会因缺失本地副本标志退出服务线程
    And 检查失败会终止相关请求而不让另一端无限等待
    And 不通过删除 WARN 或盲目补位掩盖未定位的一致性问题

  # evidence: docs/evidence/ssi-copyset-retry-20261106.json
  @verified @p0
  Scenario: 只读固定页面触发读请求重试时保留副本集合
    Given 每台独占实验 VM 用真实 KVM 接口建立一页所有权并只读固定页面
    When 合成远端读请求经至少两次真实服务线程重试后解除固定
    Then PF15 基线复现处理线程返回 EINVAL 且未收到页面
    And PF16 返回完整页面正确副本集合版本与事务号
    And 无固定页面的对照和两台实验 VM 的运行证据均保留
    And 检查器拒绝溢出缺失线程或不完整锁配对的跟踪
    And 不把单页回环对照视为所有固定模式并发写入或完整 SSI 验收

  # evidence: docs/evidence/ssi-pin-lifecycle-20261106.json
  @verified @p0
  Scenario: 关闭入口拒绝仍持有固定引用或在途固定调用的实例
    Given PF22 对照在两台独占实验 VM 复现读页仍等待却封闭入口并拒绝解除固定
    When PF23 在读引用仍存在或跨页固定尚等待远端响应时申请封闭
    Then 返回 EBUSY 且保持入口开放并允许后续解除固定
    And 已完成的固定调用仍由读写引用计数追踪而不是普通 ioctl 计数代替
    And 解除后对端收到正确页面且全部引用归零时才封闭成功
    And 不把本地引用清零当作后台设备停止或全局关闭证明

  # evidence: docs/evidence/ssi-pin-lifecycle-20261106.json
  @verified @p0
  Scenario: 固定引用按类型配对并在部分失败时保留原有引用
    Given 两台 PF23 实验 VM 分别运行跨页重叠读写固定与缺失反向映射探针
    When 遇到重复解除错误类型或部分范围无匹配引用
    Then 返回 EINVAL 且不提前减少有效引用
    And 部分固定失败只回滚本次新增引用并保留此前已有引用
    And 持有引用时删除移动修改标志与新增别名都返回 EBUSY
    And 释放后可重建内存槽且真实内核事件与原始查询 ABI 一致

  @research @p0
  Scenario: 固定操作与设备后台清理在截止时间内完成
    Given 设备持有跨调用的页面引用且其他固定操作等待远端页面或共享锁
    When 执行设备复位正常关闭或遇到无响应的远端
    Then 解除路径不因其他固定操作的反向依赖而永久等待
    And 取消与超时释放本次资源但保留既有引用和首次错误
    And 全部设备后台任务停止后才允许最终 DSM 关闭确认
