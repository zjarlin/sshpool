Feature: SSI 客体计时信息保持跨节点一致
  TSC、KVM 纳秒时钟和客体共享的 pvclock 页面必须分别验证。

  # evidence: docs/evidence/ssi-clock-baseline-20261105.txt
  @verified @p0
  Scenario: 时钟探针能区分单节点对照与真实跨节点倒退
    Given 同一个静态探针在四 CPU 单节点与双节点客体运行
    When 同一线程按 0 2 1 3 顺序迁移并检查计数器与时钟
    Then 单节点完成八轮采样和四个不提前到期的定时器
    And 双节点实际 TSC 倒退时返回失败并保留原始读数
    And 检查器拒绝缺失重复错序的采样和时钟倒退
    And 不把有限采样通过当作长期同步证明

  @partial @p0
  Scenario: 冷启动同步 TSC 偏移和 KVM 时钟
    Given 两节点提供可靠的 KVM 时钟快照与一致的原生 TSC 频率
    When 从多次请求中选择往返时间最短的快照
    Then 在启动客体 CPU 前设置并读回每个 vCPU 的 TSC offset
    And 用同一份时间快照初始化目标 KVM 时钟
    And 报告往返时间和估计的不确定范围
    And 客体跨 CPU 时钟探针和 watchdog 同时通过

  @partial @p0
  Scenario: 不满足时钟协议前提时明确失败
    Given 节点频率被缩放或不一致能力缺失协议不匹配或采样误差过大
    When 尝试启动分布式客体
    Then 明确失败而不退回未经同步的时钟
    And 每种拒绝路径都有真实接口或故障注入证据

  # evidence: docs/ssi-pvclock.md
  @verified @p0
  Scenario: 受控页面交接后远端能够读到新的 pvclock 记录
    Given 两个隔离 KVM 实例在同一共享页各有一条时钟记录
    When 强制将页面交给远端后再由本地内核更新时钟
    Then PF5 基线两方向均复现旧版本而 PF6 八次检查全部取得新版本
    And 同页另一条记录与远端标记保持正确
    And 两边 VM fd 释放并退出后才记录探针完成
    And 不把串行交接测试视为并发撕裂或长期计时验收

  @partial @p0
  Scenario: pvclock 页面更新参与 DSM 一致性
    Given 两个执行节点更新位于同一共享页的 vCPU 时钟记录
    When 客体线程跨 CPU 读取记录且页面所有权反复转移
    Then 宿主缓存指针写入不能绕过 DSM 授权或覆盖新版本
    And 奇偶版本协议保证读取者不接受撕裂记录
    And 不出现已启用时钟返回零或单调时钟倒退

  @research @p0
  Scenario: 长期漂移与生命周期变更有同步协议
    Given 客体跨不同物理机运行且时钟存在频率漂移
    When 长时间负载暂停恢复重置或执行节点重连
    Then 时钟误差受明确界限约束且不会倒退
    And 未实现这些协议的冷启动候选不能被视为可用替代

  # evidence: docs/evidence/ssi-virtio-dsm-pins-20261107.json
  @verified @p0
  Scenario: 本地 QMP 暂停能唤醒远端 vCPU 占位线程
    Given 两个实验 VM 的 QEMU 各含两个本地 vCPU 和两个远端占位线程
    When 协调器分别向两边发送 stop
    Then 旧版的暂停等待与占位线程阻塞由实际线程栈复现
    And 候选唤醒独立条件变量并等待占位线程确认停止
    And 正常写入后暂停再关闭两端退出零且没有强制清理
    And 不声称一次 stop 已停止真实远端或已支持恢复

  # evidence: docs/ssi-clock-resume.md
  @partial @p0
  Scenario: 全局暂停恢复建立新的时钟同步边界
    Given 两端已分别暂停且实际 vCPU 和设备生产者均已停止
    When 请求恢复同一客体
    Then 以新代际重新同步时间并协调释放执行许可
    And 跨 CPU 计时在多轮暂停恢复后仍不倒退或提前到期
    And 现有冷启动限制触发的真实失败保持可见直到协议完成
    And 不以删除 cold start only 检查替代实现

  # evidence: docs/evidence/ssi-clock-resume-20261107.json
  @verified @p0
  Scenario: 两端分别暂停后的有限恢复实验保留时钟连续性
    Given 同一物理 ESXi 的两个隔离 PF24 VM 已分别完成 QMP stop
    When 交错向两端发送 cont 并在七轮中重新校时
    Then 准备屏障和时钟就绪屏障均核对连续代际再放行
    And 同一客体进程跨七轮保留读数并完成三十二次跨 CPU 采样
    And 四个二十毫秒定时器不提前到期且低于原二百五十毫秒门槛
    And 客体正常关机后两端自行退出零
    And 反向复验的 watchdog 失败保持未通过
    And 不声称单条全局 stop 设备全部静止或跨物理机稳定性已完成

  # evidence: docs/evidence/ssi-clock-resume-20261107.json
  @verified @p0
  Scenario: 不完整恢复和错误代际拒绝放行
    Given 两端分别暂停且管理连接已经建立
    When 只恢复一端对端进程不响应复位后恢复或注入错误代际
    Then 对应错误路径不发送 RESUME 事件
    And 单端和无响应准备在独立期限内失败停止
    And 超时线程不进入需要主线程锁的退出回调
    And 旧候选超时后仍阻塞的真实线程栈和强制清理记录保留
    And 对端进程被暂停的实验仅在解除暂停后验证其自行失败退出
    And 不把失败停止当作数据库接管或持久化确认

  # evidence: docs/evidence/ssi-rtc-20261106.json
  @verified @p0
  Scenario: 跨节点 RTC 读取用独立时间基准验收
    Given 两个专用实验 VM 上的四 CPU 无磁盘客体
    When 同一线程按 0 2 1 3 顺序读取八轮 RTC
    Then 原版本错误日期由独立控制端和宿主时间窗口检出
    And 禁用分布式合并 PIO 注册的候选通过全部三十二次读取
    And 普通单节点对照保留合并 PIO 注册且通过读取
    And 不把合法日期字段或 ioctl 成功当作正确时间
    And 秒级短窗口通过不代表 RTC 中断长期漂移或完整 SSI 通过
