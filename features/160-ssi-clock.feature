Feature: SSI 客体计时信息保持跨节点一致
  TSC、KVM 纳秒时钟和客体共享的 pvclock 页面必须分别验证。

  # evidence: docs/evidence/ssi-tsc-scaling-20261109.json
  @verified @p0
  Scenario: 显式软件缩放必须同时改变三条 TSC 路径并保持 pvclock 一致
    Given 独立 ESXi 的专用 VM 没有向 Linux 暴露硬件 TSC 缩放
    When PF32 单 vCPU 分别执行原生升频降频和另一节点目标频率
    Then RDTSC RDTSCP TSC MSR 与 pvclock 的每段实测包络同时满足预设门槛
    And RDTSCP AUX 与三种读取的零点顺序一致
    And PF31 的三组 MSR 不一致记录继续被检查器拒绝
    And 多 vCPU 定时器暂停恢复及跨物理同一客体不因单节点实验升级为通过

  # evidence: docs/evidence/ssi-tsc-scaling-20261109.json
  @verified @p0
  Scenario: 软件缩放保持默认关闭和执行后配置冻结
    Given PF31 与 PF32 分别以默认关闭和显式开启的宿主参数启动
    When 未选择的普通实例和显式选择的软件实例完成读数采集
    Then 关闭时软件属性不可用且无客体执行
    And 硬件能力位保持零且未选择实例仍以原生速率运行
    And 执行后改频或选择被拒绝且读回状态未变
    And 原版内核启动配置防火墙网络与下载缓存已恢复并无遗留 KVM fd
    And 默认预检仍拒绝不同原生频率

  # evidence: docs/evidence/ssi-tsc-frequency-candidate-20261109.json
  @verified @p0
  Scenario: 重装后独立候选的身份与实测频率必须对应预检拒绝
    Given 新 ESXi 的实验副本隔离重建身份并在重启后保持独立身份
    When 同一探针采集三种频率请求并与原实验节点运行真实 CLI 预检
    Then 两端原生频率分别为 2394374 与 2095148 kHz
    And 候选升频设置读回成功但实测仍为原生速率且降频失败后不执行
    And 检查器关联身份频率及重启记录并拒绝旧候选数据与未清理状态
    And Rust 重放完整预检报告并保留不同频率的退出码二
    And 空 VM 预检与独立单节点运行不升级为跨物理同一客体或完整 SSI 验收

  # evidence: docs/evidence/ssi-tsc-frequency-20261109.json
  @verified @p0
  Scenario: 频率设置和读回不能替代客体实际计时
    Given 同一物理 ESXi 上两个原版 Linux 实验 VM 均未暴露硬件 TSC 缩放
    When 标准 KVM 分别请求原生频率升频与降频并由共享内存握手建立宿主时间包络
    Then 升频设置成功及运行后读回一致仍保留实测频率维持原生的结果
    And 降频设置失败后即使读回值已改变也不执行该临时客体
    And 检查器逐段重算 RDTSC 和 pvclock 拒绝错序宽包络非法版本与未清理状态
    And 普通 CI 重放双端六组记录启动前失败与实际编译源码
    And 既有不同频率拒绝保持生效且不声称跨物理长期同步或完整 SSI 完成

  # evidence: docs/evidence/ssi-write-grant-20261108.json
  @verified @p0
  Scenario: 同一次单指令写入的重复缺页可以重放并比较有期限的授权
    Given 两个独占实验 VM 每次 KVM_RUN 只执行一条固定写指令和 HLT
    When 用唯一编号的宿主标记包围调用并启动另一节点真实 DSM 读者
    Then 检查器核对写入结果调用边界事件身份零丢失与读者进展
    And PF29 与关闭开关的 PF30 保留同一次调用数百次缺页的真实记录
    And PF30 开启一毫秒保留时两端各三百二十次写入样本无重复写缺页
    And 完整 Linux 客体回归保留原二百五十毫秒门槛和无法完整归因的跟踪
    And 普通 CI 重放完整原始数据并核对候选补丁与编译源一致
    And 原生关闭和原版内核恢复不替代取消竞态公平性与完整 SSI 验收

  # evidence: docs/evidence/ssi-timekeeper-writer-20261108.json
  @verified @p0
  Scenario: 时间写入者观测核对奇偶序列并保留连续缺页的解释边界
    Given 固定 PF29 和客体 ELF 的单节点对照与四次双节点运行
    When 完整采集时间写入临界区并在一轮双节点实验覆盖所有六次计时的宿主缺页
    Then 检查器拒绝写入阶段丢失重复身份错误和非法序列并允许 u32 回绕
    And 与标记相交的完整调用校验阶段但只有窗口内调用进入耗时分布
    And 宿主缺页按同一 vCPU 的连续指令地址和错误码分组且验证计数线程和时钟
    And 普通 CI 重放六份完整客体归档与两份完整宿主缺页归档
    And 最大九百五十二毫秒写入区间和原二百五十毫秒应用超限均被保留
    And 重复缺页跨度不被称作单次缺页耗时或已确定的运行时根因
    And 原生关闭和 stock 内核恢复通过不替代严格 SSI 验收

  # evidence: docs/evidence/ssi-guest-irq-20261108.json
  @verified @p0
  Scenario: 客体中断函数观测拒绝启停漏记并保留时间读取分段
    Given 固定 PF29 与客体 ELF 的单节点和双节点独占实验
    When 在记录窗口内同步停用探针并核对完整函数与序列读取阶段
    Then 所有入口和分段命中等于事件数且没有探针漏采或缓冲区丢失
    And 窗口内部孤立返回未完成入口和不符合序列值的重试被拒绝
    And 最长函数只关联实际包含它的中断而不替代最大应用等待
    And 普通 CI 重放完整归档并保留原二百五十毫秒门槛的失败退出
    And 启停计数不符与 SSH 握手超时分别保留为失败
    And 时间读取前段停顿不被宣称为已确定根因或已修复 SSI

  # evidence: docs/evidence/ssi-steal-time-20261108.json
  @verified @p0
  Scenario: 受控页面交接后远端能够读到新的 steal time 记录
    Given 同一物理 ESXi 的两个独占实验 VM 使用同一最小 KVM 探针
    When 将包含两条 steal time 记录的页面交给远端后再次由原节点更新
    Then PF28 八次复现旧记录而 PF29 八次取得新记录且两版单节点对照通过
    And 同页另一条记录与远端标记不被缓存地址写入覆盖
    And 原生关闭代际与连接计数完成后才释放两端 VM fd
    And 普通 CI 重放完整原始交互并核对补丁与实际编译源码一致
    And 原 QEMU 版本校验导致的完整客体关闭失败保留
    And 新 QEMU 正常关闭仍保留三百五十九毫秒定时器超限失败
    And 不声称抢占提示并发撕裂或既有定时器停顿已完成验收

  # evidence: docs/evidence/ssi-guest-timers-20261108.json
  @verified @p0
  Scenario: 客体定时器观测区分中断内等待与重新运行
    Given 同一物理 ESXi 上的单节点对照与双节点客体使用相同 tracepoint 集合
    When 按 PID CPU 和定时器初始化代次关联应用区间与完整客体跟踪
    Then 检查器拒绝漏采取消重复回调和错误时钟域或线程归属
    And 本地中断和回调按 CPU 嵌套配对且边界未知部分不补造耗时
    And 唤醒后仍在中断内的区间不被称作普通调度队列等待
    And 普通 CI 重放已提交的四十八个应用定时器与完整跟踪
    And 函数探针漏采与三百九十毫秒超限保留为失败且不声称已修复停顿

  # evidence: docs/evidence/ssi-clock-stalls-20261108.json
  @verified @p0
  Scenario: 活动时钟与取页观测区分完整调用和采集边界
    Given 同一物理 ESXi 的两个独占 PF28 VM 正在执行真实四 CPU 客体
    When 在 SSH 就绪至 SFTP 完成之间记录时钟更新和页面获取
    Then 检查器核对入口命中和逐 CPU 事件计数并拒绝漏采或线程身份变化
    And 停用后的返回命中只允许对应末尾未完成调用且不补造耗时
    And 原生关闭通过与客体 watchdog 及 workqueue 告警分别保留
    And 探针退出零但定时器超过原二百五十毫秒门槛时仍记录验收失败
    And 零次时钟更新和有限取页分布不被当作停顿根因或完整 SSI 验收

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
