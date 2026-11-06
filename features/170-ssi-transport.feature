Feature: SSI 传输等待与启动资源生命周期
  先在真实 KVM 监听器和独占实验 VM 中验证，不将同一 ESXi 的结果当作跨物理机性能。

  # evidence: docs/evidence/ssi-vcpu-residency-20261106.json
  @verified @p0
  Scenario: KVM 进入退出区间与宿主中断使用完整记录核查
    Given 两个独占实验节点记录目标 vCPU 以及宿主调度和中断事件
    When 分析 KVM 进入退出与本地定时器间隔
    Then 检查线程身份全局时钟事件总数和每 CPU 丢失计数
    And 区间包含 KVM 准备和返回代码且不能直接当作有效客体计算时间
    And 开关产生更多事件导致缓冲溢出时必须拒绝该次时间分析
    And 缩短诊断窗口不改变三轮无跟踪运行的原时钟验收门槛

  # evidence: docs/evidence/ssi-timer-progress-20261106.json
  @verified @p0
  Scenario: 定时器空档内的频繁退出不能冒充宿主调度进度
    Given 同一 PF14 开关对照的四份完整跟踪已核对原始哈希
    When 逐宿主 CPU 分析相邻真实定时器入口之间的事件
    Then 分别报告 PAUSE 退出调度切换和相邻事件最大间隔
    And 其他 CPU 的活动不能填补本 CPU 的空档且采样边界不得外推
    And 跟踪点中断标志不能证明整个窗口持续关闭中断
    And 诊断结果不替代客体时钟内存与关闭验收

  # evidence: docs/evidence/ssi-vcpu-residency-20261106.json
  @partial @p0
  Scenario: 无 PLE 实验宿主可显式强制 DSM 客体从 PAUSE 返回
    Given 默认关闭的实验开关和缺少 PLE 的两个独占 x86 VMX 节点
    When 对同一候选内核分别开启和关闭该开关
    Then 仅开启时捕获真实 PAUSE 退出且四个客体 vCPU 的用户态探针能继续执行
    And 记录开关对 KVM 区间和调度等待的影响及额外退出开销
    And 仍需解决剩余时钟关闭与性能问题后才能通过完整 SSI 验收

  # evidence: docs/evidence/ssi-latency-20261106.json
  @verified @p0
  Scenario: 页面交接计时排除管理 SSH 且可以独立复核
    Given 单节点对照与两个实验 VM 都创建没有 vCPU 的真实 KVM 页面
    When 执行一百六十次顺序操作和每节点两个线程各二百五十六次写入
    Then 每次 ioctl 使用工作进程内的单调时钟计时并按线程对应内核入口和返回
    And 各次顺序读取内容正确且并发结束后各节点得到相同的完整最终页面
    And 验收重新计算页面校验和与所有耗时而不采信通过标记
    And 所有调用配对且跟踪没有丢失并确认工作进程完成关闭
    And 空闲监听等待单独报告且不能当作响应延迟

  @partial @p0
  Scenario: 完整客体的慢取页可以定位但尚未消除
    Given 两个实验 VM 上运行同一未经修改的 Linux 客体
    When 在应用时钟采样期间同时记录页面获取网络与锁调用
    Then 报告热点页面与函数等待并区分测量窗口边缘的不完整调用
    And 两侧窗口在导出任一大文件之前同时停止避免导出污染对端
    And 仍须在无跟踪运行中消除秒级停顿与 watchdog 告警后才通过完整工作区验收

  # evidence: docs/evidence/ssi-scheduling-20261106.json
  @verified @p0
  Scenario: 调度等待分解必须保留未知边界并拒绝丢失采样
    Given 独占实验 VM 中记录目标 QEMU 与 DSM 线程的身份及切换事件
    When 分解函数调用期间的等待
    Then 区分可运行等待睡眠已调度和窗口外未知时间
    And 已调度时间不冒充有效 CPU 计算且空闲接收不冒充响应延迟
    And 跟踪溢出探针遗漏时间倒退和线程身份变化均不能通过验收
    And 未覆盖的窗口边界不能用最后一次线程状态外推

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
    And 正在处理的页面请求与缺失内存槽重试都应响应停止信号

  # evidence: docs/evidence/ssi-request-cancel-20261106.json
  @verified @p0
  Scenario: 完整读页请求等待缺失内存槽时可取消
    Given 独占实验 VM 已接收完整 DSM 读页请求但尚未注册目标页
    When 根线程向处理线程定向发送取消或调用者直接关闭 VM
    Then 九个 DSM 线程在目标页仍未注册时完成退出
    And 故障取消保留 EINTR 且不依赖稍后补注册才能回收
    And 未取消的对照在延迟注册后返回相同事务号和完整正确页面
    And 两台节点上的事件计数完整且没有跟踪丢失

  # evidence: docs/evidence/ssi-request-safety-20261106.json
  @verified @p0
  Scenario: 请求接收在复制前检查容量并拒绝无效字段
    Given 独占实验 VM 接收十五种长度类型与节点字段异常的完整帧
    When 超过二十四字节容量或请求字段非法
    Then 返回 EMSGSIZE 或 EPROTO 且不获取 KVM SRCU 与页面锁
    And 每个处理器的临时页面分配和释放均有配对的真实跟踪事件
    And 同一 VM 仍能注册内存并返回正确页面和已清零的失效确认帧
    And 两台节点的全部线程退出且临时跟踪和防火墙规则恢复

  # evidence: docs/evidence/ssi-request-safety-20261106.json
  @verified @p0
  Scenario: 同页锁等待者可在持锁者等待远端响应时单独取消
    Given 真实处理器持有页面锁并等待受控对端的响应
    And 第二个处理器进入同一页面锁但尚未获得锁
    When 仅向第二个处理器定向发送取消信号
    Then 等待者在五百毫秒内返回 EINTR 并释放 SRCU 和临时页面
    And 等待者没有解锁自己未持有的锁且先于持锁者释放完成退出
    And 随后释放对端响应时持锁者仍返回完整正确页面

  @research @p0
  Scenario: 更多异常事务与内部不变量分支也能安全回收
    Given 事务缓存中的超长响应或超长失效确认或内部页面状态不一致
    When 请求被取消或协议校验失败
    Then 独立故障注入应证明所有 SRCU 和页面锁均被释放
    And 响应复制不能越过实际目标缓冲区且临时页面必须被回收
    And 错误保留给调用者而不伪装为成功

  # evidence: docs/evidence/ssi-teardown-20261106.json
  @verified @p0
  Scenario: 本地 VM 销毁前先停止访问其资源的 DSM 线程
    Given 真实 KVM VM 包含两个 vCPU 内存槽和一个 DSM 半帧连接
    When 对端先关闭连接或本地先关闭 VM
    Then 内核跟踪确认八个接收线程和根线程先全部退出
    And 停止函数返回后才进入 vCPU 和 MMU 销毁
    And 最终释放仍可再次调用停止函数且没有重复的线程退出
    And 跟踪缓冲区与 kprobe 计数都没有丢失事件
    And 临时跟踪事件和防火墙规则均完成清理

  # evidence: docs/evidence/ssi-startup-20261106.json
  @verified @p0
  Scenario: 本地监听失败同步返回并允许在同一空 VM 重试
    Given 独占实验节点上有一个占用 DSM 端口的真实监听器
    When 通过 KVM ioctl 启用 DSM
    Then 返回 EADDRINUSE 而不是异步报告成功
    And 释放端口后在同一个 VM 启用成功并可关闭
    And 真实 QEMU 遇到相同冲突会报告错误并在客体启动前退出

  # evidence: docs/evidence/ssi-startup-20261106.json
  @verified @p0
  Scenario: 无连接的重复启停和参数失败不会遗留监听器
    Given 两台独占实验节点各运行创建空 VM 的真实 KVM 探针
    When 每台节点执行六十四次启用与关闭
    Then 每次关闭后原端口都能由新的监听器绑定
    And 空列表越界节点和过多节点返回 EINVAL
    And 无效用户地址返回 EFAULT
    And 参数失败后同一 VM 可使用有效参数启用并关闭
    And 所有探针退出后没有 DSM 线程残留

  @partial @p0
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
